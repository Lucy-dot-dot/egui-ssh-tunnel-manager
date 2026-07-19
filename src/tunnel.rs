use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use russh::{client, Channel, ChannelMsg};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub ssh_host: String,
    /// SSH port override. `None` means "defer to ~/.ssh/config `Port`, else 22",
    /// exactly like omitting `-p` on the `ssh` command line.
    #[serde(default)]
    pub ssh_port: Option<u16>,
    /// SSH user override. Empty means "defer to ~/.ssh/config `User`, else the
    /// current user", like omitting `-l`.
    pub ssh_user: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self {
            id: unique_id(),
            name: String::new(),
            ssh_host: String::new(),
            ssh_port: None,
            ssh_user: String::new(),
            local_port: 8080,
            remote_host: String::new(),
            remote_port: 80,
        }
    }
}

fn unique_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{}", t.as_secs(), t.subsec_nanos())
}

#[derive(Debug, Clone, PartialEq)]
pub enum TunnelStatus {
    Disconnected,
    Connected,
    /// Last error from the reconnect loop, if any (`None` for a clean session end).
    Reconnecting(Option<String>),
}

pub struct TunnelHandle {
    status: Arc<Mutex<TunnelStatus>>,
    stop_flag: Arc<AtomicBool>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl TunnelHandle {
    pub fn status(&self) -> TunnelStatus {
        self.status.lock().unwrap().clone()
    }

    /// Request the tunnel to stop. The underlying SSH session is dropped and the
    /// local listening port is released.
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(join) = &self.join {
            join.abort();
        }
        *self.status.lock().unwrap() = TunnelStatus::Disconnected;
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(join) = &self.join {
            join.abort();
        }
    }
}

/// A lazily-initialised shared multi-threaded tokio runtime that backs every
/// active tunnel. Created once and kept alive for the lifetime of the process.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("ssh-tunnel-worker")
            .build()
            .expect("failed to build tokio runtime")
    })
}

pub fn start_tunnel(tunnel: Tunnel) -> TunnelHandle {
    let status = Arc::new(Mutex::new(TunnelStatus::Reconnecting(None)));
    let stop_flag = Arc::new(AtomicBool::new(false));

    let join = runtime().spawn(run_tunnel_loop(
        tunnel,
        status.clone(),
        stop_flag.clone(),
    ));

    TunnelHandle {
        status,
        stop_flag,
        join: Some(join),
    }
}

/// Reconnect loop: keep the tunnel alive, reconnecting with backoff after any
/// failure, until the user requests a stop.
async fn run_tunnel_loop(
    tunnel: Tunnel,
    status: Arc<Mutex<TunnelStatus>>,
    stop_flag: Arc<AtomicBool>,
) {
    while !stop_flag.load(Ordering::SeqCst) {
        let last_error = match serve_forward(&tunnel, &status, &stop_flag).await {
            ForwardResult::Stopped => break,
            ForwardResult::Err(msg) => {
                log::error!("[{}] tunnel error: {msg}", tunnel.name);
                Some(msg)
            }
            ForwardResult::Ended => {
                log::info!("[{}] session ended; reconnecting", tunnel.name);
                None
            }
        };

        if stop_flag.load(Ordering::SeqCst) {
            break;
        }

        *status.lock().unwrap() = TunnelStatus::Reconnecting(last_error);

        // Backoff, but stay responsive to a stop request.
        let mut waited = Duration::ZERO;
        while waited < Duration::from_secs(3) {
            if stop_flag.load(Ordering::SeqCst) {
                break;
            }
            let step = Duration::from_millis(200);
            tokio::time::sleep(step).await;
            waited += step;
        }
    }

    *status.lock().unwrap() = TunnelStatus::Disconnected;
}

enum ForwardResult {
    Stopped,
    Ended,
    Err(String),
}

/// Resolve the host via `~/.ssh/config`, connect, authenticate, bind the local
/// port and forward accepted connections through `direct-tcpip` channels.
async fn serve_forward(
    tunnel: &Tunnel,
    status: &Arc<Mutex<TunnelStatus>>,
    stop_flag: &Arc<AtomicBool>,
) -> ForwardResult {
    let resolved = crate::ssh::resolve(tunnel);

    let mut session = match crate::ssh::connect(&resolved).await {
        Ok(s) => s,
        Err(e) => return ForwardResult::Err(format!("connect: {e}")),
    };

    if let Err(e) = crate::ssh::authenticate(&mut session, &resolved).await {
        return ForwardResult::Err(format!("auth: {e}"));
    }

    // Bind the local forward port (mirrors `ExitOnForwardFailure=yes`).
    let local_addr = format!("127.0.0.1:{}", tunnel.local_port);
    let listener = match TcpListener::bind(&local_addr).await {
        Ok(l) => l,
        Err(e) => {
            crate::ssh::disconnect(&session).await;
            return ForwardResult::Err(format!("bind {local_addr}: {e}"));
        }
    };

    *status.lock().unwrap() = TunnelStatus::Connected;

    let remote_host = tunnel.remote_host.clone();
    let remote_port = tunnel.remote_port;

    // Periodically check session liveness; keepalives configured in ssh::connect
    // ensure the underlying session fails fast when the server is unreachable.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if stop_flag.load(Ordering::SeqCst) {
            crate::ssh::disconnect(&session).await;
            return ForwardResult::Stopped;
        }

        tokio::select! {
            accept = listener.accept() => {
                let (socket, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        crate::ssh::disconnect(&session).await;
                        return ForwardResult::Err(format!("accept: {e}"));
                    }
                };

                match session
                    .channel_open_direct_tcpip(
                        remote_host.clone(),
                        remote_port as u32,
                        peer.ip().to_string(),
                        peer.port() as u32,
                    )
                    .await
                {
                    Ok(channel) => {
                        tokio::spawn(pipe_data(socket, channel));
                    }
                    Err(e) => {
                        log::warn!("failed to open direct-tcpip channel: {e}");
                    }
                }
            }
            _ = tick.tick() => {
                if session.is_closed() {
                    crate::ssh::disconnect(&session).await;
                    return ForwardResult::Ended;
                }
            }
        }
    }
}

/// Bidirectionally copy bytes between a local TCP socket and an SSH channel.
async fn pipe_data(mut socket: tokio::net::TcpStream, mut channel: Channel<client::Msg>) {
    let mut buf = vec![0u8; 65536];
    let mut socket_closed = false;

    loop {
        tokio::select! {
            r = socket.read(&mut buf), if !socket_closed => {
                match r {
                    Ok(0) => {
                        socket_closed = true;
                        let _ = channel.eof().await;
                    }
                    Ok(n) => {
                        if channel.data(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    if socket.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Some(ChannelMsg::Eof) | None => {
                    if !socket_closed {
                        let _ = channel.eof().await;
                    }
                    break;
                }
                // Window adjustments, extended data (stderr), close, etc.
                _ => {}
            },
        }
    }
}
