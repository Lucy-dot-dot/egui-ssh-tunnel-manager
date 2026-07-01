use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use russh::keys::HashAlg;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::ssh_key;
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts};
use russh::{Disconnect, client};
use russh::keys::agent::AgentIdentity;
use ssh2_config::{ParseRule, SshConfig};

use crate::tunnel::Tunnel;

/// A fully resolved connection target after consulting `~/.ssh/config`.
pub struct Resolved {
    pub hostname: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub connect_timeout: Option<Duration>,
    pub keepalive: Option<Duration>,
}

fn ssh_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".ssh"))
}

/// Parse the user's `~/.ssh/config`. Returns an empty config if it is missing or
/// unreadable, so a missing file never blocks a connection.
fn load_config() -> SshConfig {
    let Some(dir) = ssh_dir() else {
        return SshConfig::default();
    };
    let Ok(file) = std::fs::File::open(dir.join("config")) else {
        return SshConfig::default();
    };
    let mut reader = std::io::BufReader::new(file);
    SshConfig::default()
        .parse(&mut reader, ParseRule::ALLOW_UNKNOWN_FIELDS)
        .unwrap_or_default()
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

/// Expand a leading `~` to the user's home directory. OpenSSH expands `~` in
/// `IdentityFile`; ssh2-config leaves the path as-is, so we normalise it here.
fn expand_tilde(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(home) = dirs::home_dir() {
        if let Some(rest) = s
            .strip_prefix("~/")
            .or_else(|| s.strip_prefix("~\\"))
            .or_else(|| s.strip_prefix("~"))
        {
            return home.join(rest);
        }
    }
    p.to_path_buf()
}

/// Resolve a tunnel definition against `~/.ssh/config`.
///
/// This is what gives us SSH *alias* support: `ssh_host` may be an alias whose
/// real `HostName`, `Port`, `User` and `IdentityFile` are looked up here.
///
/// Precedence mirrors OpenSSH:
/// - values explicitly set in the GUI (port/user) act like `-p`/`-l` and win
/// - otherwise the matched `Host` block from `~/.ssh/config` is used
/// - finally sensible defaults are applied
pub fn resolve(t: &Tunnel) -> Resolved {
    let config = load_config();
    let params = config.query(&t.ssh_host);

    let hostname = params
        .host_name
        .clone()
        .unwrap_or_else(|| t.ssh_host.clone());

    // GUI port only overrides config when explicitly set (like `ssh -p`).
    let port = t.ssh_port.or(params.port).unwrap_or(22);

    // GUI user only overrides config when non-empty (like `ssh -l`).
    let user = if !t.ssh_user.trim().is_empty() {
        t.ssh_user.clone()
    } else {
        params.user.clone().unwrap_or_else(current_user)
    };

    // Identity files declared in config, plus the standard defaults if none.
    let mut identity_files: Vec<PathBuf> = params
        .identity_file
        .unwrap_or_default()
        .into_iter()
        .map(|p| expand_tilde(&p))
        .map(|p| {
            // OpenSSH: a filename ending in `.pub` refers to the matching
            // private key (the suffix is removed).
            let s = p.to_string_lossy();
            if let Some(stripped) = s.strip_suffix(".pub") {
                PathBuf::from(stripped)
            } else {
                p
            }
        })
        .filter(|p| p.is_file())
        .collect();

    if identity_files.is_empty() {
        if let Some(dir) = ssh_dir() {
            for name in [
                "id_ed25519",
                "id_ecdsa",
                "id_rsa",
                "id_ed25519_sk",
                "id_ecdsa_sk",
            ] {
                let p = dir.join(name);
                if p.is_file() {
                    identity_files.push(p);
                }
            }
        }
    }

    Resolved {
        hostname,
        port,
        user,
        identity_files,
        connect_timeout: params.connect_timeout,
        keepalive: params.server_alive_interval,
    }
}

/// Verify the server host key against `~/.ssh/known_hosts` (`accept-new`):
/// known + matching -> accept, unknown -> accept (new host), changed -> reject.
fn verify_host_key(host: &str, port: u16, key: &ssh_key::PublicKey) -> bool {
    match check_known_hosts(host, port, key) {
        Ok(true) => true,
        Ok(false) => true,
        Err(e) => {
            eprintln!("host key for {host}:{port} changed: {e}");
            false
        }
    }
}

pub(crate) struct ClientHandler {
    host: String,
    port: u16,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(verify_host_key(&self.host, self.port, server_public_key))
    }
}

/// Connect (TCP + key exchange) to the resolved host, honouring `ConnectTimeout`.
pub(crate) async fn connect(resolved: &Resolved) -> Result<client::Handle<ClientHandler>> {
    let keepalive = resolved.keepalive.or(Some(Duration::from_secs(15)));
    let config = Arc::new(client::Config {
        nodelay: true,
        keepalive_interval: keepalive,
        keepalive_max: 3,
        ..Default::default()
    });

    let handler = ClientHandler {
        host: resolved.hostname.clone(),
        port: resolved.port,
    };
    let addr = format!("{}:{}", resolved.hostname, resolved.port);

    let connect_fut = client::connect(config, addr, handler);
    let session = match resolved.connect_timeout {
        Some(t) => tokio::time::timeout(t, connect_fut)
            .await
            .map_err(|_| anyhow!("connection timed out after {t:?}"))??,
        None => connect_fut.await?,
    };

    Ok(session)
}

/// Authenticate an established session, trying (in order) the SSH agent and then
/// any private key files discovered in config. Returns Ok(()) on success.
pub(crate) async fn authenticate(
    session: &mut client::Handle<ClientHandler>,
    resolved: &Resolved,
) -> Result<()> {
    let user = &resolved.user;

    // Best RSA hash advertised by the server (ignored for non-RSA keys).
    let rsa_hash: Option<HashAlg> = match session.best_supported_rsa_hash().await {
        Ok(opt_opt) => opt_opt.flatten(),
        Err(_) => None,
    };

    // 1. SSH agent (ssh-agent on Unix, Pageant / OpenSSH named pipe on Windows).
    if try_agent_auth(session, user, rsa_hash).await? {
        return Ok(());
    }

    // 2. Identity files from disk (unencrypted, or those we can read without a
    //    passphrase — encrypted keys are expected to live in the agent).
    for path in &resolved.identity_files {
        let key = match russh::keys::load_secret_key(path, None) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("skipping identity {path:?}: {e}");
                continue;
            }
        };
        let with_hash = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
        match session.authenticate_publickey(user, with_hash).await {
            Ok(res) if res.success() => return Ok(()),
            Ok(_) => continue,
            Err(e) => {
                eprintln!("publickey auth with {path:?} failed: {e}");
                continue;
            }
        }
    }

    Err(anyhow!(
        "all authentication methods failed (tried agent + {} identity file(s))",
        resolved.identity_files.len()
    ))
}

type DynAgent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

/// Connect to a running SSH agent, cross-platform.
async fn connect_agent() -> Result<DynAgent> {
    #[cfg(unix)]
    {
        Ok(AgentClient::connect_env().await?.dynamic())
    }
    #[cfg(windows)]
    {
        // OpenSSH on Windows can expose the agent via SSH_AUTH_SOCK (named pipe);
        // otherwise fall back to Pageant.
        if let Ok(sock) = std::env::var("SSH_AUTH_SOCK") {
            if !sock.is_empty() {
                return Ok(AgentClient::connect_named_pipe(&sock).await?.dynamic());
            }
        }
        Ok(AgentClient::connect_pageant().await?.dynamic())
    }
}

async fn try_agent_auth(
    session: &mut client::Handle<ClientHandler>,
    user: &str,
    rsa_hash: Option<HashAlg>,
) -> Result<bool> {
    let mut agent = match connect_agent().await {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };

    let identities = match agent.request_identities().await {
        Ok(v) => v,
        Err(_) => return Ok(false),
    };

    for identity in identities {
        let authenticated = match &identity {
            AgentIdentity::PublicKey { key, .. } => {
                session
                    .authenticate_publickey_with(user, key.clone(), rsa_hash, &mut agent)
                    .await
            }
            AgentIdentity::Certificate { certificate, .. } => {
                session
                    .authenticate_certificate_with(user, certificate.clone(), rsa_hash, &mut agent)
                    .await
            }
        };

        match authenticated {
            Ok(res) if res.success() => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                eprintln!("agent identity failed: {e}");
                continue;
            }
        }
    }

    Ok(false)
}

/// Gracefully tear down a session.
pub(crate) async fn disconnect(session: &client::Handle<ClientHandler>) {
    let _ = session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await;
}
