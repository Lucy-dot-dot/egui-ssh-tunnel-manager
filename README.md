# SSH Tunnel Manager

SSH Tunnel Manager is a simple desktop application for Windows that lets you
create and run SSH port tunnels without using the command line.

A tunnel securely forwards traffic from a port on your computer, through an
SSH server, to another computer and port. Typical uses:

- Reach a database, web dashboard, or admin panel that is only reachable
  from inside a remote network.
- Encrypt traffic to a service that only offers plain HTTP or other
  unencrypted protocols.
- Replace long `ssh -L ...` commands with saved, one-click profiles.

## Features

- Save any number of tunnel profiles, each with its own settings.
- One-click Connect / Disconnect with a clear status indicator.
- Automatic reconnection: if the connection drops, the app reconnects on its
  own (and retries every few seconds while the network is down).
- Works with your existing SSH setup: it reads `~/.ssh/config` (aliases,
  ports, users, identity files, timeouts) and `~/.ssh/known_hosts`, and uses
  your SSH keys and SSH agent (OpenSSH agent or Pageant) for login.
- Runs entirely on your machine. No accounts, no cloud.

## Requirements

- An SSH server you can log in to with an SSH key (password login is not
  used).
- On Windows: the OpenSSH agent service or Pageant running if your key needs
  an agent (keys without a passphrase are loaded directly).

## Getting started

### Install

Build from source with [Rust](https://rustup.rs):

```
cargo build --release
```

The finished program is `target\release\ssh-tunnel.exe`. Copy it anywhere you
like (for example your Desktop) and double-click to run it.

### Create your first tunnel

1. Start SSH Tunnel Manager.
2. Click **+ Add Tunnel**.
3. Fill in the fields (explained below).
4. Click **Save**.
5. Click **Connect**. The status shows **Connected** (green) once the tunnel
   is up.
6. Point your application at `localhost` and the **Local Port** you chose —
   the traffic now reaches the remote service as if it were running on your
   own machine.

Example: to reach a web server that lives at `intranet.local` port 80 on a
remote network, via your server `bastion.example.com`:

| Field | Value |
|---|---|
| Name | Company intranet |
| SSH Host | bastion.example.com |
| SSH Port | *(leave empty for 22)* |
| SSH User | *(leave empty to use your ~/.ssh/config or Windows username)* |
| Local Port | 8080 |
| Remote Host | intranet.local |
| Remote Port | 80 |

Connect, then open `http://localhost:8080` in your browser.

### The fields

| Field | Meaning |
|---|---|
| **Name** | A label for the tunnel, shown in the list on the left. |
| **SSH Host** | The server you log in to. This may be a nickname (alias) from your `~/.ssh/config`. |
| **SSH Port** | The SSH server's port. Leave empty to use the value from `~/.ssh/config`, or 22. |
| **SSH User** | The username on the SSH server. Leave empty to use the value from `~/.ssh/config`, or your Windows username. |
| **Local Port** | The port that will be opened on **your** computer (127.0.0.1). Your programs connect here. |
| **Remote Host** | The computer you ultimately want to reach, as seen *from the SSH server*. |
| **Remote Port** | The port of the service on that computer (e.g. 80 for HTTP, 5432 for PostgreSQL). |

All ports must be between 1 and 65535. The Local Port must not already be in
use by another program.

### Managing tunnels

- Click a tunnel in the left list to edit it or see its status.
- **Disconnect** stops the tunnel and frees the local port.
- **Delete** removes the tunnel after a confirmation. Fields are locked while
  a tunnel is running — disconnect first to change them.

### Status indicators

| Dot | Meaning |
|---|---|
| Green | Connected — the tunnel is up. |
| Yellow | Reconnecting — the connection was lost or failed; the app keeps retrying automatically. The error that caused it is shown next to the status. |
| Grey | Disconnected. |

## How login works

The app never asks for passwords. It logs in the same way the `ssh` command
does:

1. **Identity files** from `IdentityFile` in `~/.ssh/config`, or the usual
   default keys (`id_ed25519`, `id_ecdsa`, `id_rsa`, and the hardware-key
   variants) in `~/.ssh` if none are configured.
2. **Your SSH agent** — the Windows OpenSSH agent (`\\.\pipe\openssh-ssh-agent`),
   an agent named by `SSH_AUTH_SOCK`, or Pageant.

Host keys are checked against `~/.ssh/known_hosts`: known hosts must match,
new hosts are accepted automatically, and a *changed* host key is rejected
(the connection fails and details are written to the log).

Keepalive packets are sent every 15 seconds (or at your configured
`ServerAliveInterval`) so dead connections are noticed quickly.

## Where my data is stored

| File | Location (Windows) | Contents |
|---|---|---|
| Tunnel settings | `%APPDATA%\ssh-tunnel\tunnels.json` | Your saved tunnels |
| Log file | `%APPDATA%\ssh-tunnel\ssh-tunnel.log` | Connection history and errors |

Delete `tunnels.json` to reset the app to an empty state.

## Troubleshooting

- **Connect fails with `auth: all authentication methods failed`**
  The server rejected your keys. Make sure your key is loaded in your SSH
  agent, or that the private key file exists and is readable. Remember:
  password login is not supported.
- **Connect fails with `bind 127.0.0.1:XXXX`**
  Another program is already using that local port. Pick a different
  Local Port.
- **Status stays yellow / Reconnecting**
  Check that the SSH host, port, and your internet connection are working.
  The error text next to the status tells you what went wrong; more detail is
  in the log file.
- **Changed host key warning in the log**
  The server's key no longer matches `~/.ssh/known_hosts`. If you know the
  server was reinstalled, remove the old line for that host from
  `known_hosts` (or run `ssh-keygen -R host`) and try again.
- **The tunnel is connected but the service does not respond**
  The Remote Host must be reachable *from the SSH server*, not from your
  computer. Test it by logging in to the server with `ssh` and trying to
  reach it from there.

## License

See [LICENSE](LICENSE).
