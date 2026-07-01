use crate::tunnel::Tunnel;
use std::path::PathBuf;

fn data_path() -> PathBuf {
    let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("ssh-tunnel");
    path.push("tunnels.json");
    path
}

pub fn load_tunnels() -> Vec<Tunnel> {
    let path = data_path();
    if !path.exists() {
        return vec![];
    }
    let data = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn save_tunnels(tunnels: &[Tunnel]) {
    let path = data_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(tunnels) {
        Ok(data) => {
            let _ = std::fs::write(&path, data);
        }
        Err(_) => {}
    }
}
