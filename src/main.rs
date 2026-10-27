#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod ssh;
mod storage;
mod tunnel;

use std::path::PathBuf;

use log::LevelFilter;
use log4rs::{
    append::file::FileAppender,
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

/// Initialise file logging under the per-user data dir as `ssh-tunnel.log`.
/// Failures are silent: a missing logger must never block the GUI.
fn init_log() {
    let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("ssh-tunnel");
    let _ = std::fs::create_dir_all(&path);
    path.push("ssh-tunnel.log");

    let Ok(logfile) = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} {l:5} {t} - {m}{n}",
        )))
        .build(&path)
    else {
        return;
    };

    let Ok(config) = Config::builder()
        .appender(Appender::builder().build("file", Box::new(logfile)))
        .build(Root::builder().appender("file").build(LevelFilter::Info))
    else {
        return;
    };

    let _ = log4rs::init_config(config);
}

fn main() -> eframe::Result<()> {
    init_log();
    log::info!("starting ssh-tunnel manager");

    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
        .map(std::sync::Arc::new)
        .ok();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("SSH Tunnel Manager")
        .with_inner_size([700.0, 480.0])
        .with_min_inner_size([500.0, 300.0]);
    if let Some(icon) = icon {
        viewport = viewport.with_icon(icon);
    }

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "SSH Tunnel Manager",
        native_options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
