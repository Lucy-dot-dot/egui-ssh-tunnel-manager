mod app;
mod ssh;
mod storage;
mod tunnel;

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SSH Tunnel Manager")
            .with_inner_size([700.0, 480.0])
            .with_min_inner_size([500.0, 300.0]),
        ..Default::default()
    };

    eframe::run_native(
        "SSH Tunnel Manager",
        native_options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
