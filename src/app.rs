use std::collections::HashMap;

use eframe::egui::{self, Color32, RichText};
use eframe::Frame;
use egui::Ui;
use crate::{
    storage::{load_tunnels, save_tunnels},
    tunnel::{start_tunnel, Tunnel, TunnelHandle, TunnelStatus},
};

pub struct App {
    tunnels: Vec<Tunnel>,
    handles: HashMap<String, TunnelHandle>,
    selected: Option<usize>,
    edit_buf: EditBuf,
    mode: Mode,
    confirm_delete: Option<usize>,
}

#[derive(Default)]
struct EditBuf {
    tunnel: Tunnel,
    ssh_port: String,
    local_port: String,
    remote_port: String,
}

impl EditBuf {
    fn from_tunnel(t: &Tunnel) -> Self {
        Self {
            ssh_port: t.ssh_port.map(|p| p.to_string()).unwrap_or_default(),
            local_port: t.local_port.to_string(),
            remote_port: t.remote_port.to_string(),
            tunnel: t.clone(),
        }
    }

    fn apply_ports(&mut self) {
        let ssh = self.ssh_port.trim();
        self.tunnel.ssh_port = if ssh.is_empty() {
            None
        } else {
            ssh.parse::<u16>().ok()
        };
        if let Ok(v) = self.local_port.parse() {
            self.tunnel.local_port = v;
        }
        if let Ok(v) = self.remote_port.parse() {
            self.tunnel.remote_port = v;
        }
    }

    fn validate(&self) -> Option<&'static str> {
        if self.tunnel.name.trim().is_empty() {
            return Some("Name is required.");
        }
        if self.tunnel.ssh_host.trim().is_empty() {
            return Some("SSH host is required.");
        }
        if self.tunnel.remote_host.trim().is_empty() {
            return Some("Remote host is required.");
        }
        let ssh = self.ssh_port.trim();
        if !ssh.is_empty() && ssh.parse::<u16>().is_err() {
            return Some("SSH port must be 1-65535 or empty.");
        }
        if self.local_port.parse::<u16>().is_err() {
            return Some("Local port must be 1-65535.");
        }
        if self.remote_port.parse::<u16>().is_err() {
            return Some("Remote port must be 1-65535.");
        }
        None
    }
}

#[derive(PartialEq)]
enum Mode {
    None,
    Adding,
    Editing,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            tunnels: load_tunnels(),
            handles: HashMap::new(),
            selected: None,
            edit_buf: EditBuf::default(),
            mode: Mode::None,
            confirm_delete: None,
        }
    }

    fn tunnel_status(&self, id: &str) -> TunnelStatus {
        self.handles
            .get(id)
            .map(|h| h.status())
            .unwrap_or(TunnelStatus::Disconnected)
    }

    fn status_dot_color(status: &TunnelStatus) -> Color32 {
        match status {
            TunnelStatus::Connected => Color32::from_rgb(80, 200, 80),
            TunnelStatus::Reconnecting => Color32::from_rgb(220, 180, 0),
            TunnelStatus::Error(_) => Color32::from_rgb(220, 60, 60),
            TunnelStatus::Disconnected => Color32::from_rgb(120, 120, 120),
        }
    }

    fn save(&mut self) {
        save_tunnels(&self.tunnels);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut Frame) {
        ui.ctx().request_repaint_after(std::time::Duration::from_millis(500));

        self.show_side_panel(ui);
        self.show_central_panel(ui);
    }
}

impl App {
    fn show_side_panel(&mut self, ui: &mut Ui) {
        egui::Panel::left("tunnel_list")
            .min_size(220.0)
            .max_size(300.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                ui.heading("SSH Tunnels");
                ui.separator();

                if ui
                    .add_sized([ui.available_width(), 24.0], egui::Button::new("+ Add Tunnel"))
                    .clicked()
                {
                    self.mode = Mode::Adding;
                    self.edit_buf = EditBuf::from_tunnel(&Tunnel::default());
                    self.selected = None;
                    self.confirm_delete = None;
                }

                ui.separator();
                ui.add_space(2.0);

                let mut select_idx: Option<usize> = None;

                for (i, tunnel) in self.tunnels.iter().enumerate() {
                    let status = self.tunnel_status(&tunnel.id);
                    let is_selected = self.selected == Some(i);
                    let dot_color = Self::status_dot_color(&status);

                    let response = ui.horizontal(|ui| {
                        ui.colored_label(dot_color, RichText::new("●").size(12.0));
                        ui.selectable_label(is_selected, &tunnel.name)
                    });

                    if response.inner.clicked() {
                        select_idx = Some(i);
                    }
                }

                if let Some(i) = select_idx {
                    self.selected = Some(i);
                    self.edit_buf = EditBuf::from_tunnel(&self.tunnels[i]);
                    self.mode = Mode::Editing;
                    self.confirm_delete = None;
                }
            });
    }

    fn show_central_panel(&mut self, ctx: &mut Ui) {
        egui::CentralPanel::default().show(ctx, |ui| match self.mode {
            Mode::None => {
                ui.centered_and_justified(|ui| {
                    ui.label("Select a tunnel or add a new one.");
                });
            }
            Mode::Adding => {
                self.show_form(ui, true);
            }
            Mode::Editing => {
                self.show_form(ui, false);
            }
        });
    }

    fn show_form(&mut self, ui: &mut Ui, is_new: bool) {
        let tunnel_id = self.edit_buf.tunnel.id.clone();
        let status = self.tunnel_status(&tunnel_id);
        let is_running = matches!(
            status,
            TunnelStatus::Connected | TunnelStatus::Reconnecting
        );

        ui.add_space(4.0);
        ui.heading(if is_new { "New Tunnel" } else { "Edit Tunnel" });
        ui.separator();

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("form")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .min_col_width(100.0)
                .show(ui, |ui| {
                    field(ui, "Name", &mut self.edit_buf.tunnel.name, is_running);
                    ui.end_row();

                    field(ui, "SSH Host", &mut self.edit_buf.tunnel.ssh_host, is_running);
                    ui.end_row();

                    port_field(ui, "SSH Port", &mut self.edit_buf.ssh_port, is_running, "config / 22");
                    ui.end_row();

                    field(ui, "SSH User", &mut self.edit_buf.tunnel.ssh_user, is_running);
                    ui.end_row();

                    ui.separator();
                    ui.separator();
                    ui.end_row();

                    port_field(ui, "Local Port", &mut self.edit_buf.local_port, is_running, "");
                    ui.end_row();

                    field(
                        ui,
                        "Remote Host",
                        &mut self.edit_buf.tunnel.remote_host,
                        is_running,
                    );
                    ui.end_row();

                    port_field(
                        ui,
                        "Remote Port",
                        &mut self.edit_buf.remote_port,
                        is_running,
                        "",
                    );
                    ui.end_row();
                });

            ui.add_space(8.0);

            // Status bar
            match &status {
                TunnelStatus::Connected => {
                    ui.label(RichText::new("Connected").color(Color32::from_rgb(80, 200, 80)));
                }
                TunnelStatus::Reconnecting => {
                    ui.label(
                        RichText::new("Reconnecting...").color(Color32::from_rgb(220, 180, 0)),
                    );
                }
                TunnelStatus::Error(e) => {
                    ui.label(
                        RichText::new(format!("Error: {e}"))
                            .color(Color32::from_rgb(220, 60, 60)),
                    );
                }
                TunnelStatus::Disconnected => {}
            }

            ui.add_space(4.0);
            ui.separator();
            ui.add_space(4.0);

            let validation_err = self.edit_buf.validate();

            ui.horizontal(|ui| {
                if is_new {
                    let save_btn = ui.add_enabled(validation_err.is_none(), egui::Button::new("Save"));
                    if save_btn.clicked() {
                        self.edit_buf.apply_ports();
                        self.tunnels.push(self.edit_buf.tunnel.clone());
                        self.selected = Some(self.tunnels.len() - 1);
                        self.mode = Mode::Editing;
                        self.save();
                    }

                    if ui.button("Cancel").clicked() {
                        self.mode = Mode::None;
                        self.selected = None;
                    }
                } else {
                    // Connect / Disconnect
                    if is_running {
                        if ui
                            .add(egui::Button::new(
                                RichText::new("Disconnect").color(Color32::from_rgb(220, 60, 60)),
                            ))
                            .clicked()
                        {
                            if let Some(mut handle) = self.handles.remove(&tunnel_id) {
                                handle.stop();
                            }
                        }
                    } else {
                        let connect_enabled = validation_err.is_none();
                        let connect_btn = ui.add_enabled(
                            connect_enabled,
                            egui::Button::new(
                                RichText::new("Connect").color(Color32::from_rgb(80, 200, 80)),
                            ),
                        );
                        if connect_btn.clicked() {
                            self.edit_buf.apply_ports();
                            if let Some(idx) = self.selected {
                                self.tunnels[idx] = self.edit_buf.tunnel.clone();
                                self.save();
                            }
                            let handle = start_tunnel(self.edit_buf.tunnel.clone());
                            self.handles.insert(tunnel_id.clone(), handle);
                        }
                    }

                    let save_btn =
                        ui.add_enabled(!is_running && validation_err.is_none(), egui::Button::new("Save"));
                    if save_btn.clicked() {
                        self.edit_buf.apply_ports();
                        if let Some(idx) = self.selected {
                            self.tunnels[idx] = self.edit_buf.tunnel.clone();
                            self.save();
                        }
                    }

                    if !is_running {
                        let del_btn = ui.add(
                            egui::Button::new("Delete")
                                .fill(Color32::from_rgb(100, 30, 30)),
                        );
                        if del_btn.clicked() {
                            self.confirm_delete = self.selected;
                        }
                    }
                }
            });

            if let Some(err) = validation_err {
                ui.add_space(4.0);
                ui.label(RichText::new(err).color(Color32::from_rgb(220, 60, 60)).small());
            }

            // Confirm delete dialog
            if let Some(del_idx) = self.confirm_delete {
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.label("Delete this tunnel?");
                    ui.horizontal(|ui| {
                        if ui.button("Yes, delete").clicked() {
                            if del_idx < self.tunnels.len() {
                                self.tunnels.remove(del_idx);
                                self.save();
                            }
                            self.selected = None;
                            self.mode = Mode::None;
                            self.confirm_delete = None;
                        }
                        if ui.button("Cancel").clicked() {
                            self.confirm_delete = None;
                        }
                    });
                });
            }
        });
    }
}

fn field(ui: &mut Ui, label: &str, value: &mut String, disabled: bool) {
    ui.label(label);
    let widget = egui::TextEdit::singleline(value).interactive(!disabled);
    ui.add(widget);
}

fn port_field(ui: &mut Ui, label: &str, value: &mut String, disabled: bool, hint: &str) {
    ui.label(label);
    let widget = egui::TextEdit::singleline(value)
        .interactive(!disabled)
        .desired_width(80.0)
        .hint_text(hint);
    ui.add(widget);
}
