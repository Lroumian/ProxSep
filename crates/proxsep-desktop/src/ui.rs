use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

use eframe::egui::{self, Color32, ComboBox, DragValue, RichText, ScrollArea, TextEdit};
use proxsep_command::{CommandContext, CommandRegistry};
use proxsep_core::{
    profile::{Action, Chain, CredentialState, Profile, Proxy, Rule},
    rules::{Connection, RuleEngine, RuleTraceOutcome},
};
use proxsep_desktop::{DiagnosticContextInput, ProfileEditor, window_title};
use proxsep_runtime::{ConnectionEvent, ListenerHandle, Runtime};

const DEFAULT_PROFILE: &str = include_str!("../../proxsep-core/tests/fixtures/default.ppx");

fn new_profile() -> Profile {
    let mut profile = Profile::from_xml(DEFAULT_PROFILE).expect("embedded profile");
    profile.options.encryption_mode = "disabled".into();
    profile.credential_state = CredentialState::Plaintext;
    profile
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Connections,
    Proxies,
    Chains,
    Rules,
    Options,
    Diagnostics,
}

#[derive(Clone, Copy)]
enum Pending {
    New,
    Open,
    Quit,
}

pub struct DesktopApp {
    editor: ProfileEditor,
    path: Option<PathBuf>,
    tab: Tab,
    status: String,
    pending: Option<Pending>,
    allow_close: bool,
    application: String,
    target: String,
    port: u16,
    diagnostic_context: DiagnosticContextInput,
    check_result: String,
    check_rx: Option<mpsc::Receiver<String>>,
    async_runtime: tokio::runtime::Runtime,
    service: Arc<Runtime>,
    commands: CommandRegistry,
    listener: Option<ListenerHandle>,
    start_rx: Option<mpsc::Receiver<Result<ListenerHandle, String>>>,
    listen_address: String,
    listener_application: String,
    log_filter: String,
    errors_only: bool,
    include_history: bool,
    selected_connection: Option<u64>,
    dns_listener: Option<ListenerHandle>,
    dns_start_rx: Option<mpsc::Receiver<Result<ListenerHandle, String>>>,
    dns_address: String,
    dns_upstream: String,
}

impl DesktopApp {
    pub fn new(cc: &eframe::CreationContext<'_>, path: Option<PathBuf>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        if let Ok(bytes) = std::fs::read("C:/Windows/Fonts/msyh.ttc") {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "system-cjk".into(),
                Arc::new(egui::FontData::from_owned(bytes)),
            );
            for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts
                    .families
                    .entry(family)
                    .or_default()
                    .push("system-cjk".into());
            }
            cc.egui_ctx.set_fonts(fonts);
        }
        let mut app = Self {
            editor: ProfileEditor::new(new_profile()),
            path: None,
            tab: Tab::Connections,
            status: "Ready".into(),
            pending: None,
            allow_close: false,
            application: "browser.exe".into(),
            target: "example.com".into(),
            port: 443,
            diagnostic_context: DiagnosticContextInput::default(),
            check_result: String::new(),
            check_rx: None,
            async_runtime: tokio::runtime::Runtime::new().expect("network runtime"),
            service: Runtime::new(new_profile()),
            commands: CommandRegistry::standard(),
            listener: None,
            start_rx: None,
            listen_address: "127.0.0.1:1080".into(),
            listener_application: "socks-client.exe".into(),
            log_filter: String::new(),
            errors_only: false,
            include_history: false,
            selected_connection: None,
            dns_listener: None,
            dns_start_rx: None,
            dns_address: "127.0.0.1:5353".into(),
            dns_upstream: "1.1.1.1:53".into(),
        };
        if let Some(path) = path {
            app.load(path);
        }
        app
    }

    fn load(&mut self, path: PathBuf) {
        match std::fs::read_to_string(&path)
            .map_err(|e| e.to_string())
            .and_then(|xml| self.editor.replace_xml(&xml))
        {
            Ok(()) => {
                self.path = Some(path);
                self.status = match self.service.replace_profile(self.editor.profile.clone()) {
                    Ok(()) => "Profile opened and applied to new connections".into(),
                    Err(error) => format!("Profile opened; runtime validation failed: {error}"),
                };
            }
            Err(error) => self.status = format!("Open failed: {error}"),
        }
    }

    fn execute_runtime_command(
        &self,
        command: &str,
        arguments: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.commands
            .execute(
                &CommandContext {
                    runtime: Some(Arc::clone(&self.service)),
                },
                command,
                arguments,
            )
            .map_err(|error| error.to_string())
    }

    fn apply_runtime_profile(&self) -> Result<(), String> {
        let xml = self
            .editor
            .profile
            .to_xml()
            .map_err(|error| error.to_string())?;
        self.execute_runtime_command("runtime.profile.replace", serde_json::json!({ "xml": xml }))?;
        Ok(())
    }

    fn save_profile(&mut self, save_as: bool) -> bool {
        let path = if save_as || self.path.is_none() {
            rfd::FileDialog::new()
                .add_filter("Proxifier profile", &["ppx"])
                .set_file_name("Profile.ppx")
                .save_file()
        } else {
            self.path.clone()
        };
        let Some(path) = path else { return false };
        match self
            .editor
            .profile
            .to_xml()
            .map_err(|e| e.to_string())
            .and_then(|xml| {
                proxsep_desktop::save_xml_atomic(&path, &xml).map_err(|e| e.to_string())
            }) {
            Ok(()) => {
                self.path = Some(path);
                self.editor.dirty = false;
                self.status = "Profile saved".into();
                true
            }
            Err(error) => {
                self.status = format!("Save failed: {error}");
                false
            }
        }
    }

    fn request(&mut self, pending: Pending, ctx: &egui::Context) {
        if self.editor.dirty {
            self.pending = Some(pending);
        } else {
            self.execute(pending, ctx);
        }
    }

    fn execute(&mut self, pending: Pending, ctx: &egui::Context) {
        match pending {
            Pending::New => {
                self.editor = ProfileEditor::new(new_profile());
                self.path = None;
                self.status = match self.service.replace_profile(self.editor.profile.clone()) {
                    Ok(()) => "New profile applied to new connections".into(),
                    Err(error) => format!("Runtime validation failed: {error}"),
                };
            }
            Pending::Open => {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Proxifier profile", &["ppx"])
                    .pick_file()
                {
                    self.load(path);
                }
            }
            Pending::Quit => {
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn unsaved_prompt(&mut self, ctx: &egui::Context) {
        if let Some(pending) = self.pending {
            egui::Modal::new(egui::Id::new("unsaved_profile")).show(ctx, |ui| {
                ui.heading("Unsaved profile");
                ui.label("Save your profile changes before continuing?");
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() && self.save_profile(false) {
                        self.pending = None;
                        self.execute(pending, ctx);
                    }
                    if ui.button("Discard").clicked() {
                        self.pending = None;
                        self.execute(pending, ctx);
                    }
                    if ui.button("Cancel").clicked() {
                        self.pending = None;
                    }
                });
            });
        }
    }

    fn proxies(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy servers");
        if self.editor.profile.credential_state == CredentialState::AccountUnlocked {
            ui.label("Credentials are unlocked for this Windows account and will be protected with Windows DPAPI when saved.");
        } else if !["none", "disabled"].iter().any(|mode| {
            self.editor
                .profile
                .options
                .encryption_mode
                .eq_ignore_ascii_case(mode)
        }) {
            ui.label("This profile uses an unsupported credential scheme. Existing opaque values are preserved, but cannot be edited or converted without their matching backend.");
        }
        if ui.button("Add proxy").clicked() {
            let proxy = Proxy {
                id: self.editor.next_proxy_id(),
                ..Proxy::default()
            };
            self.editor.profile.proxies.push(proxy);
            self.editor.dirty = true;
        }
        let mut remove = None;
        let mut check = None;
        for proxy in &mut self.editor.profile.proxies {
            ui.push_id(proxy.id, |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", proxy.id));
                        ComboBox::from_id_salt("protocol")
                            .selected_text(&proxy.protocol)
                            .show_ui(ui, |ui| {
                                for (value, label) in [
                                    ("SOCKS5", "SOCKS5"),
                                    ("SOCKS4", "SOCKS4 / SOCKS4a"),
                                    ("HTTPS", "HTTP CONNECT"),
                                ] {
                                    self.editor.dirty |= ui
                                        .selectable_value(&mut proxy.protocol, value.into(), label)
                                        .changed();
                                }
                            });
                        self.editor.dirty |= ui
                            .add(
                                TextEdit::singleline(&mut proxy.address)
                                    .hint_text("Proxy host")
                                    .desired_width(220.0),
                            )
                            .changed();
                        self.editor.dirty |= ui
                            .add(DragValue::new(&mut proxy.port).range(1..=65535))
                            .changed();
                        if ui.button("Check").clicked() {
                            check = Some(proxy.clone());
                        }
                        if ui.button("Delete").clicked() {
                            remove = Some(proxy.id);
                        }
                    });
                    ui.horizontal(|ui| {
                        let mut auth = proxy.username.is_some();
                        if ui.checkbox(&mut auth, "Authentication").changed() {
                            proxy.username = auth.then(String::new);
                            proxy.password = auth.then(String::new);
                            self.editor.dirty = true;
                        }
                        if let Some(username) = &mut proxy.username {
                            self.editor.dirty |= ui
                                .add(
                                    TextEdit::singleline(username)
                                        .hint_text("User")
                                        .desired_width(160.0),
                                )
                                .changed();
                        }
                        if let Some(password) = &mut proxy.password {
                            self.editor.dirty |= ui
                                .add(
                                    TextEdit::singleline(password)
                                        .password(true)
                                        .hint_text("Password")
                                        .desired_width(160.0),
                                )
                                .changed();
                        }
                    });
                    ui.collapsing("Advanced proxy settings", |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Label");
                            self.editor.dirty |=
                                ui.text_edit_singleline(&mut proxy.label).changed();
                        });
                        ui.horizontal(|ui| {
                            ui.label("HTTP User-Agent");
                            self.editor.dirty |=
                                ui.text_edit_singleline(&mut proxy.user_agent).changed();
                        });
                        ui.horizontal(|ui| {
                            ui.label("Options bitfield");
                            self.editor.dirty |=
                                ui.add(DragValue::new(&mut proxy.options)).changed();
                        });
                    });
                })
            });
        }
        if let Some(id) = remove {
            match self.editor.remove_proxy(id) {
                Ok(()) => self.status = "Proxy removed".into(),
                Err(e) => self.status = e,
            }
        }
        if let Some(proxy) = check {
            self.check_route(Action::Proxy(proxy.id.to_string()));
        }
        ui.separator();
        ui.label("Checker target (shared with Route diagnostics)");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.target);
            ui.add(DragValue::new(&mut self.port).range(1..=65535));
        });
        ui.label(&self.check_result);
    }

    fn check_route(&mut self, action: Action) {
        let mut profile = self.editor.profile.clone();
        let rule = Rule {
            name: "Proxy checker".into(),
            action,
            ..Rule::default()
        };
        profile.rules = vec![rule];
        let connection = Connection::new("proxy-checker.exe", &self.target, self.port);
        self.run_check(profile, connection);
    }

    fn run_check(&mut self, profile: Profile, connection: Connection) {
        let (tx, rx) = mpsc::channel();
        self.check_rx = Some(rx);
        self.check_result = "Connecting and testing tunnel...".into();
        let service = Runtime::new(profile);
        self.async_runtime.spawn(async move {
            let start = Instant::now();
            let result =
                tokio::time::timeout(Duration::from_secs(10), service.connect(&connection)).await;
            let message = match result {
                Ok(Ok(_)) => {
                    let route = service
                        .events()
                        .last()
                        .map(|event| format!("{} / {}", event.rule, event.action))
                        .unwrap_or_default();
                    format!(
                        "Tunnel established in {} ms — {}",
                        start.elapsed().as_millis(),
                        route
                    )
                }
                Ok(Err(error)) => format!("Check failed: {error}"),
                Err(_) => "Check timed out after 10 seconds".into(),
            };
            let _ = tx.send(message);
        });
    }

    fn chains(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxy chains");
        if ui.button("Add chain").clicked() {
            let chain = Chain {
                id: self.editor.next_proxy_id(),
                name: "New chain".into(),
                ..Chain::default()
            };
            self.editor.profile.chains.push(chain);
            self.editor.dirty = true;
        }
        let proxies = self.editor.profile.proxies.clone();
        let mut remove = None;
        let mut check = None;
        for chain in &mut self.editor.profile.chains {
            ui.push_id(chain.id, |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(format!("#{}", chain.id));
                        self.editor.dirty |= ui.text_edit_singleline(&mut chain.name).changed();
                        ComboBox::from_id_salt("chain_mode")
                            .selected_text(&chain.kind)
                            .show_ui(ui, |ui| {
                                for (value, label) in [
                                    ("simple", "Sequential chain"),
                                    ("redundancy", "Redundancy"),
                                    ("load_balancing", "Load balancing"),
                                ] {
                                    self.editor.dirty |= ui
                                        .selectable_value(&mut chain.kind, value.into(), label)
                                        .changed();
                                }
                            });
                        if ui.button("Check").clicked() {
                            check = Some(chain.id);
                        }
                        if ui.button("Delete chain").clicked() {
                            remove = Some(chain.id);
                        }
                    });
                    let mut movement = None;
                    let mut deletion = None;
                    let hop_count = chain.proxy_ids.len();
                    for (index, id) in chain.proxy_ids.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(format!("{}.", index + 1));
                            ComboBox::from_id_salt(index)
                                .selected_text(proxy_label(&proxies, *id))
                                .show_ui(ui, |ui| {
                                    for proxy in &proxies {
                                        self.editor.dirty |= ui
                                            .selectable_value(
                                                id,
                                                proxy.id,
                                                proxy_label(&proxies, proxy.id),
                                            )
                                            .changed();
                                    }
                                });
                            let mut enabled = !chain.disabled_proxy_ids.contains(id);
                            if ui.checkbox(&mut enabled, "Enabled").changed() {
                                chain.disabled_proxy_ids.retain(|disabled| disabled != id);
                                if !enabled {
                                    chain.disabled_proxy_ids.push(*id);
                                }
                                self.editor.dirty = true;
                            }
                            if ui.add_enabled(index > 0, egui::Button::new("Up")).clicked() {
                                movement = Some((index, index - 1));
                            }
                            if ui
                                .add_enabled(index + 1 < hop_count, egui::Button::new("Down"))
                                .clicked()
                            {
                                movement = Some((index, index + 1));
                            }
                            if ui.button("Remove").clicked() {
                                deletion = Some(index);
                            }
                        });
                    }
                    if let Some((a, b)) = movement {
                        chain.proxy_ids.swap(a, b);
                        self.editor.dirty = true;
                    }
                    if let Some(index) = deletion {
                        chain.proxy_ids.remove(index);
                        self.editor.dirty = true;
                    }
                    chain
                        .disabled_proxy_ids
                        .retain(|id| chain.proxy_ids.contains(id));
                    if ui
                        .add_enabled(!proxies.is_empty(), egui::Button::new("Append proxy hop"))
                        .clicked()
                    {
                        chain.proxy_ids.push(proxies[0].id);
                        self.editor.dirty = true;
                    }
                    if chain.kind == "redundancy" {
                        ui.horizontal(|ui| {
                            ui.label("Failover timeout (seconds)");
                            self.editor.dirty |= ui
                                .add(DragValue::new(&mut chain.redundancy_timeout).range(1..=9999))
                                .changed();
                        });
                        self.editor.dirty |= ui
                            .checkbox(
                                &mut chain.redundancy_try_direct,
                                "Try direct if every proxy fails",
                            )
                            .changed();
                        self.editor.dirty |= ui
                            .checkbox(&mut chain.redundancy_recheck, "Recheck failed proxies")
                            .changed();
                        ui.horizontal(|ui| {
                            ui.label("Recheck interval (seconds)");
                            self.editor.dirty |= ui
                                .add(
                                    DragValue::new(&mut chain.redundancy_recheck_time)
                                        .range(1..=86400),
                                )
                                .changed();
                        });
                    } else if chain.kind == "load_balancing" {
                        self.editor.dirty |= ui
                            .checkbox(
                                &mut chain.load_balancing_same_proxy_for_pid,
                                "Use the same proxy for connections from one process",
                            )
                            .changed();
                    }
                })
            });
        }
        if let Some(id) = remove {
            if self.editor.profile.rules.iter().any(|rule| matches!(&rule.action, Action::Chain(reference) if reference == &id.to_string())) {
                self.status = "Chain is used by a rule. Change that rule before deleting the chain.".into();
            } else { self.editor.profile.chains.retain(|c| c.id != id); self.editor.dirty = true; }
        }
        if let Some(id) = check {
            self.check_route(Action::Chain(id.to_string()));
        }
        ui.label(&self.check_result);
    }

    fn rules(&mut self, ui: &mut egui::Ui) {
        ui.heading("Proxification rules");
        ui.label("Rules run from top to bottom. The first enabled match decides the route.");
        if ui.button("Add rule").clicked() {
            let rule = Rule {
                name: "New rule".into(),
                ..Rule::default()
            };
            let index = self.editor.profile.rules.len().saturating_sub(1);
            self.editor.profile.rules.insert(index, rule);
            self.editor.dirty = true;
        }
        let routes = self
            .editor
            .profile
            .proxies
            .iter()
            .map(|p| {
                (
                    Action::Proxy(p.id.to_string()),
                    format!("Proxy {} · {}:{}", p.id, p.address, p.port),
                )
            })
            .chain(self.editor.profile.chains.iter().map(|c| {
                (
                    Action::Chain(c.id.to_string()),
                    format!("Chain {} · {}", c.id, c.name),
                )
            }))
            .collect::<Vec<_>>();
        let count = self.editor.profile.rules.len();
        let default_index = self
            .editor
            .profile
            .rules
            .iter()
            .position(|rule| rule.name.eq_ignore_ascii_case("Default"));
        let mut movement = None;
        let mut remove = None;
        for (index, rule) in self.editor.profile.rules.iter_mut().enumerate() {
            let is_default = rule.name.eq_ignore_ascii_case("Default");
            ui.push_id(index, |ui| {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        self.editor.dirty |= ui
                            .add_enabled(
                                !is_default,
                                egui::Checkbox::new(&mut rule.enabled, format!("{}.", index + 1)),
                            )
                            .changed();
                        let mut name = rule.name.clone();
                        if ui
                            .add_enabled(!is_default, TextEdit::singleline(&mut name))
                            .changed()
                        {
                            if name.eq_ignore_ascii_case("Default") {
                                self.status = "Default is a reserved rule name".into();
                            } else {
                                rule.name = name;
                                self.editor.dirty = true;
                            }
                        }
                        ComboBox::from_id_salt("action")
                            .selected_text(action_label(&rule.action, &routes))
                            .show_ui(ui, |ui| {
                                self.editor.dirty |= ui
                                    .selectable_value(&mut rule.action, Action::Direct, "Direct")
                                    .changed();
                                self.editor.dirty |= ui
                                    .selectable_value(&mut rule.action, Action::Block, "Block")
                                    .changed();
                                for (action, name) in &routes {
                                    self.editor.dirty |= ui
                                        .selectable_value(&mut rule.action, action.clone(), name)
                                        .changed();
                                }
                            });
                        if ui
                            .add_enabled(!is_default && index > 0, egui::Button::new("Up"))
                            .clicked()
                        {
                            movement = Some((index, -1));
                        }
                        if ui
                            .add_enabled(
                                !is_default
                                    && index + 1 < count
                                    && default_index != Some(index + 1),
                                egui::Button::new("Down"),
                            )
                            .clicked()
                        {
                            movement = Some((index, 1));
                        }
                        if ui
                            .add_enabled(!is_default, egui::Button::new("Delete"))
                            .clicked()
                        {
                            remove = Some(index);
                        }
                    });
                    egui::Grid::new("fields").num_columns(2).show(ui, |ui| {
                        ui.label("Applications");
                        self.editor.dirty |= ui
                            .add_enabled(
                                !is_default,
                                TextEdit::singleline(&mut rule.applications)
                                    .desired_width(640.0)
                                    .hint_text("Any; or app.exe; C:\\Apps\\*; separated by ;"),
                            )
                            .changed();
                        ui.end_row();
                        ui.label("Targets");
                        self.editor.dirty |= ui
                            .add_enabled(
                                !is_default,
                                TextEdit::singleline(&mut rule.targets)
                                    .desired_width(640.0)
                                    .hint_text("Any; or *.example.com; 10.0.0.0/8"),
                            )
                            .changed();
                        ui.end_row();
                        ui.label("Ports");
                        self.editor.dirty |= ui
                            .add_enabled(
                                !is_default,
                                TextEdit::singleline(&mut rule.ports)
                                    .desired_width(640.0)
                                    .hint_text("Any; or 80; 443; 8000-9000"),
                            )
                            .changed();
                        ui.end_row();
                        ui.label("Interface ID");
                        self.editor.dirty |= ui
                            .add_enabled(
                                !is_default,
                                TextEdit::singleline(&mut rule.interface_id)
                                    .desired_width(640.0)
                                    .hint_text("Interface GUID, or blank for any interface"),
                            )
                            .changed();
                        ui.end_row();
                        ui.label("Interface availability");
                        self.editor.dirty |= ui
                            .add_enabled(
                                !is_default,
                                egui::Checkbox::new(
                                    &mut rule.skip_if_interface_down,
                                    "Skip rule when interface is down",
                                ),
                            )
                            .changed();
                        ui.end_row();
                    });
                })
            });
        }
        if let Some((index, offset)) = movement {
            self.editor.move_rule(index, offset);
        }
        if let Some(index) = remove {
            self.editor.profile.rules.remove(index);
            self.editor.dirty = true;
        }
    }

    fn options(&mut self, ui: &mut egui::Ui) {
        ui.heading("Name resolution and profile options");
        let options = &mut self.editor.profile.options;
        let mut changed = false;
        ui.group(|ui| {
            ui.strong("DNS");
            changed |= ui
                .checkbox(
                    &mut options.resolve.auto_mode_detection,
                    "Detect DNS mode automatically",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.resolve.via_proxy,
                    "Resolve hostnames through proxy",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.resolve.block_non_a_types,
                    "Block non-A DNS query types",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.resolve.exclusion_only_from_list,
                    "Use only the DNS exclusion list",
                )
                .changed();
            ui.label("DNS exclusions (; separated)");
            changed |= ui
                .text_edit_singleline(&mut options.resolve.exclusion_list)
                .changed();
            ui.horizontal(|ui| {
                ui.label("DNS UDP mode");
                changed |= ui
                    .add(DragValue::new(&mut options.resolve.dns_udp_mode).range(0..=255))
                    .changed();
            });
        });
        ui.group(|ui| {
            ui.strong("Connections");
            changed |= ui
                .checkbox(
                    &mut options.connection_loop_detection,
                    "Detect proxy connection loops",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.connection_loop_resolve,
                    "Resolve connection loops automatically",
                )
                .changed();
            changed |= ui
                .checkbox(&mut options.leak_prevention, "Leak prevention")
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.process_other_users,
                    "Process connections from other users",
                )
                .changed();
            changed |= ui
                .checkbox(&mut options.process_services, "Process service connections")
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.handle_direct_connections,
                    "Handle direct connections",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut options.http_proxies_support,
                    "Enable HTTP proxy support",
                )
                .changed();
            ui.horizontal(|ui| {
                ui.label("UDP mode");
                changed |= ui.text_edit_singleline(&mut options.udp_mode).changed();
            });
        });
        self.editor.dirty |= changed;
        let current_mode = self.editor.profile.options.encryption_mode.clone();
        let mut requested_mode = current_mode.clone();
        ui.horizontal(|ui| {
            ui.label("Encryption mode");
            ComboBox::from_id_salt("credential_encryption")
                .selected_text(&current_mode)
                .show_ui(ui, |ui| {
                    for (mode, label) in [
                        ("disabled", "Disabled (plaintext)"),
                        ("basic", "Basic"),
                        ("account", "Current account"),
                        ("master", "Master password"),
                    ] {
                        ui.selectable_value(&mut requested_mode, mode.into(), label);
                    }
                });
        });
        if requested_mode != current_mode
            && let Err(error) = self.editor.set_encryption_mode(&requested_mode)
        {
            self.status = error;
        }
        ui.label("The profile preserves these options. OS-wide capture and driver features require a runtime backend that implements them.");
        ui.separator();
        ui.strong("Local DNS listener");
        ui.label("Use an explicit client DNS configuration to send queries here. This control does not change Windows DNS settings.");
        ui.horizontal(|ui| {
            ui.label("Listen");
            ui.add_enabled(
                self.dns_listener.is_none(),
                TextEdit::singleline(&mut self.dns_address).desired_width(170.0),
            );
            ui.label("Upstream DNS");
            ui.add_enabled(
                self.dns_listener.is_none(),
                TextEdit::singleline(&mut self.dns_upstream).desired_width(170.0),
            );
            if ui
                .add_enabled(
                    self.dns_listener.is_none() && self.dns_start_rx.is_none(),
                    egui::Button::new("Start DNS"),
                )
                .clicked()
            {
                match self.dns_upstream.parse::<std::net::SocketAddr>() {
                    Ok(upstream) => match self.service.replace_profile(self.editor.profile.clone())
                    {
                        Ok(()) => {
                            let (tx, rx) = mpsc::channel();
                            self.dns_start_rx = Some(rx);
                            let service = Arc::clone(&self.service);
                            let address = self.dns_address.clone();
                            self.async_runtime.spawn(async move {
                                let _ = tx.send(
                                    service
                                        .start_dns(&address, upstream)
                                        .await
                                        .map_err(|e| e.to_string()),
                                );
                            });
                            self.status = "Starting DNS listener...".into();
                        }
                        Err(error) => self.status = format!("Invalid profile: {error}"),
                    },
                    Err(error) => {
                        self.status =
                            format!("Upstream must be a numeric DNS socket address: {error}")
                    }
                }
            }
            if ui
                .add_enabled(self.dns_listener.is_some(), egui::Button::new("Stop DNS"))
                .clicked()
                && let Some(listener) = self.dns_listener.take()
            {
                self.async_runtime.spawn(async move {
                    listener.stop().await;
                });
                self.status = "DNS listener stopped".into();
            }
            if ui.button("Apply profile").clicked() {
                self.status = match self.service.replace_profile(self.editor.profile.clone()) {
                    Ok(()) => "Profile applied to new connections and DNS queries".into(),
                    Err(error) => format!("Invalid profile: {error}"),
                };
            }
        });
        if let Some(listener) = &self.dns_listener {
            ui.colored_label(
                Color32::from_rgb(20, 130, 60),
                format!("DNS listening on {}", listener.local_addr()),
            );
        }
    }

    fn diagnostics(&mut self, ui: &mut egui::Ui) {
        ui.heading("Route diagnostics");
        egui::Grid::new("diagnostics").show(ui, |ui| {
            ui.label("Application path");
            ui.text_edit_singleline(&mut self.application);
            ui.end_row();
            ui.label("Target host / address");
            ui.text_edit_singleline(&mut self.target);
            ui.end_row();
            ui.label("Port");
            ui.add(DragValue::new(&mut self.port).range(1..=65535));
            ui.end_row();
            ui.label("PID (optional)");
            ui.text_edit_singleline(&mut self.diagnostic_context.pid);
            ui.end_row();
            ui.label("Resolved IPs");
            ui.text_edit_singleline(&mut self.diagnostic_context.resolved_ips);
            ui.end_row();
            ui.label("Interface name");
            ui.text_edit_singleline(&mut self.diagnostic_context.interface_name);
            ui.end_row();
            ui.label("Interface IPs");
            ui.text_edit_singleline(&mut self.diagnostic_context.interface_ips);
            ui.end_row();
        });
        let mut connection = Connection::new(&self.application, &self.target, self.port);
        if let Err(error) = self.diagnostic_context.apply_to(&mut connection) {
            ui.separator();
            ui.colored_label(Color32::from_rgb(180, 45, 45), error);
            return;
        }
        let trace = RuleEngine::new(&self.editor.profile.rules).trace(&connection);
        ui.separator();
        ui.label(format!("Static rule preview: {}", trace.decision.rule_name));
        ui.label("Live testing includes runtime DNS and interface context.");
        ui.label(format!("Route: {:?}", trace.decision.action));
        ui.separator();
        ui.strong("Rule decision trace");
        ScrollArea::vertical()
            .id_salt("rule_decision_trace")
            .max_height(360.0)
            .show(ui, |ui| render_rule_trace(ui, &trace.rules));
        if ui.button("Test live profile route").clicked() {
            self.run_check(self.editor.profile.clone(), connection);
        }
        ui.label(&self.check_result);
    }

    fn connections(&mut self, ui: &mut egui::Ui) {
        ui.heading("Live Connections");
        ui.label("Local SOCKS5 listener routes configured clients through this profile.");
        ui.horizontal(|ui| {
            ui.label("Listen");
            ui.add_enabled(
                self.listener.is_none(),
                TextEdit::singleline(&mut self.listen_address).desired_width(170.0),
            );
            ui.label("Application rule identity");
            ui.add_enabled(
                self.listener.is_none(),
                TextEdit::singleline(&mut self.listener_application).desired_width(190.0),
            );
            if ui
                .add_enabled(
                    self.listener.is_none() && self.start_rx.is_none(),
                    egui::Button::new("Start"),
                )
                .clicked()
            {
                match self.service.replace_profile(self.editor.profile.clone()) {
                    Ok(()) => {
                        let (tx, rx) = mpsc::channel();
                        self.start_rx = Some(rx);
                        let service = Arc::clone(&self.service);
                        let address = self.listen_address.clone();
                        let application = self.listener_application.clone();
                        self.async_runtime.spawn(async move {
                            let result = service
                                .start_socks5(&address, application)
                                .await
                                .map_err(|e| e.to_string());
                            let _ = tx.send(result);
                        });
                        self.status = "Starting local listener...".into();
                    }
                    Err(error) => self.status = format!("Invalid profile: {error}"),
                }
            }
            if ui
                .add_enabled(self.listener.is_some(), egui::Button::new("Stop"))
                .clicked()
                && let Some(listener) = self.listener.take()
            {
                self.async_runtime.spawn(async move {
                    listener.stop().await;
                });
                self.status = "Listener stopped".into();
            }
            if ui.button("Apply profile").clicked() {
                self.status = match self.apply_runtime_profile() {
                    Ok(()) => "Runtime profile updated for new connections".into(),
                    Err(e) => format!("Invalid profile: {e}"),
                };
            }
            if ui.button("Reset failed proxies").clicked() {
                self.status = match self
                    .execute_runtime_command("runtime.failure.reset", serde_json::json!({}))
                {
                    Ok(_) => "Proxy failure and affinity state reset".into(),
                    Err(error) => format!("Reset failed: {error}"),
                };
            }
        });
        if let Some(listener) = &self.listener {
            ui.colored_label(
                Color32::from_rgb(20, 130, 60),
                format!("Listening on {}", listener.local_addr()),
            );
        }
        ui.separator();
        let events = self.service.events();
        let active_count = events.iter().filter(|event| event.is_active()).count();
        let sent: u64 = events.iter().map(|event| event.sent).sum();
        let received: u64 = events.iter().map(|event| event.received).sum();
        ui.horizontal(|ui| {
            ui.strong(format!("Active: {active_count}"));
            ui.label(format!(
                "Retained: {} · Sent: {} · Received: {}",
                events.len(),
                format_bytes(sent),
                format_bytes(received)
            ));
        });
        ui.horizontal(|ui| {
            ui.label("Filter");
            ui.text_edit_singleline(&mut self.log_filter);
            ui.checkbox(&mut self.include_history, "Include history");
            ui.checkbox(&mut self.errors_only, "Errors only");
            if ui.button("Clear history").clicked() {
                self.status = match self.execute_runtime_command(
                    "runtime.connection.history_clear",
                    serde_json::json!({}),
                ) {
                    Ok(result) => format!(
                        "Cleared {} completed connections",
                        result["removed"].as_u64().unwrap_or_default()
                    ),
                    Err(error) => format!("Clear history failed: {error}"),
                };
            }
            if ui.button("Export log...").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("TSV log", &["tsv"])
                    .set_file_name("connections.tsv")
                    .save_file()
            {
                let mut log = "ID\tProtocol\tApplication\tPID\tTarget\tPort\tResolved IPs\tInterface\tRule\tAction\tState\tSent\tReceived\tDuration ms\tError\n".to_owned();
                for event in &events {
                    log.push_str(&format!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                        event.id,
                        tsv(&event.protocol),
                        tsv(&event.application),
                        event.pid.map(|pid| pid.to_string()).unwrap_or_default(),
                        tsv(&event.target),
                        event.port,
                        tsv(&ip_list(&event.resolved_ips)),
                        tsv(event.interface_id.as_deref().unwrap_or("")),
                        tsv(&event.rule),
                        tsv(&event.action),
                        tsv(&event.state),
                        event.sent,
                        event.received,
                        event
                            .duration()
                            .map(|duration| duration.as_millis().to_string())
                            .unwrap_or_default(),
                        tsv(event.error.as_deref().unwrap_or(""))
                    ));
                }
                self.status = match std::fs::write(path, log) {
                    Ok(()) => "Connection log exported".into(),
                    Err(e) => format!("Export failed: {e}"),
                };
            }
        });
        let filter = self.log_filter.to_ascii_lowercase();
        let visible_events = events
            .iter()
            .rev()
            .filter(|event| self.include_history || event.is_active())
            .filter(|event| !self.errors_only || event.error.is_some())
            .filter(|event| {
                filter.is_empty()
                    || format!(
                        "{} {} {} {} {} {}",
                        event.application,
                        event.pid.map(|pid| pid.to_string()).unwrap_or_default(),
                        event.target,
                        event.rule,
                        event.action,
                        event.state
                    )
                    .to_ascii_lowercase()
                    .contains(&filter)
            })
            .collect::<Vec<_>>();
        ScrollArea::both()
            .id_salt("connection_grid")
            .max_height(360.0)
            .show(ui, |ui| {
                egui::Grid::new("events")
                    .striped(true)
                    .spacing([16.0, 8.0])
                    .show(ui, |ui| {
                        for label in [
                            "ID",
                            "Process",
                            "PID",
                            "Protocol",
                            "Destination",
                            "Route",
                            "State",
                            "Up",
                            "Down",
                        ] {
                            ui.strong(label);
                        }
                        ui.end_row();
                        for event in &visible_events {
                            if ui
                                .selectable_label(
                                    self.selected_connection == Some(event.id),
                                    event.id.to_string(),
                                )
                                .clicked()
                            {
                                self.selected_connection = Some(event.id);
                            }
                            ui.label(&event.application);
                            ui.label(event.pid.map(|pid| pid.to_string()).unwrap_or_default());
                            ui.label(&event.protocol);
                            ui.label(format!("{}:{}", event.target, event.port));
                            ui.label(&event.action);
                            ui.label(&event.state);
                            ui.label(format_bytes(event.sent));
                            ui.label(format_bytes(event.received));
                            ui.end_row();
                        }
                    });
            });
        if let Some(event) = self
            .selected_connection
            .and_then(|id| events.iter().find(|event| event.id == id))
        {
            ui.separator();
            connection_details(ui, event);
        }
    }
}

fn proxy_label(proxies: &[proxsep_core::profile::Proxy], id: u32) -> String {
    proxies
        .iter()
        .find(|p| p.id == id)
        .map(|p| format!("{} · {}:{}", id, p.address, p.port))
        .unwrap_or_else(|| format!("Missing proxy #{id}"))
}

fn action_label(action: &Action, routes: &[(Action, String)]) -> String {
    match action {
        Action::Direct => "Direct".into(),
        Action::Block => "Block".into(),
        Action::Proxy(id) | Action::Chain(id) => routes
            .iter()
            .find(|(value, _)| value == action)
            .map(|(_, label)| label.clone())
            .unwrap_or_else(|| format!("Proxy/chain {id}")),
    }
}

fn render_rule_trace(ui: &mut egui::Ui, rules: &[proxsep_core::rules::RuleTrace]) {
    for rule in rules {
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.strong(format!("Rule #{} {}", rule.index + 1, rule.rule_name));
                let color = match rule.outcome {
                    RuleTraceOutcome::Matched | RuleTraceOutcome::DefaultFallback => {
                        Color32::from_rgb(20, 130, 60)
                    }
                    RuleTraceOutcome::NotMatched => Color32::from_rgb(180, 45, 45),
                    _ => Color32::GRAY,
                };
                ui.colored_label(color, rule.outcome.label());
            });
            for condition in &rule.conditions {
                let marker = if condition.matched { "✓" } else { "✗" };
                let result = if condition.matched {
                    "matched"
                } else {
                    "mismatch"
                };
                let color = if condition.matched {
                    Color32::from_rgb(20, 130, 60)
                } else {
                    Color32::from_rgb(180, 45, 45)
                };
                ui.colored_label(
                    color,
                    format!("{marker} {} {result}", condition.kind.label()),
                );
                if !condition.matched {
                    ui.indent((rule.index, condition.kind.label()), |ui| {
                        ui.label(format!("Expected: {}", condition.expected));
                        ui.label(format!("Actual: {}", condition.actual));
                    });
                }
            }
        });
    }
}

fn ip_list(addresses: &[std::net::IpAddr]) -> String {
    addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() < 1 {
        format!("{} ms", duration.as_millis())
    } else if duration.as_secs() < 60 {
        format!("{:.1} s", duration.as_secs_f64())
    } else {
        format!("{:.1} min", duration.as_secs_f64() / 60.0)
    }
}

fn connection_details(ui: &mut egui::Ui, event: &ConnectionEvent) {
    ui.heading(format!("Connection #{}", event.id));
    egui::Grid::new(("connection_details", event.id))
        .num_columns(2)
        .spacing([18.0, 6.0])
        .show(ui, |ui| {
            ui.strong("Application");
            ui.label(&event.application);
            ui.end_row();
            ui.strong("PID");
            ui.label(
                event
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("Protocol");
            ui.label(&event.protocol);
            ui.end_row();
            ui.strong("State");
            ui.label(&event.state);
            ui.end_row();
            ui.strong("Started");
            ui.label(
                event
                    .started_at
                    .elapsed()
                    .map(|elapsed| format!("{} ago", format_duration(elapsed)))
                    .unwrap_or_else(|_| "just now".into()),
            );
            ui.end_row();
            ui.strong("Duration");
            ui.label(
                event
                    .duration()
                    .map(format_duration)
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("Traffic");
            ui.label(format!(
                "{} sent · {} received",
                format_bytes(event.sent),
                format_bytes(event.received)
            ));
            ui.end_row();
            ui.strong("Target");
            ui.label(format!("{}:{}", event.target, event.port));
            ui.end_row();
            ui.strong("Resolved IPs");
            let resolved = ip_list(&event.resolved_ips);
            ui.label(if resolved.is_empty() {
                "—"
            } else {
                &resolved
            });
            ui.end_row();
            ui.strong("Connected endpoint");
            ui.label(
                event
                    .destination
                    .map(|destination| destination.to_string())
                    .unwrap_or_else(|| "—".into()),
            );
            ui.end_row();
            ui.strong("Interface");
            ui.label(event.interface_id.as_deref().unwrap_or("—"));
            ui.end_row();
            ui.strong("Bind addresses");
            let bind_ips = ip_list(&event.bind_ips);
            ui.label(if bind_ips.is_empty() {
                "—"
            } else {
                &bind_ips
            });
            ui.end_row();
            ui.strong("Rule");
            ui.label(&event.rule);
            ui.end_row();
            ui.strong("Action");
            ui.label(&event.action);
            ui.end_row();
            if let Some(error) = &event.error {
                ui.strong("Error");
                ui.colored_label(Color32::from_rgb(180, 45, 45), error);
                ui.end_row();
            }
        });
    egui::CollapsingHeader::new("Decision trace")
        .default_open(true)
        .show(ui, |ui| render_rule_trace(ui, &event.rule_trace));
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn tsv(value: &str) -> String {
    value.replace(['\t', '\r', '\n'], " ")
}

impl eframe::App for DesktopApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| i.viewport().close_requested()) && self.editor.dirty && !self.allow_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.pending = Some(Pending::Quit);
        }
        if let Some(receiver) = &self.check_rx
            && let Ok(result) = receiver.try_recv()
        {
            self.check_result = result;
            self.check_rx = None;
        }
        if let Some(receiver) = &self.start_rx
            && let Ok(result) = receiver.try_recv()
        {
            match result {
                Ok(listener) => {
                    self.status = format!("Listening on {}", listener.local_addr());
                    self.listener = Some(listener);
                }
                Err(e) => self.status = format!("Listener failed: {e}"),
            }
            self.start_rx = None;
        }
        if let Some(receiver) = &self.dns_start_rx
            && let Ok(result) = receiver.try_recv()
        {
            match result {
                Ok(listener) => {
                    self.status = format!("DNS listening on {}", listener.local_addr());
                    self.dns_listener = Some(listener);
                }
                Err(error) => self.status = format!("DNS listener failed: {error}"),
            }
            self.dns_start_rx = None;
        }
        if self.pending.is_none()
            && ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::S))
        {
            self.save_profile(false);
        }
        if self.pending.is_none()
            && ctx.input(|i| i.modifiers.command && i.key_pressed(egui::Key::O))
        {
            self.request(Pending::Open, ctx);
        }
        let profile_name = self
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "New profile".into());
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(window_title(
            &profile_name,
            self.editor.dirty,
        )));
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("New").clicked() {
                    self.request(Pending::New, ctx);
                }
                if ui.button("Open...").clicked() {
                    self.request(Pending::Open, ctx);
                }
                if ui.button("Save").clicked() {
                    self.save_profile(false);
                }
                if ui.button("Save as...").clicked() {
                    self.save_profile(true);
                }
                ui.separator();
                ui.label(RichText::new(profile_name).strong());
            });
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (Tab::Connections, "Connections"),
                    (Tab::Proxies, "Proxy servers"),
                    (Tab::Chains, "Proxy chains"),
                    (Tab::Rules, "Rules"),
                    (Tab::Options, "DNS / Options"),
                    (Tab::Diagnostics, "Route diagnostics"),
                ] {
                    ui.selectable_value(&mut self.tab, tab, label);
                }
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                if self.editor.dirty {
                    ui.colored_label(Color32::from_rgb(180, 110, 0), "Unsaved changes");
                }
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ScrollArea::both().show(ui, |ui| match self.tab {
                Tab::Connections => self.connections(ui),
                Tab::Proxies => self.proxies(ui),
                Tab::Chains => self.chains(ui),
                Tab::Rules => self.rules(ui),
                Tab::Options => self.options(ui),
                Tab::Diagnostics => self.diagnostics(ui),
            });
        });
        self.unsaved_prompt(ctx);
        ctx.request_repaint_after(Duration::from_millis(250));
    }
}
