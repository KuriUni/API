#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Align, Color32, Layout, RichText, TextEdit};
use rand::{Rng, distributions::Alphanumeric};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        Arc,
        mpsc::{self, Receiver, Sender},
    },
    thread,
    time::{Duration, Instant},
};

const ADMIN_API: &str = "https://2415.jp/license/admin_api.php";
const TENANT_API: &str = "https://2415.jp/license/ha/tenant-admin.php";
const HEALTH_API: &str = "https://2415.jp/license/ha/health.php";
const SSO_START: &str =
    "https://2415.jp/license/admin_api.php?admin_sso_start=1&return_app=desktop";
const BG: Color32 = Color32::from_rgb(242, 244, 247);
const NAV: Color32 = Color32::from_rgb(38, 50, 56);
const BLUE: Color32 = Color32::from_rgb(0, 90, 158);

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 850.0])
            .with_min_inner_size([980.0, 640.0])
            .with_title("TUTI Operations"),
        ..Default::default()
    };
    eframe::run_native(
        "TUTI Operations",
        options,
        Box::new(|cc| Ok(Box::new(OperationsApp::new(cc)))),
    )
}

fn install_japanese_font(ctx: &egui::Context) {
    // Windows Japanese editions include this standalone TrueType font. Load it
    // from the OS instead of bundling a licensed font file with the app.
    let candidates = [
        Path::new(r"C:\Windows\Fonts\yumin.ttf"),
        Path::new(r"C:\Windows\Fonts\yuminl.ttf"),
    ];
    let Some(bytes) = candidates.iter().find_map(|path| fs::read(path).ok()) else {
        return;
    };

    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "windows_japanese".to_owned(),
        Arc::new(egui::FontData::from_owned(bytes)),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .push("windows_japanese".to_owned());
    }
    ctx.set_fonts(fonts);
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Page {
    #[default]
    Overview,
    Tenants,
    ApiKeys,
    Licenses,
    Audit,
    Admins,
    Invite,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Admin,
    Tenant,
    Health,
}

#[derive(Clone)]
struct RequestSpec {
    action: String,
    endpoint: Endpoint,
    method: String,
    path: String,
    body: Value,
    confirm: Option<String>,
}

enum Event {
    Login(Result<String, String>),
    Request {
        action: String,
        result: Result<Value, String>,
    },
}

struct OperationsApp {
    tx: Sender<Event>,
    rx: Receiver<Event>,
    page: Page,
    session_token: Option<String>,
    login_busy: bool,
    pending_jobs: usize,
    after_step_up: Option<RequestSpec>,
    confirm: Option<RequestSpec>,
    status: String,
    status_error: bool,
    admin_api_connected: bool,
    service_ready: Option<bool>,
    tenants: Vec<Value>,
    licenses: Vec<Value>,
    api_keys: Vec<Value>,
    audit_logs: Vec<Value>,
    admins: Vec<Value>,
    selected_tenant: String,
    selected_license: String,
    selected_api_key: String,
    selected_admin: String,
    tenant_name: String,
    tenant_slug: String,
    tenant_plan: String,
    tenant_edit_name: String,
    tenant_edit_plan: String,
    license_tenant: String,
    license_product: String,
    license_label: String,
    license_mode: String,
    license_max_devices: String,
    license_query: String,
    license_status: String,
    show_deleted: bool,
    license_operation: String,
    renew_days: String,
    key_tenant: String,
    key_name: String,
    key_scopes: String,
    key_rate: String,
    key_grace: String,
    audit_query: String,
    audit_event: String,
    audit_actor: String,
    audit_from: String,
    audit_to: String,
    admin_role: String,
    invite_tenant: String,
    invite_email: String,
    secret_dialog: Option<(String, String)>,
}

impl OperationsApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        install_japanese_font(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel();
        Self {
            tx,
            rx,
            page: Page::Overview,
            session_token: None,
            login_busy: false,
            pending_jobs: 0,
            after_step_up: None,
            confirm: None,
            status: "SSO IDでログインしてください。".into(),
            status_error: false,
            admin_api_connected: false,
            service_ready: None,
            tenants: vec![],
            licenses: vec![],
            api_keys: vec![],
            audit_logs: vec![],
            admins: vec![],
            selected_tenant: String::new(),
            selected_license: String::new(),
            selected_api_key: String::new(),
            selected_admin: String::new(),
            tenant_name: String::new(),
            tenant_slug: String::new(),
            tenant_plan: "standard".into(),
            tenant_edit_name: String::new(),
            tenant_edit_plan: "standard".into(),
            license_tenant: String::new(),
            license_product: String::new(),
            license_label: String::new(),
            license_mode: "single".into(),
            license_max_devices: "10".into(),
            license_query: String::new(),
            license_status: String::new(),
            show_deleted: false,
            license_operation: "停止／再開".into(),
            renew_days: "30".into(),
            key_tenant: String::new(),
            key_name: String::new(),
            key_scopes: "tenant:read,licenses:read".into(),
            key_rate: "120".into(),
            key_grace: "60".into(),
            audit_query: String::new(),
            audit_event: String::new(),
            audit_actor: String::new(),
            audit_from: String::new(),
            audit_to: String::new(),
            admin_role: "viewer".into(),
            invite_tenant: String::new(),
            invite_email: String::new(),
            secret_dialog: None,
        }
    }

    fn start_login(&mut self, step_up: bool) {
        if self.login_busy {
            return;
        }
        self.login_busy = true;
        self.status = if step_up {
            "Passkey再認証を開始しています…"
        } else {
            "SSO IDログインを開始しています…"
        }
        .into();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let _ = tx.send(Event::Login(do_login(step_up)));
        });
    }

    fn request(&mut self, spec: RequestSpec) {
        if spec.confirm.is_some() {
            self.confirm = Some(spec);
            return;
        }
        let Some(token) = self.session_token.clone() else {
            self.set_status("先に管理者SSOへログインしてください。", true);
            return;
        };
        self.pending_jobs += 1;
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = do_request(&token, &spec);
            let _ = tx.send(Event::Request {
                action: spec.action,
                result,
            });
        });
    }

    fn admin(&mut self, action: &str, fields: Value, confirm: Option<&str>) {
        let mut body = fields.as_object().cloned().unwrap_or_default();
        body.insert("action".into(), Value::String(action.into()));
        self.request(RequestSpec {
            action: action.into(),
            endpoint: Endpoint::Admin,
            method: "POST".into(),
            path: ADMIN_API.into(),
            body: Value::Object(body),
            confirm: confirm.map(str::to_owned),
        });
    }

    fn tenant(
        &mut self,
        label: &str,
        method: &str,
        path: &str,
        body: Value,
        confirm: Option<&str>,
    ) {
        self.request(RequestSpec {
            action: label.into(),
            endpoint: Endpoint::Tenant,
            method: method.into(),
            path: path.into(),
            body,
            confirm: confirm.map(str::to_owned),
        });
    }

    fn set_status(&mut self, text: impl Into<String>, error: bool) {
        self.status = text.into();
        self.status_error = error;
    }

    fn load_tenants(&mut self) {
        self.tenant("tenant-list", "GET", TENANT_API, Value::Null, None);
    }
    fn load_licenses(&mut self) {
        self.admin(if self.show_deleted { "list_deleted_licenses" } else { "list_licenses" }, json!({"q": self.license_query.trim(), "status": if self.show_deleted { "" } else { self.license_status.as_str() }, "page": 1, "limit": 100}), None);
    }
    fn load_keys(&mut self) {
        if !self.key_tenant.trim().is_empty() {
            let path = format!(
                "{TENANT_API}?tenant_id={}",
                urlencoding::encode(self.key_tenant.trim())
            );
            self.tenant("key-list", "GET", &path, Value::Null, None);
        } else {
            self.admin("list_tenant_api_keys", json!({"page":1,"limit":100}), None);
        }
    }
    fn load_audit(&mut self) {
        self.admin("list_audit_logs", json!({"q":self.audit_query.trim(), "event_type":self.audit_event.trim(), "actor":self.audit_actor.trim(), "from":self.audit_from.trim(), "to":self.audit_to.trim(), "page":1,"limit":100}), None);
    }
    fn load_admins(&mut self) {
        self.admin("list_admin_principals", json!({}), None);
    }

    fn handle_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                Event::Login(result) => {
                    self.login_busy = false;
                    match result {
                        Ok(token) => {
                            self.session_token = Some(token);
                            self.set_status("SSO IDで認証しました。権限を確認しています。", false);
                            if let Some(spec) = self.after_step_up.take() {
                                self.request(spec);
                            } else {
                                self.admin("ping", json!({}), None);
                                self.load_tenants();
                                self.refresh_overview();
                            }
                        }
                        Err(error) => self.set_status(format!("ログイン失敗: {error}"), true),
                    }
                }
                Event::Request { action, result } => {
                    self.pending_jobs = self.pending_jobs.saturating_sub(1);
                    match result {
                        Ok(value) => self.request_succeeded(&action, value),
                        Err(error) => {
                            if action == "ping" {
                                self.admin_api_connected = false;
                            }
                            if action == "ha-health" {
                                self.service_ready = Some(false);
                            }
                            self.set_status(error, true);
                        }
                    }
                }
            }
        }
    }

    fn request_succeeded(&mut self, action: &str, value: Value) {
        match action {
            "tenant-list" => {
                self.tenants = array_at(&value, "tenants");
                if self.selected_tenant.is_empty() {
                    if let Some(t) = self.tenants.first().cloned() {
                        self.select_tenant(&t);
                    }
                }
                self.set_status(
                    format!("契約者 {} 件を取得しました。", self.tenants.len()),
                    false,
                );
            }
            "list_licenses" | "list_deleted_licenses" => {
                self.licenses = array_at(&value, "licenses");
                self.set_status(format!("ライセンス {} 件", self.licenses.len()), false);
            }
            "list_tenant_api_keys" | "key-list" => {
                self.api_keys = array_at(&value, "api_clients");
                self.set_status(format!("APIクライアント {} 件", self.api_keys.len()), false);
            }
            "list_audit_logs" => {
                self.audit_logs = array_at(&value, "logs");
                self.set_status(format!("監査ログ {} 件", self.audit_logs.len()), false);
            }
            "list_admin_principals" => {
                self.admins = array_at(&value, "admin_principals");
                self.set_status(format!("管理者 {} 件", self.admins.len()), false);
            }
            "ha-health" => {
                self.service_ready = Some(value.get("ok").and_then(Value::as_bool) == Some(true));
                self.set_status(
                    if self.service_ready == Some(true) {
                        "HAヘルス: 正常"
                    } else {
                        "HAヘルス: 要確認"
                    },
                    self.service_ready != Some(true),
                );
            }
            "ping" => {
                self.admin_api_connected = true;
                self.set_status("管理APIに接続しました。", false);
            }
            "create_license" | "issue_tenant_api_key" | "rotate_tenant_api_key" => {
                let secret = string_at(
                    &value,
                    if action == "create_license" {
                        "product_key"
                    } else {
                        "key"
                    },
                );
                if !secret.is_empty() {
                    self.secret_dialog = Some(("秘密値を発行しました".into(), secret));
                }
                self.set_status(
                    "発行が完了しました。秘密値はこの画面を閉じると再表示できません。",
                    false,
                );
                if action == "create_license" {
                    self.load_licenses();
                } else {
                    self.load_keys();
                }
            }
            "create_tenant" | "update_tenant" | "suspend_tenant" | "resume_tenant"
            | "ensure_sandbox" => {
                self.set_status("テナント操作が完了しました。", false);
                self.load_tenants();
            }
            "pause_license"
            | "resume_license"
            | "force_reauth_license"
            | "renew_license"
            | "delete_license"
            | "restore_license"
            | "revoke_tenant_api_key" => {
                self.set_status("変更を反映しました。", false);
                if action == "revoke_tenant_api_key" {
                    self.load_keys();
                } else {
                    self.load_licenses();
                }
            }
            "create_contractor_sso" => {
                self.set_status(string_at(&value, "message"), false);
                self.invite_email.clear();
            }
            "set_admin_role" => {
                self.set_status("管理者権限を更新しました。", false);
                self.load_admins();
            }
            "logout" => {
                self.session_token = None;
                self.set_status("ログアウトしました。", false);
            }
            other => self.set_status(format!("{other} 完了"), false),
        }
    }

    fn refresh_overview(&mut self) {
        self.admin("ping", json!({}), None);
        self.request(RequestSpec {
            action: "ha-health".into(),
            endpoint: Endpoint::Health,
            method: "GET".into(),
            path: HEALTH_API.into(),
            body: Value::Null,
            confirm: None,
        });
        self.admin("list_tenants", json!({"page":1,"limit":1}), None);
        self.admin("list_licenses", json!({"page":1,"limit":1}), None);
    }

    fn selected_tenant_value(&self) -> Option<&Value> {
        self.tenants
            .iter()
            .find(|x| string_at(x, "id") == self.selected_tenant)
    }

    fn select_tenant(&mut self, value: &Value) {
        self.selected_tenant = string_at(value, "id");
        self.tenant_edit_name = string_at(value, "name");
        self.tenant_edit_plan = string_at(value, "plan_code");
        self.key_tenant = self.selected_tenant.clone();
        if self.invite_tenant.is_empty() && string_at(value, "status") == "active" {
            self.invite_tenant = self.selected_tenant.clone();
        }
    }

    fn step_up_then(&mut self, spec: RequestSpec) {
        self.after_step_up = Some(spec);
        self.start_login(true);
    }

    fn load_page(&mut self, page: Page) {
        match page {
            Page::Tenants | Page::Invite => self.load_tenants(),
            Page::ApiKeys => self.load_keys(),
            Page::Licenses => self.load_licenses(),
            Page::Audit => self.load_audit(),
            Page::Admins => self.load_admins(),
            Page::Overview => self.refresh_overview(),
        }
    }
}

impl eframe::App for OperationsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_events();
        ctx.request_repaint_after(Duration::from_millis(120));

        egui::TopBottomPanel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(Color32::WHITE)
                    .inner_margin(egui::Margin::symmetric(12, 6)),
            )
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("TUTI Operations")
                                .strong()
                                .size(18.0)
                                .color(NAV),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new("管理コンソール")
                                .small()
                                .color(Color32::DARK_GRAY),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if self.session_token.is_some() {
                                if ui.button("ログアウト").clicked() {
                                    self.admin("logout", json!({}), None);
                                    self.session_token = None;
                                }
                            } else if ui
                                .add_enabled(
                                    !self.login_busy,
                                    egui::Button::new(if self.login_busy {
                                        "ブラウザーで認証中…"
                                    } else {
                                        "SSO IDでログイン"
                                    }),
                                )
                                .clicked()
                            {
                                self.start_login(false);
                            }
                            ui.separator();
                            ui.label(if self.session_token.is_some() {
                                RichText::new("SSO 接続中").color(Color32::from_rgb(26, 112, 69))
                            } else {
                                RichText::new("未ログイン").color(Color32::GRAY)
                            });
                        });
                    });
                    ui.add_space(4.0);
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        for (page, title) in [
                            (Page::Overview, "概要"),
                            (Page::Tenants, "テナント"),
                            (Page::ApiKeys, "APIキー"),
                            (Page::Licenses, "ライセンス"),
                            (Page::Audit, "監査ログ"),
                            (Page::Admins, "管理者権限"),
                            (Page::Invite, "契約者SSO招待"),
                        ] {
                            if ui.selectable_value(&mut self.page, page, title).changed()
                                && self.session_token.is_some()
                            {
                                self.load_page(page);
                            }
                        }
                    });
                });
            });

        egui::TopBottomPanel::bottom("status")
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(235, 237, 240))
                    .inner_margin(egui::Margin::symmetric(10, 4)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.pending_jobs > 0 {
                        ui.spinner();
                    }
                    ui.colored_label(
                        if self.status_error {
                            Color32::DARK_RED
                        } else {
                            Color32::from_rgb(70, 78, 86)
                        },
                        &self.status,
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new("管理API").small().color(Color32::DARK_GRAY));
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.heading(RichText::new(self.page.title()).size(20.0).color(NAV));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(
                                    RichText::new(self.page.description())
                                        .small()
                                        .color(Color32::DARK_GRAY),
                                );
                            });
                        });
                        ui.separator();
                        ui.add_space(8.0);
                        if self.session_token.is_none() {
                            self.login_prompt(ui);
                        } else {
                            match self.page {
                                Page::Overview => self.overview_ui(ui),
                                Page::Tenants => self.tenants_ui(ui),
                                Page::ApiKeys => self.keys_ui(ui),
                                Page::Licenses => self.licenses_ui(ui),
                                Page::Audit => self.audit_ui(ui),
                                Page::Admins => self.admins_ui(ui),
                                Page::Invite => self.invite_ui(ui),
                            }
                        }
                    });
            });

        if let Some(spec) = self.confirm.clone() {
            egui::Window::new("操作の確認")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(
                        spec.confirm
                            .as_deref()
                            .unwrap_or("この操作を実行しますか？"),
                    );
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("キャンセル").clicked() {
                            self.confirm = None;
                        }
                        if ui.button("実行").clicked() {
                            self.confirm = None;
                            self.launch_spec(spec);
                        }
                    });
                });
        }

        if let Some((title, secret)) = self.secret_dialog.clone() {
            egui::Window::new(title)
                .collapsible(false)
                .resizable(true)
                .default_width(580.0)
                .show(ctx, |ui| {
                    ui.colored_label(
                        Color32::DARK_RED,
                        "この秘密値は発行時だけ表示されます。安全な場所に保管してください。",
                    );
                    ui.add(
                        TextEdit::multiline(&mut secret.clone())
                            .desired_rows(3)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("コピー").clicked() {
                            ui.ctx().copy_text(secret.clone());
                            self.set_status(
                                "クリップボードにコピーしました。安全な場所に保管してください。",
                                false,
                            );
                        }
                        if ui.button("閉じる").clicked() {
                            self.secret_dialog = None;
                        }
                    });
                });
        }
    }
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Overview => "概要",
            Self::Tenants => "テナント",
            Self::ApiKeys => "テナントAPIキー",
            Self::Licenses => "ライセンス",
            Self::Audit => "監査ログ",
            Self::Admins => "管理者権限",
            Self::Invite => "契約者SSO招待",
        }
    }
    fn description(self) -> &'static str {
        match self {
            Self::Overview => "サービス状況と運用対象を確認します。",
            Self::Tenants => "契約者の環境、プラン、運用状態を管理します。",
            Self::ApiKeys => "テナントAPIクライアントの発行と失効を管理します。",
            Self::Licenses => "プロダクトキーとライセンス状態を管理します。",
            Self::Audit => "管理操作の監査記録を検索します。",
            Self::Admins => "管理者権限をPasskey再認証付きで変更します。",
            Self::Invite => "tenant IDを指定して契約者SSOを招待します。",
        }
    }
}

impl OperationsApp {
    fn login_prompt(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.heading("管理者SSO");
        ui.label("管理者IDでサインインしてください。認証は既定のブラウザーで行います。");
        ui.add_space(8.0);
        if ui
            .add_enabled(
                !self.login_busy,
                egui::Button::new("SSO IDでログイン").fill(BLUE),
            )
            .clicked()
        {
            self.start_login(false);
        }
    }

    fn overview_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            self.metric(
                ui,
                "管理API",
                if self.admin_api_connected {
                    "接続済み"
                } else {
                    "未確認"
                },
            );
            self.metric(
                ui,
                "サービス準備状態",
                match self.service_ready {
                    Some(true) => "正常",
                    Some(false) => "要確認",
                    None => "未確認",
                },
            );
            self.metric(ui, "契約者", self.tenants.len().to_string());
            self.metric(ui, "取得ライセンス", self.licenses.len().to_string());
        });
        ui.add_space(12.0);
        if ui.button("状況を更新").clicked() {
            self.refresh_overview();
        }
        ui.add_space(12.0);
        Self::card(ui, "運用の状態", |ui| {
            ui.label("一覧・操作の結果はサーバー管理APIから読み込みます。表示件数は現在の検索結果数です。");
            ui.label(
                "書き込み権限、対象テナント保護、再認証の要否はサーバー側の認可結果に従います。",
            );
        });
    }

    fn metric(&self, ui: &mut egui::Ui, label: &str, value: impl ToString) {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).small().color(Color32::DARK_GRAY));
            ui.label(
                RichText::new(value.to_string())
                    .strong()
                    .size(16.0)
                    .color(NAV),
            );
        });
    }
    fn card(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui)) {
        egui::Frame::group(ui.style())
            .fill(Color32::WHITE)
            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(205, 210, 216)))
            .corner_radius(egui::CornerRadius::same(2))
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.label(RichText::new(title).strong().color(NAV));
                ui.separator();
                content(ui);
            });
    }

    fn tenants_ui(&mut self, ui: &mut egui::Ui) {
        Self::card(ui, "新規契約先", |ui| {
            ui.horizontal_wrapped(|ui| { ui.label("契約者名"); ui.text_edit_singleline(&mut self.tenant_name); ui.label("Slug"); ui.text_edit_singleline(&mut self.tenant_slug); egui::ComboBox::from_id_salt("tenant-plan-new").selected_text(&self.tenant_plan).show_ui(ui,|ui| { for p in ["standard","trial","business","enterprise"] { ui.selectable_value(&mut self.tenant_plan,p.into(),p); } }); if ui.button("作成").clicked() { if self.tenant_name.trim().is_empty() || self.tenant_slug.trim().is_empty() { self.set_status("テナント名とslugを入力してください。",true); } else { self.admin("create_tenant",json!({"name":self.tenant_name.trim(),"slug":self.tenant_slug.trim(),"plan_code":self.tenant_plan}),Some("新しい契約先を作成しますか？")); } } if ui.button("一覧更新").clicked() { self.load_tenants(); } });
        });
        ui.add_space(12.0);
        Self::card(ui, "契約先一覧", |ui| {
            egui::Grid::new("tenant-grid").striped(true).show(ui, |ui| {
                for t in &self.tenants {
                    let id = string_at(t, "id");
                    let name = string_at(t, "name");
                    let status = string_at(t, "status");
                    let plan = string_at(t, "plan_code");
                    let env = string_at(t, "environment");
                    let products = string_at(t, "products");
                    let licenses = string_at(t, "licenses");
                    let active = self.selected_tenant == id;
                    if ui
                        .selectable_label(active, format!("#{id} {name}"))
                        .clicked()
                    {
                        self.selected_tenant = id.clone();
                        self.tenant_edit_name = name;
                        self.tenant_edit_plan = plan.clone();
                        self.key_tenant = id.clone();
                        if status == "active" {
                            self.invite_tenant = id;
                        }
                    }
                    ui.label(status);
                    ui.label(plan);
                    ui.label(env);
                    ui.label(format!("製品 {products} · License {licenses}"));
                    ui.end_row();
                }
            });
        });
        if let Some(t) = self.selected_tenant_value().cloned() {
            ui.add_space(12.0);
            Self::card(ui, "選択中テナントの運用", |ui| {
                ui.label(format!(
                    "ID {} · {} · {}",
                    self.selected_tenant,
                    string_at(&t, "slug"),
                    string_at(&t, "environment")
                ));
                ui.horizontal_wrapped(|ui| { ui.label("名称"); ui.text_edit_singleline(&mut self.tenant_edit_name); egui::ComboBox::from_id_salt("tenant-plan-edit").selected_text(&self.tenant_edit_plan).show_ui(ui,|ui| { for p in ["standard","trial","business","enterprise"] {ui.selectable_value(&mut self.tenant_edit_plan,p.into(),p);} });
                    if ui.button("名称・プランを保存").clicked() { if self.selected_tenant.parse::<i64>().unwrap_or(0)>1 { let id=self.selected_tenant.parse::<i64>().unwrap_or_default(); self.tenant("update_tenant","POST",TENANT_API,json!({"action":"update_tenant","tenant_id":id,"name":self.tenant_edit_name.trim(),"plan_code":self.tenant_edit_plan}),Some("契約先情報を更新しますか？")); } }
                    let active=string_at(&t,"status")=="active"; if ui.button(if active {"契約を一時停止"}else{"契約を再開"}).clicked() { let id=self.selected_tenant.parse::<i64>().unwrap_or_default(); let action=if active{"suspend_tenant"}else{"resume_tenant"}; self.tenant(action,"POST",TENANT_API,json!({"action":action,"tenant_id":id}),Some(if active{"契約を停止し、APIキーも一時停止しますか？"}else{"契約を再開しますか？"})); }
                    let has_sandbox=self.tenants.iter().any(|x|string_at(x,"parent_tenant_id")==self.selected_tenant); if string_at(&t,"environment")=="production" && active && !has_sandbox && ui.button("検証sandboxを作成").clicked() { let id=self.selected_tenant.parse::<i64>().unwrap_or_default(); self.tenant("ensure_sandbox","POST",TENANT_API,json!({"action":"ensure_sandbox","tenant_id":id}),Some("この契約先に検証sandboxを作成しますか？")); }
                });
            });
        }
    }

    fn keys_ui(&mut self, ui: &mut egui::Ui) {
        Self::card(ui, "APIクライアントの発行", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Tenant ID");
                ui.text_edit_singleline(&mut self.key_tenant);
                ui.label("名前");
                ui.text_edit_singleline(&mut self.key_name);
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("権限");
                ui.add(TextEdit::singleline(&mut self.key_scopes).desired_width(310.0));
                ui.label("毎分上限");
                ui.add(TextEdit::singleline(&mut self.key_rate).desired_width(65.0));
                ui.label("更新猶予(分)");
                ui.add(TextEdit::singleline(&mut self.key_grace).desired_width(65.0));
            });
            ui.horizontal(|ui| { if ui.button("一覧を更新").clicked(){self.load_keys();} if ui.button("APIキーを発行").clicked(){if let (Ok(tenant_id),Ok(rate))=(self.key_tenant.parse::<i64>(),self.key_rate.parse::<u32>()){self.admin("issue_tenant_api_key",json!({"tenant_id":tenant_id,"client_name":self.key_name.trim(),"scopes":self.key_scopes.trim(),"rate_limit_per_minute":rate,"api_key_expires_at":""}),Some("秘密キーを発行します。キーは一度だけ表示されます。実行しますか？"));}else{self.set_status("Tenant IDと毎分上限を確認してください。",true);}} if ui.button("選択キーを更新").clicked(){if let (Ok(id),Ok(grace))=(self.selected_api_key.parse::<i64>(),self.key_grace.parse::<u32>()){self.admin("rotate_tenant_api_key",json!({"client_id":id,"grace_minutes":grace}),Some("APIキーを更新しますか？"));}} if ui.button("選択キーを失効").clicked(){if let Ok(id)=self.selected_api_key.parse::<i64>(){self.admin("revoke_tenant_api_key",json!({"client_id":id}),Some("このAPIキーを失効しますか？この操作は元に戻せません。"));}} });
        });
        ui.add_space(12.0);
        Self::card(ui, "APIキー一覧", |ui| {
            egui::Grid::new("key-grid").striped(true).show(ui, |ui| {
                for h in [
                    "選択",
                    "ID",
                    "Tenant",
                    "契約先",
                    "クライアント",
                    "Prefix",
                    "Scopes",
                    "状態",
                    "期限",
                ] {
                    ui.strong(h);
                }
                ui.end_row();
                for k in &self.api_keys {
                    let id = string_at(k, "id");
                    if ui
                        .selectable_label(self.selected_api_key == id, "選択")
                        .clicked()
                    {
                        self.selected_api_key = id.clone();
                    }
                    ui.label(&id);
                    ui.label(string_at(k, "tenant_id"));
                    ui.label(string_at(k, "tenant_name"));
                    ui.label(string_at(k, "name"));
                    ui.label(string_at(k, "key_prefix"));
                    ui.label(string_at(k, "scopes_json"));
                    ui.label(string_at(k, "status"));
                    ui.label(string_at(k, "expires_at"));
                    ui.end_row();
                }
            });
        });
    }

    fn licenses_ui(&mut self, ui: &mut egui::Ui) {
        Self::card(ui, "発行・検索", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Tenant ID");
                ui.text_edit_singleline(&mut self.license_tenant);
                ui.label("Product ID");
                ui.text_edit_singleline(&mut self.license_product);
                ui.label("Label");
                ui.text_edit_singleline(&mut self.license_label);
            });
            ui.horizontal_wrapped(|ui| {
                egui::ComboBox::from_id_salt("license-mode")
                    .selected_text(&self.license_mode)
                    .show_ui(ui, |ui| {
                        for v in ["single", "volume", "evaluation"] {
                            ui.selectable_value(&mut self.license_mode, v.into(), v);
                        }
                    });
                ui.label("端末数");
                ui.add(TextEdit::singleline(&mut self.license_max_devices).desired_width(55.0));
                ui.separator();
                ui.add(
                    TextEdit::singleline(&mut self.license_query)
                        .desired_width(230.0)
                        .hint_text("ID・ラベル・テナント・製品"),
                );
                egui::ComboBox::from_id_salt("license-status")
                    .selected_text(if self.license_status.is_empty() {
                        "すべて"
                    } else {
                        &self.license_status
                    })
                    .show_ui(ui, |ui| {
                        for v in ["", "active", "paused", "revoked", "expired", "expiring"] {
                            ui.selectable_value(
                                &mut self.license_status,
                                v.into(),
                                if v.is_empty() { "すべて" } else { v },
                            );
                        }
                    });
                ui.checkbox(&mut self.show_deleted, "削除済み");
                if ui.button("検索・更新").clicked() {
                    self.load_licenses();
                }
            });
            ui.horizontal_wrapped(|ui| { if ui.button("ライセンス発行").clicked(){if let (Ok(t),Ok(p),Ok(devices))=(self.license_tenant.parse::<i64>(),self.license_product.parse::<i64>(),self.license_max_devices.parse::<u32>()){self.admin("create_license",json!({"tenant_id":t,"product_id":p,"license_mode":self.license_mode,"label":self.license_label.trim(),"max_devices":devices,"evaluation_days":30,"expires_at":""}),Some("プロダクトキーを発行しますか？"));}else{self.set_status("Tenant ID、Product ID、端末数を確認してください。",true);}}
                egui::ComboBox::from_id_salt("license-action").selected_text(&self.license_operation).show_ui(ui,|ui|{for v in ["停止／再開","端末を強制再認証","有効期限を延長","削除（復元可能）","削除済みを復元"]{ui.selectable_value(&mut self.license_operation,v.into(),v);}});ui.label("延長日数");ui.add(TextEdit::singleline(&mut self.renew_days).desired_width(55.0));if ui.button("選択行に実行").clicked(){self.apply_license_action();} });
        });
        ui.add_space(12.0);
        Self::card(ui, "ライセンス一覧", |ui| {
            egui::Grid::new("license-grid")
                .striped(true)
                .show(ui, |ui| {
                    for h in [
                        "選択",
                        "ID",
                        "Tenant",
                        "契約先",
                        "Product",
                        "製品",
                        "ラベル",
                        "状態",
                        "端末",
                        "期限",
                    ] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for l in &self.licenses {
                        let id = string_at(l, "id");
                        if ui
                            .selectable_label(self.selected_license == id, "選択")
                            .clicked()
                        {
                            self.selected_license = id.clone();
                        }
                        ui.label(&id);
                        ui.label(string_at(l, "tenant_id"));
                        ui.label(string_at(l, "tenant_name"));
                        ui.label(string_at(l, "product_id"));
                        ui.label(string_at(l, "product_name"));
                        ui.label(string_at(l, "label"));
                        ui.label(license_state(l));
                        ui.label(string_at(l, "active_sessions"));
                        ui.label(string_at(l, "expires_at"));
                        ui.end_row();
                    }
                });
        });
    }

    fn apply_license_action(&mut self) {
        let Ok(id) = self.selected_license.parse::<i64>() else {
            self.set_status("操作するライセンスを選択してください。", true);
            return;
        };
        let row = self
            .licenses
            .iter()
            .find(|x| string_at(x, "id") == self.selected_license)
            .cloned()
            .unwrap_or(Value::Null);
        let active = string_at(&row, "active") == "1";
        let deleted = string_at(&row, "deleted_at") != "";
        let action = match self.license_operation.as_str() {
            "停止／再開" => {
                if active {
                    "pause_license"
                } else {
                    "resume_license"
                }
            }
            "端末を強制再認証" => "force_reauth_license",
            "有効期限を延長" => "renew_license",
            "削除（復元可能）" => "delete_license",
            "削除済みを復元" => "restore_license",
            _ => return,
        };
        if action == "restore_license" && !deleted {
            self.set_status("復元する削除済みライセンスを選択してください。", true);
            return;
        }
        let mut fields = json!({"license_id":id});
        if action == "renew_license" {
            let Ok(days) = self.renew_days.parse::<u32>() else {
                self.set_status("延長日数を確認してください。", true);
                return;
            };
            fields["renew_days"] = json!(days);
        }
        if action == "delete_license" {
            fields["reason"] = json!("administrator_request");
        }
        let confirm = match action {
            "pause_license" => "ライセンスを停止し、登録端末セッションも無効化しますか？",
            "resume_license" => "ライセンスを再開しますか？",
            "force_reauth_license" => "登録端末をすべて強制再認証しますか？",
            "renew_license" => "ライセンス期限を延長しますか？",
            "delete_license" => "ライセンスを削除しますか？削除済み一覧から復元できます。",
            _ => "削除済みライセンスを停止状態で復元しますか？",
        };
        self.admin(action, fields, Some(confirm));
    }

    fn audit_ui(&mut self, ui: &mut egui::Ui) {
        Self::card(ui, "監査ログ検索", |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.audit_query)
                        .desired_width(190.0)
                        .hint_text("対象ID・リクエストID"),
                );
                ui.add(
                    TextEdit::singleline(&mut self.audit_event)
                        .desired_width(150.0)
                        .hint_text("イベント名"),
                );
                ui.add(
                    TextEdit::singleline(&mut self.audit_actor)
                        .desired_width(130.0)
                        .hint_text("操作者ID"),
                );
                ui.add(
                    TextEdit::singleline(&mut self.audit_from)
                        .desired_width(105.0)
                        .hint_text("開始 YYYY-MM-DD"),
                );
                ui.add(
                    TextEdit::singleline(&mut self.audit_to)
                        .desired_width(105.0)
                        .hint_text("終了 YYYY-MM-DD"),
                );
                if ui.button("検索").clicked() {
                    self.load_audit();
                }
            });
        });
        ui.add_space(12.0);
        Self::card(ui, "操作記録", |ui| {
            egui::Grid::new("audit-grid").striped(true).show(ui, |ui| {
                for h in [
                    "日時",
                    "操作",
                    "対象種別",
                    "対象ID",
                    "役割",
                    "ノード",
                    "操作者ID",
                ] {
                    ui.strong(h);
                }
                ui.end_row();
                for a in &self.audit_logs {
                    ui.label(string_at(a, "created_at"));
                    ui.label(string_at(a, "event_type"));
                    ui.label(string_at(a, "target_type"));
                    ui.label(string_at(a, "target_id"));
                    ui.label(string_at(a, "role_name"));
                    ui.label(string_at(a, "node_role"));
                    ui.label(string_at(a, "actor_hash"));
                    ui.end_row();
                }
            });
        });
    }

    fn admins_ui(&mut self, ui: &mut egui::Ui) {
        Self::card(ui, "管理者権限", |ui| {
            ui.label("権限変更は毎回Passkey再認証を行い、サーバー側でも権限を検証します。");
            ui.horizontal(|ui| {
                if ui.button("管理者一覧を更新").clicked() { self.load_admins(); }
                egui::ComboBox::from_id_salt("admin-role")
                    .selected_text(&self.admin_role)
                    .show_ui(ui, |ui| {
                        for role in ["viewer", "operator", "security-admin", "ha-admin"] {
                            ui.selectable_value(&mut self.admin_role, role.into(), role);
                        }
                    });
                if ui.button("選択管理者の権限を変更").clicked() {
                    if let Some(admin) = self.admins.iter().find(|x| string_at(x, "id") == self.selected_admin) {
                        let name = string_at(admin, "display_name");
                        let before = string_at(admin, "role_name");
                        if before != self.admin_role {
                            let spec = RequestSpec {
                                action: "set_admin_role".into(), endpoint: Endpoint::Admin,
                                method: "POST".into(), path: ADMIN_API.into(),
                                body: json!({"action":"set_admin_role","principal_id":self.selected_admin.parse::<i64>().unwrap_or_default(),"role_name":self.admin_role}),
                                confirm: Some(format!("{name} の権限を {before} から {} に変更しますか？Passkey再認証が必要です。", self.admin_role)),
                            };
                            self.confirm = Some(spec);
                        }
                    }
                }
            });
        });
        ui.add_space(12.0);
        Self::card(ui, "管理者一覧", |ui| {
            egui::Grid::new("admins-grid").striped(true).show(ui, |ui| {
                for heading in ["選択", "ID", "表示名", "Role", "最終ログイン"] {
                    ui.strong(heading);
                }
                ui.end_row();
                for admin in &self.admins {
                    let id = string_at(admin, "id");
                    if ui
                        .selectable_label(self.selected_admin == id, "選択")
                        .clicked()
                    {
                        self.selected_admin = id.clone();
                    }
                    ui.label(id);
                    ui.label(string_at(admin, "display_name"));
                    ui.label(string_at(admin, "role_name"));
                    ui.label(string_at(admin, "last_login_at"));
                    ui.end_row();
                }
            });
        });
    }

    fn invite_ui(&mut self, ui: &mut egui::Ui) {
        Self::card(ui, "契約者SSO招待", |ui| {
            ui.label("有効なテナントのtenant IDを指定して、本人確認メールを招待先へ送信します。");
            ui.horizontal(|ui|{egui::ComboBox::from_id_salt("invite-tenant").selected_text(if self.invite_tenant.is_empty(){"tenantを選択".into()}else{format!("Tenant ID {}",self.invite_tenant)}).show_ui(ui,|ui|{for t in self.tenants.iter().filter(|x|string_at(x,"status")=="active"){let id=string_at(t,"id");ui.selectable_value(&mut self.invite_tenant,id.clone(),format!("{} · #{} · {}",string_at(t,"name"),id,string_at(t,"slug")));}});ui.text_edit_singleline(&mut self.invite_email);if ui.button("Passkey再認証して招待").clicked(){let Ok(id)=self.invite_tenant.parse::<i64>()else{self.set_status("有効なtenant IDを選択してください。",true);return;};if !self.invite_email.contains('@'){self.set_status("有効なメールアドレスを入力してください。",true);return;}let spec=RequestSpec{action:"create_contractor_sso".into(),endpoint:Endpoint::Admin,method:"POST".into(),path:ADMIN_API.into(),body:json!({"action":"create_contractor_sso","contractor_email":self.invite_email.trim(),"tenant_id":id}),confirm:Some(format!("{} へ、tenant ID {} のSSO招待メールを送信しますか？送信前にPasskey再認証を行います。",self.invite_email.trim(),id))};self.confirm=Some(spec);}});
        });
    }

    fn launch_spec(&mut self, spec: RequestSpec) {
        if spec.action == "set_admin_role" || spec.action == "create_contractor_sso" {
            self.step_up_then(spec);
        } else {
            self.request(spec);
        }
    }
}

fn array_at(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
fn string_at(value: &Value, key: &str) -> String {
    value
        .get(key)
        .map(|x| {
            if x.is_string() {
                x.as_str().unwrap_or_default().to_owned()
            } else if x.is_null() {
                String::new()
            } else {
                x.to_string()
            }
        })
        .unwrap_or_default()
}
fn license_state(value: &Value) -> String {
    if !string_at(value, "deleted_at").is_empty() {
        "削除済み".into()
    } else if !string_at(value, "revoked_at").is_empty() {
        "失効".into()
    } else if string_at(value, "active") == "0" {
        "停止".into()
    } else if !string_at(value, "expires_at").is_empty() {
        string_at(value, "expires_at")
    } else {
        "有効".into()
    }
}

fn do_request(token: &str, spec: &RequestSpec) -> Result<Value, String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())?;
    let mut request = match spec.method.as_str() {
        "GET" => client.get(&spec.path),
        "DELETE" => client.delete(&spec.path),
        _ => client.post(&spec.path),
    };
    request = request
        .header("X-HA-Session", token)
        .header("Accept", "application/json");
    if spec.endpoint == Endpoint::Admin {
        request = request.header("Origin", "https://2415.jp");
    }
    if spec.method != "GET" {
        request = request.json(&spec.body);
    }
    let response = request
        .send()
        .map_err(|e| format!("サーバーへ接続できません: {e}"))?;
    let status = response.status();
    let value: Value = response
        .json()
        .map_err(|e| format!("JSON応答を読めません (HTTP {status}): {e}"))?;
    let ok = match spec.endpoint {
        Endpoint::Admin => value.get("success").and_then(Value::as_bool) == Some(true),
        Endpoint::Tenant => value.get("ok").and_then(Value::as_bool) == Some(true),
        Endpoint::Health => status.is_success(),
    };
    if !status.is_success() || !ok {
        let message = string_at(&value, "message");
        let code = string_at(&value, "error");
        return Err(if !message.is_empty() {
            message
        } else if !code.is_empty() {
            format!("{code} (HTTP {status})")
        } else {
            format!("HTTP {status}")
        });
    }
    Ok(value)
}

fn do_login(step_up: bool) -> Result<String, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("ローカル認証ポートを開けません: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let state: String = (0..32)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    let redirect = format!("http://127.0.0.1:{port}/callback");
    let url = format!(
        "{SSO_START}{}&desktop_redirect={}&desktop_state={state}",
        if step_up { "&step_up=1" } else { "" },
        urlencoding::encode(&redirect)
    );
    open::that(&url).map_err(|e| format!("既定のブラウザーを開けません: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(300);
    while Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
                if let Some(result) = handle_callback(&mut stream, port, &state)? {
                    return Ok(result);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(format!("SSOコールバックの受信に失敗: {e}")),
        }
    }
    Err("SSO認証がタイムアウトしました。ログインをやり直してください。".into())
}

fn handle_callback(
    stream: &mut TcpStream,
    port: u16,
    state: &str,
) -> Result<Option<String>, String> {
    let mut bytes = Vec::with_capacity(4096);
    let mut buf = [0u8; 2048];
    let mut header_end = None;
    while bytes.len() < 32768 && header_end.is_none() {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.to_string()),
        };
        if n == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&buf[..n]);
        header_end = find_header_end(&bytes);
    }
    let Some(end) = header_end else {
        write_http(stream, 400, "text/plain", "Bad Request", "");
        return Ok(None);
    };
    let header = String::from_utf8_lossy(&bytes[..end]);
    let mut lines = header.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut request = first.split_whitespace();
    let method = request.next().unwrap_or("");
    let path = request.next().unwrap_or("");
    let headers: Vec<(&str, &str)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| *v)
        .unwrap_or("");
    if host != format!("127.0.0.1:{port}") {
        write_http(stream, 403, "text/plain", "Forbidden", "");
        return Ok(None);
    }
    if method == "GET" && path == "/callback" {
        let nonce: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(24)
            .map(char::from)
            .collect();
        let body = format!(
            "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><title>TUTI Operations</title><p id=s>SSO応答をアプリへ返しています…</p><script nonce='{nonce}'>const p=new URLSearchParams(location.hash.slice(1)),session=p.get('session'),state=p.get('state');history.replaceState(null,'','/callback');if(!session||!state)document.getElementById('s').textContent='認証応答を取得できません。アプリへ戻ってやり直してください。';else fetch('/complete',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{session,state}})}}).then(r=>document.getElementById('s').textContent=r.ok?'ログインしました。アプリに戻ってください。':'認証応答を確認できません。').catch(()=>document.getElementById('s').textContent='アプリへの接続に失敗しました。');</script>"
        );
        let csp = format!(
            "Content-Security-Policy: default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n"
        );
        write_http(stream, 200, "text/html; charset=utf-8", &body, &csp);
        return Ok(None);
    }
    if method != "POST" || path != "/complete" {
        write_http(stream, 404, "text/plain", "Not Found", "");
        return Ok(None);
    }
    let expected_origin = format!("http://127.0.0.1:{port}");
    if headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
        .map(|(_, v)| *v)
        != Some(expected_origin.as_str())
    {
        write_http(stream, 403, "text/plain", "Forbidden", "");
        return Ok(None);
    }
    let len = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    if len == 0 || len > 16384 {
        write_http(stream, 413, "text/plain", "Too Large", "");
        return Ok(None);
    }
    let body_start = end + 4;
    while bytes.len() < body_start + len {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e.to_string()),
        };
        if n == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&buf[..n]);
    }
    let parsed: Value = serde_json::from_slice(&bytes[body_start..body_start + len])
        .map_err(|_| "SSO応答形式が不正です。".to_string())?;
    let token = string_at(&parsed, "session");
    let got_state = string_at(&parsed, "state");
    if token.len() < 40
        || token.len() > 8192
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        write_http(stream, 400, "text/plain", "Invalid response", "");
        return Ok(None);
    }
    if !constant_time_eq(got_state.as_bytes(), state.as_bytes()) {
        write_http(stream, 400, "text/plain", "Invalid state", "");
        return Ok(None);
    }
    write_http(stream, 200, "application/json", "{\"ok\":true}", "");
    Ok(Some(token))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut x = 0u8;
    for (i, j) in a.iter().zip(b) {
        x |= i ^ j;
    }
    x == 0
}
fn write_http(stream: &mut TcpStream, status: u16, content_type: &str, body: &str, extra: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n{extra}\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}
