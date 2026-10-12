//! Native macOS interface written entirely in Rust. AppKit supplies controls,
//! panels and the menu bar; all relay networking is implemented by the Rust
//! controller. See `ui/appkit.rs` for the isolated Objective-C ABI adapter.
#![allow(unsafe_op_in_unsafe_fn)]

mod appkit;
use crate::controller::{Controller, Status};
use crate::model::{Configuration, LogLevel, Server, TransferScope, Transport};
use anyhow::{Context, Result, bail};
use appkit::*;
use std::cell::RefCell;
use std::ffi::c_void;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

const APP_NAME: &str = "Network Relay RS";
const POWER: isize = 1;
const SAVE: isize = 2;
const SERVER: isize = 3;
const ADD: isize = 4;
const REMOVE: isize = 5;
const TRANSPORT: isize = 6;
const LEVEL: isize = 7;
const COPY_ADDRESS: isize = 8;
const PAGE: isize = 9;
const COPY_LOG: isize = 10;
const SAVE_LOG: isize = 11;
const FOLLOW: isize = 12;
const LATEST: isize = 13;
const OPEN_MAIN: isize = 14;
const QUIT: isize = 15;
const ERASE: isize = 16;
const STATUS_SERVER: isize = 17;
const SHOW_POPOVER: isize = 18;
const IMPORT: isize = 19;
const EXPORT: isize = 20;
const MORE: isize = 21;

thread_local! { static APPLICATION: RefCell<Option<App>> = const { RefCell::new(None) }; }
static TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);
unsafe extern "C" {
    fn signal(number: i32, handler: usize) -> usize;
}
unsafe extern "C" fn request_signal_termination(_: i32) {
    TERMINATION_REQUESTED.store(true, Ordering::Relaxed);
}

struct Editor {
    names: Id,
    name: Id,
    domain: Id,
    ip: Id,
    username: Id,
    password: Id,
    transport: Id,
    listen: Id,
    port: Id,
    launch: Id,
    lan_warning: Id,
    message: Id,
}
struct StatusViews {
    title: Id,
    detail: Id,
    power: Id,
    ring: Id,
    ring_layer: Id,
    server: Id,
    address: Id,
}
struct LogViews {
    text: Id,
    level: Id,
    follow: Id,
    count: Id,
}
struct App {
    controller: Controller,
    draft: Configuration,
    editing: Option<Uuid>,
    select_after_save: Option<Uuid>,
    imported_log_level: bool,
    application: Id,
    delegate: Id,
    window: Id,
    pages: [Id; 3],
    page_title: Id,
    page_detail: Id,
    status_item: Id,
    popover: Id,
    timer: Id,
    main_status: StatusViews,
    menu_status: StatusViews,
    editor: Editor,
    logs: LogViews,
    follow_latest: bool,
    last_log: String,
    last_status: String,
}

/// Run AppKit on the calling (main) thread. The GUI never uses a socket or TLS
/// API: it dispatches user actions to `Controller` and polls its event queue.
pub fn run(controller: Controller) -> Result<()> {
    #[cfg(target_os = "macos")]
    if !cfg!(target_arch = "aarch64") {
        bail!("The native application currently supports Apple silicon only.");
    }
    unsafe {
        let pool = new("NSAutoreleasePool");
        let app = App::new(controller)?;
        signal(15, request_signal_termination as *const () as usize);
        APPLICATION.with(|slot| *slot.borrow_mut() = Some(app));
        with_app(|app| {
            app.show_main();
            app.controller.launched();
            app.refresh();
        });
        let nsapp: Id = send0(class("NSApplication"), "sharedApplication");
        send0::<()>(nsapp, "run");
        APPLICATION.with(|slot| {
            if let Some(mut app) = slot.borrow_mut().take() {
                app.controller.stop();
            }
        });
        send0::<()>(pool, "drain");
    }
    Ok(())
}

fn with_app(action: impl FnOnce(&mut App)) {
    // Cocoa modal panels may run the timer reentrantly. Skip that poll while a
    // user action owns the state; the Rust network runtime continues independently.
    APPLICATION.with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut()
            && let Some(app) = slot.as_mut()
        {
            action(app);
        }
    });
}
unsafe extern "C" fn perform_action(_: Id, _: Id, sender: Id) {
    let pool = new("NSAutoreleasePool");
    let tag: isize = send0(sender, "tag");
    with_app(|app| {
        if let Err(error) = app.action(tag, sender) {
            app.message(&error.to_string());
        }
        app.refresh();
    });
    send0::<()>(pool, "drain");
}
unsafe extern "C" fn tick(_: Id, _: Id, _: Id) {
    let pool = new("NSAutoreleasePool");
    with_app(|app| {
        if TERMINATION_REQUESTED.swap(false, Ordering::Relaxed) {
            app.controller.stop();
            send1::<_, ()>(app.application, "terminate:", NIL);
            return;
        }
        app.controller.poll();
        app.refresh();
    });
    send0::<()>(pool, "drain");
}
unsafe extern "C" fn window_closed(_: Id, _: Id, _: Id) {
    with_app(|app| {
        send1::<_, bool>(app.application, "setActivationPolicy:", 1_isize);
    });
}
unsafe extern "C" fn keep_running(_: Id, _: Id, _: Id) -> bool {
    false
}
unsafe extern "C" fn terminating(_: Id, _: Id, _: Id) {
    with_app(|app| {
        app.controller.stop();
        send0::<()>(app.timer, "invalidate");
    });
}

impl App {
    unsafe fn new(controller: Controller) -> Result<Self> {
        let application: Id = send0(class("NSApplication"), "sharedApplication");
        let delegate = make_delegate(&[
            ("performAction:", perform_action as *const c_void, "v@:@"),
            ("pollController:", tick as *const c_void, "v@:@"),
            ("windowWillClose:", window_closed as *const c_void, "v@:@"),
            ("applicationShouldTerminateAfterLastWindowClosed:", keep_running as *const c_void, "B@:@"),
            ("applicationWillTerminate:", terminating as *const c_void, "v@:@"),
        ]);
        send1::<_, ()>(application, "setDelegate:", delegate);
        send1::<_, bool>(application, "setActivationPolicy:", 0_isize);
        // Window state is deliberately not persisted by AppKit.
        let allocated: Id = send0(class("NSWindow"), "alloc");
        let window: Id = send4(
            allocated,
            "initWithContentRect:styleMask:backing:defer:",
            rect(0., 0., 940., 660.),
            15_usize,
            2_usize,
            false,
        );
        send1::<_, ()>(window, "setTitle:", string(APP_NAME));
        send1::<_, ()>(window, "setReleasedWhenClosed:", false);
        send1::<_, ()>(window, "setRestorable:", false);
        send1::<_, ()>(window, "setDelegate:", delegate);
        send1::<_, ()>(window, "setContentMinSize:", Size { width: 820., height: 600. });
        send0::<()>(window, "center");
        let main_view: Id = send0(window, "contentView");
        let left = card(main_view, rect(0., 0., 300., 660.));
        autoresize(left, 16);
        let main_status = status_views(left, delegate, false);
        let page_title = label(main_view, "Settings", rect(324., 612., 220., 24.), 17., true);
        let page_detail = label(main_view, "Servers and your local proxy", rect(324., 592., 220., 18.), 11., false);
        autoresize(page_title, 8);
        autoresize(page_detail, 8);
        let segmented = new("NSSegmentedControl");
        frame(segmented, rect(686., 603., 230., 28.));
        send1::<_, ()>(segmented, "setSegmentCount:", 3_isize);
        for (index, title) in ["Settings", "Log", "About"].iter().enumerate() {
            send2::<_, _, ()>(segmented, "setLabel:forSegment:", string(title), index as isize);
        }
        send1::<_, ()>(segmented, "setSelectedSegment:", 0_isize);
        action(segmented, delegate, PAGE);
        autoresize(segmented, 9);
        add(main_view, segmented);
        let pages =
            [view(rect(300., 0., 640., 580.)), view(rect(300., 0., 640., 580.)), view(rect(300., 0., 640., 580.))];
        for page in pages {
            autoresize(page, 18);
            add(main_view, page);
        }
        hidden(pages[1], true);
        hidden(pages[2], true);
        let editor = settings_view(pages[0], delegate);
        let logs = log_view(pages[1], delegate);
        about_view(pages[2]);
        let status_bar: Id = send0(class("NSStatusBar"), "systemStatusBar");
        let status_item: Id = send1(status_bar, "statusItemWithLength:", -1.0_f64);
        send0::<Id>(status_item, "retain");
        let status_button: Id = send0(status_item, "button");
        action(status_button, delegate, SHOW_POPOVER);
        let popover = new("NSPopover");
        send1::<_, ()>(popover, "setBehavior:", 1_isize);
        send1::<_, ()>(popover, "setContentSize:", Size { width: 320., height: 410. });
        let vc = new("NSViewController");
        let menu_view = view(rect(0., 0., 320., 410.));
        let menu_status = status_views(menu_view, delegate, true);
        send1::<_, ()>(vc, "setView:", menu_view);
        send1::<_, ()>(popover, "setContentViewController:", vc);
        send0::<()>(vc, "release");
        let timer = scheduled_timer(delegate);
        let mut draft = controller.config.clone();
        if draft.servers.is_empty() {
            draft.servers.push(Server::default());
        }
        let editing = draft.selected_server().map(|server| server.id);
        let mut result = Self {
            controller,
            draft,
            editing,
            select_after_save: None,
            imported_log_level: false,
            application,
            delegate,
            window,
            pages,
            page_title,
            page_detail,
            status_item,
            popover,
            timer,
            main_status,
            menu_status,
            editor,
            logs,
            follow_latest: true,
            last_log: String::new(),
            last_status: String::new(),
        };
        result.show_editor();
        result.install_main_menu();
        Ok(result)
    }
    unsafe fn show_main(&mut self) {
        send1::<_, bool>(self.application, "setActivationPolicy:", 0_isize);
        send1::<_, ()>(self.window, "makeKeyAndOrderFront:", NIL);
        send1::<_, ()>(self.application, "activateIgnoringOtherApps:", true);
    }
    unsafe fn message(&self, message: &str) {
        set_text(self.editor.message, message);
    }
    unsafe fn read_editor(&mut self) -> Result<()> {
        if let Some(server) = self.draft.servers.iter_mut().find(|server| Some(server.id) == self.editing) {
            server.name = text(self.editor.name);
            server.domain = text(self.editor.domain);
            server.server_ip = text(self.editor.ip);
            server.username = text(self.editor.username);
            server.password = text(self.editor.password);
            server.transport = transport_at(index(self.editor.transport));
        }
        self.draft.listen_address = text(self.editor.listen);
        self.draft.port = text(self.editor.port).trim().parse().context("The port must be between 1 and 65535.")?;
        if self.draft.port == 0 {
            bail!("The port must be between 1 and 65535.");
        }
        self.draft.connect_on_launch = send0::<isize>(self.editor.launch, "state") != 0;
        if !self.imported_log_level {
            self.draft.log_level = self.controller.config.log_level;
        }
        Ok(())
    }
    unsafe fn read_server_fields(&mut self) {
        if let Some(server) = self.draft.servers.iter_mut().find(|server| Some(server.id) == self.editing) {
            server.name = text(self.editor.name);
            server.domain = text(self.editor.domain);
            server.server_ip = text(self.editor.ip);
            server.username = text(self.editor.username);
            server.password = text(self.editor.password);
        }
    }
    unsafe fn show_editor(&mut self) {
        self.show_server_editor();
        set_text(self.editor.listen, &self.draft.listen_address);
        set_text(self.editor.port, &self.draft.port.to_string());
        send1::<_, ()>(self.editor.launch, "setState:", self.draft.connect_on_launch as isize);
    }
    unsafe fn show_server_editor(&mut self) {
        let editing =
            self.editing.and_then(|id| self.draft.servers.iter().position(|server| server.id == id)).unwrap_or(0);
        popup_items(self.editor.names, &self.draft.servers.iter().map(server_title).collect::<Vec<_>>(), editing);
        let blank = Server::default();
        let server = self.draft.servers.get(editing).unwrap_or(&blank);
        set_text(self.editor.name, &server.name);
        set_text(self.editor.domain, &server.domain);
        set_text(self.editor.ip, &server.server_ip);
        set_text(self.editor.username, &server.username);
        set_text(self.editor.password, &server.password);
        popup_items(
            self.editor.transport,
            &transports().iter().map(|mode| mode.title().to_string()).collect::<Vec<_>>(),
            transport_index(server.transport),
        );
        for field in [
            self.editor.name,
            self.editor.domain,
            self.editor.ip,
            self.editor.username,
            self.editor.password,
            self.editor.transport,
        ] {
            enabled(field, !self.draft.servers.is_empty());
        }
    }
    unsafe fn action(&mut self, tag: isize, sender: Id) -> Result<()> {
        match tag {
            POWER => {
                if active(&self.controller.status) {
                    self.controller.disconnect();
                } else {
                    self.controller.connect();
                }
            }
            SAVE => {
                self.read_editor()?;
                let saved = prepare_save(&self.draft, &self.controller.config, self.select_after_save);
                self.controller.apply(saved)?;
                self.draft = self.controller.config.clone();
                if !self.draft.servers.iter().any(|server| Some(server.id) == self.editing) {
                    self.editing = self.draft.selected_server_id;
                }
                self.select_after_save = None;
                self.imported_log_level = false;
                self.show_editor();
                self.message("Saved");
            }
            SERVER => {
                self.read_server_fields();
                let id = self.draft.servers.get(index(sender)).map(|server| server.id);
                self.editing = id;
                if let Some(id) = id {
                    if self.controller.config.servers.iter().any(|server| server.id == id) {
                        let mut config = self.controller.config.clone();
                        config.selected_server_id = Some(id);
                        self.controller.apply(config)?;
                        self.select_after_save = None;
                        self.message("Server applied. Other changes still need Save.");
                    } else {
                        self.select_after_save = Some(id);
                        self.message("Server selected; save this new server before connecting.");
                    }
                }
                self.show_server_editor();
            }
            STATUS_SERVER => {
                let id = self.controller.config.servers.get(index(sender)).map(|server| server.id);
                if let Some(id) = id {
                    self.read_server_fields();
                    let mut config = self.controller.config.clone();
                    config.selected_server_id = Some(id);
                    self.controller.apply(config)?;
                    self.editing = Some(id);
                    self.select_after_save = None;
                    self.show_server_editor();
                }
            }
            TRANSPORT => {
                let mode = transport_at(index(sender));
                if let Some(server) = self.draft.servers.iter_mut().find(|server| Some(server.id) == self.editing) {
                    server.transport = mode;
                }
                if let Some(id) = self.editing {
                    let mut config = self.controller.config.clone();
                    if let Some(server) = config.servers.iter_mut().find(|server| server.id == id) {
                        server.transport = mode;
                        self.controller.apply(config)?;
                        self.message("Transport applied. Other changes still need Save.");
                    } else {
                        self.message("Transport selected; save this new server before connecting.");
                    }
                }
            }
            ADD => {
                self.read_server_fields();
                let server = Server::default();
                self.editing = Some(server.id);
                self.draft.servers.push(server);
                self.show_server_editor();
            }
            REMOVE => {
                if let Some(at) = self.draft.servers.iter().position(|server| Some(server.id) == self.editing) {
                    self.draft.servers.remove(at);
                    self.editing = self
                        .draft
                        .servers
                        .get(at.min(self.draft.servers.len().saturating_sub(1)))
                        .map(|server| server.id);
                    self.show_server_editor();
                }
            }
            LEVEL => self.controller.set_log_level(log_level_at(index(sender)))?,
            COPY_ADDRESS => copy_text(&self.controller.config.proxy_address()),
            PAGE => {
                let page = send0::<isize>(sender, "selectedSegment").clamp(0, 2) as usize;
                for (index, view) in self.pages.iter().enumerate() {
                    hidden(*view, index != page);
                }
                set_text(self.page_title, ["Settings", "Log", "About"][page]);
                set_text(
                    self.page_detail,
                    [
                        "Servers and your local proxy",
                        "Connection activity and diagnostics",
                        "Application and build information",
                    ][page],
                );
            }
            COPY_LOG => copy_text(
                &self.controller.logs().iter().map(|entry| entry.text.as_str()).collect::<Vec<_>>().join("\n"),
            ),
            SAVE_LOG => {
                if let Some(path) =
                    choose_file(true, "Network Relay RS.log", "Save every retained log line, including hidden levels.")
                {
                    private_write(
                        &path,
                        self.controller
                            .logs()
                            .iter()
                            .map(|entry| entry.text.as_str())
                            .collect::<Vec<_>>()
                            .join("\n")
                            .as_bytes(),
                    )?;
                }
            }
            FOLLOW => self.follow_latest = send0::<isize>(sender, "state") != 0,
            LATEST => {
                self.follow_latest = true;
                send1::<_, ()>(self.logs.follow, "setState:", 1_isize);
                self.scroll_latest();
            }
            OPEN_MAIN => self.show_main(),
            QUIT => {
                self.controller.stop();
                send1::<_, ()>(self.application, "terminate:", NIL);
            }
            ERASE => {
                if alert(
                    "Erase all data and quit?",
                    "This deletes only Network Relay RS settings, including accounts and passwords. Network Relay NF and other applications are unaffected.",
                    &["Erase and Quit", "Cancel"],
                ) == 0
                {
                    self.controller.stop();
                    self.controller.erase()?;
                    send1::<_, ()>(self.application, "terminate:", NIL);
                }
            }
            SHOW_POPOVER => {
                if send0::<bool>(self.popover, "isShown") {
                    send1::<_, ()>(self.popover, "performClose:", NIL);
                } else {
                    let button: Id = send0(self.status_item, "button");
                    let bounds: Rect = send0(button, "bounds");
                    send3::<_, _, _, ()>(
                        self.popover,
                        "showRelativeToRect:ofView:preferredEdge:",
                        bounds,
                        button,
                        1_usize,
                    );
                }
            }
            IMPORT => {
                if let Some(scope) = scope_at(index(sender)) {
                    self.import_settings(scope)?;
                }
            }
            EXPORT => {
                if let Some(scope) = scope_at(index(sender)) {
                    self.export_settings(scope)?;
                }
            }
            MORE => match index(sender) {
                1 => self.action(QUIT, sender)?,
                2 => self.action(ERASE, sender)?,
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }
    unsafe fn import_settings(&mut self, scope: TransferScope) -> Result<()> {
        if scope == TransferScope::Servers {
            self.read_server_fields();
        } else {
            self.read_editor()?;
        }
        let Some(path) = choose_file(false, "", "Choose Network Relay RS/NF exported settings or a relay client TOML.")
        else {
            return Ok(());
        };
        let text = fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
        let imported = Configuration::importing(&text, scope, &self.draft)?;
        if scope == TransferScope::Application {
            self.draft.listen_address = imported.listen_address;
            self.draft.port = imported.port;
            self.draft.connect_on_launch = imported.connect_on_launch;
            self.draft.log_level = imported.log_level;
            self.imported_log_level = true;
        } else {
            let existing = self.draft.servers.iter().any(|server| !blank_server(server));
            let choice = if existing {
                alert(
                    "Import servers?",
                    "Merge updates matching servers and keeps application settings. Replace follows the imported selection. Missing passwords are retained. Nothing applies until Save.",
                    &["Merge", "Replace", "Cancel"],
                )
            } else {
                1
            };
            if choice == 2 {
                return Ok(());
            }
            let replace = choice == 1;
            let old_ids = self.draft.servers.iter().map(|server| server.id).collect::<Vec<_>>();
            self.draft.import_servers(&imported, replace);
            if replace {
                self.editing = self.draft.selected_server().map(|server| server.id);
                self.select_after_save = self.editing;
            } else if let Some(server) = self.draft.servers.iter().find(|server| !old_ids.contains(&server.id)) {
                self.editing = Some(server.id);
            }
            if scope == TransferScope::All && replace {
                self.draft.listen_address = imported.listen_address;
                self.draft.port = imported.port;
                self.draft.connect_on_launch = imported.connect_on_launch;
                self.draft.log_level = imported.log_level;
                self.imported_log_level = true;
            }
        }
        if scope == TransferScope::Servers {
            self.show_server_editor();
        } else {
            self.show_editor();
        }
        self.message("Imported. Check the settings, then click Save.");
        Ok(())
    }
    unsafe fn export_settings(&mut self, scope: TransferScope) -> Result<()> {
        if scope == TransferScope::Servers {
            self.read_server_fields();
        } else {
            self.read_editor()?;
        }
        let saved = &self.controller.config;
        let server_changes = self.draft.servers != saved.servers
            || self.select_after_save.is_some_and(|id| Some(id) != saved.selected_server_id);
        let app_changes = self.draft.listen_address != saved.listen_address
            || self.draft.port != saved.port
            || self.draft.connect_on_launch != saved.connect_on_launch
            || (self.imported_log_level && self.draft.log_level != saved.log_level);
        if (scope != TransferScope::Application && server_changes) || (scope != TransferScope::Servers && app_changes) {
            bail!("Save changes in the chosen section before exporting.");
        }
        if scope != TransferScope::Application && saved.servers.is_empty() {
            bail!("There are no saved servers to export.");
        }
        let mut passwords = false;
        if scope != TransferScope::Application && saved.servers.iter().any(|server| !server.password.is_empty()) {
            match alert(
                "Export the passwords too?",
                "Anyone with an exported password can use the account. Keep files containing passwords private.",
                &["Leave Out Passwords", "Include Passwords", "Cancel"],
            ) {
                0 => {}
                1 => passwords = true,
                _ => return Ok(()),
            }
        }
        let name = match scope {
            TransferScope::All => "Network Relay RS Settings.toml",
            TransferScope::Servers => "Network Relay RS Servers.toml",
            TransferScope::Application => "Network Relay RS Application Settings.toml",
        };
        if let Some(path) = choose_file(true, name, "Export saved settings.") {
            private_write(&path, saved.exported_toml(passwords, scope).as_bytes())?;
            self.message("Exported");
        }
        Ok(())
    }
    unsafe fn refresh(&mut self) {
        let listen = text(self.editor.listen);
        let local = listen.trim() == "::1" || listen.trim().starts_with("127.");
        set_text(
            self.editor.lan_warning,
            if local { "" } else { "Any device on the same network can use this proxy." },
        );
        let (title, detail, symbol, color) = match &self.controller.status {
            Status::Stopped => ("Not Connected", "", "shield.slash", "secondaryLabelColor"),
            Status::Connecting => ("Connecting…", "", "shield.lefthalf.filled", "systemBlueColor"),
            Status::Connected => ("Connected", "", "checkmark.shield.fill", "systemGreenColor"),
            Status::Reconnecting => (
                "Connection Lost, Reconnecting…",
                self.controller.detail.as_str(),
                "shield.lefthalf.filled",
                "systemOrangeColor",
            ),
            Status::Failed(why) => ("Connection Failed", why.as_str(), "exclamationmark.shield", "systemRedColor"),
        };
        let workspace: Id = send0(class("NSWorkspace"), "sharedWorkspace");
        let reduced = send0::<bool>(workspace, "accessibilityDisplayShouldReduceMotion");
        let status_key = format!("{title}\n{detail}\n{:?}\n{reduced}", self.controller.config.selected_server_id);
        if status_key != self.last_status {
            let busy = matches!(self.controller.status, Status::Connecting | Status::Reconnecting);
            for status in [&self.main_status, &self.menu_status] {
                set_text(status.title, title);
                set_text(status.detail, detail);
                send1::<_, ()>(status.title, "setTextColor:", appkit::color(color));
                send1::<_, ()>(status.power, "setContentTintColor:", appkit::color(color));
                hidden(status.ring, !busy);
                let tint: Id = appkit::color(color);
                let cgcolor: Id = send0(tint, "CGColor");
                send1::<_, ()>(status.ring_layer, "setStrokeColor:", cgcolor);
                if busy {
                    animate_ring(status.ring_layer, reduced);
                } else {
                    send0::<()>(status.ring_layer, "removeAllAnimations");
                }
                send1::<_, ()>(
                    status.power,
                    "setToolTip:",
                    string(if active(&self.controller.status) { "Disconnect" } else { "Connect" }),
                );
            }
            let image: Id = send2(
                class("NSImage"),
                "imageWithSystemSymbolName:accessibilityDescription:",
                string(symbol),
                string(title),
            );
            let button: Id = send0(self.status_item, "button");
            send1::<_, ()>(button, "setImage:", image);
            self.last_status = status_key;
        }
        let titles = self.controller.config.servers.iter().map(server_title).collect::<Vec<_>>();
        let empty_titles = vec!["No saved server".into()];
        let selected = self
            .controller
            .config
            .servers
            .iter()
            .position(|server| Some(server.id) == self.controller.config.selected_server_id)
            .unwrap_or(0);
        for status in [&self.main_status, &self.menu_status] {
            let selected_title: Id = send0(status.server, "titleOfSelectedItem");
            let desired = titles.get(selected).cloned().unwrap_or_else(|| "No saved server".into());
            if send0::<isize>(status.server, "numberOfItems") as usize != titles.len().max(1)
                || ns_text(selected_title) != desired
            {
                popup_items(status.server, if titles.is_empty() { &empty_titles } else { &titles }, selected);
            }
            enabled(status.server, !titles.is_empty());
            set_text(status.address, &self.controller.config.proxy_address());
        }
        let all = self.controller.logs();
        let shown = all.iter().filter(|entry| self.controller.config.log_level.shows(&entry.text)).collect::<Vec<_>>();
        let output = shown.iter().map(|entry| entry.text.as_str()).collect::<Vec<_>>().join("\n");
        if output != self.last_log {
            send1::<_, ()>(self.logs.text, "setString:", string(&output));
            let mut start = 0_usize;
            for entry in &shown {
                let count = entry.text.encode_utf16().count();
                let color = match entry.level {
                    0 | 1 => "systemOrangeColor",
                    3 | 4 => "secondaryLabelColor",
                    _ => "labelColor",
                };
                send2::<_, _, ()>(
                    self.logs.text,
                    "setTextColor:range:",
                    appkit::color(color),
                    Range { location: start, length: count },
                );
                start += count + 1;
            }
            self.last_log = output;
            if self.follow_latest {
                self.scroll_latest();
            }
        }
        set_text(
            self.logs.count,
            &format!(
                "Showing {} of {} retained lines. Copy All and Save include every retained level. Up to 5,000 recent lines; kept in memory.",
                shown.len(),
                all.len()
            ),
        );
        send1::<_, ()>(
            self.logs.level,
            "selectItemAtIndex:",
            log_level_index(self.controller.config.log_level) as isize,
        );
    }
    unsafe fn scroll_latest(&self) {
        send1::<_, ()>(
            self.logs.text,
            "scrollRangeToVisible:",
            Range { location: self.last_log.encode_utf16().count(), length: 0 },
        );
    }
    unsafe fn install_main_menu(&self) {
        let main = new("NSMenu");
        let item = new("NSMenuItem");
        let menu = new("NSMenu");
        send1::<_, ()>(item, "setTitle:", string(APP_NAME));
        send1::<_, ()>(
            menu,
            "addItem:",
            responder_menu_item("About Network Relay RS", "orderFrontStandardAboutPanel:", ""),
        );
        send1::<_, ()>(menu, "addItem:", send0::<Id>(class("NSMenuItem"), "separatorItem"));
        let open = menu_item("Open Main Window", "o", self.delegate, OPEN_MAIN);
        send1::<_, ()>(menu, "addItem:", open);
        let quit = menu_item("Quit Network Relay RS", "q", self.delegate, QUIT);
        send1::<_, ()>(menu, "addItem:", quit);
        send1::<_, ()>(item, "setSubmenu:", menu);
        send1::<_, ()>(main, "addItem:", item);
        add_menu(main, "File", &[("Close Window", "performClose:", "w")]);
        add_menu(
            main,
            "Edit",
            &[
                ("Cut", "cut:", "x"),
                ("Copy", "copy:", "c"),
                ("Paste", "paste:", "v"),
                ("Select All", "selectAll:", "a"),
            ],
        );
        let windows = add_menu(
            main,
            "Window",
            &[("Minimize", "performMiniaturize:", "m"), ("Bring All to Front", "arrangeInFront:", "")],
        );
        send1::<_, ()>(self.application, "setWindowsMenu:", windows);
        send1::<_, ()>(self.application, "setMainMenu:", main);
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Range {
    location: usize,
    length: usize,
}
unsafe fn scheduled_timer(delegate: Id) -> Id {
    // objc_msgSend with this exact five-argument selector. Keeping this separate
    // avoids accidentally omitting the BOOL `repeats` argument.
    #[cfg_attr(target_os = "macos", link(name = "objc"))]
    unsafe extern "C" {
        fn objc_msgSend();
    }
    let call: unsafe extern "C" fn(Id, Id, f64, Id, Id, Id, bool) -> Id =
        std::mem::transmute(objc_msgSend as *const ());
    let timer = call(
        class("NSTimer"),
        selector("scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:"),
        0.15,
        delegate,
        selector("pollController:"),
        NIL,
        true,
    );
    send0::<Id>(timer, "retain");
    timer
}
unsafe fn menu_item(title: &str, key: &str, delegate: Id, tag: isize) -> Id {
    let allocated: Id = send0(class("NSMenuItem"), "alloc");
    let result: Id =
        send3(allocated, "initWithTitle:action:keyEquivalent:", string(title), selector("performAction:"), string(key));
    action(result, delegate, tag);
    result
}
unsafe fn responder_menu_item(title: &str, action: &str, key: &str) -> Id {
    let allocated: Id = send0(class("NSMenuItem"), "alloc");
    let item: Id =
        send3(allocated, "initWithTitle:action:keyEquivalent:", string(title), selector(action), string(key));
    // A nil target deliberately routes editing/window commands through the
    // first-responder chain, including NSSecureTextField's field editor.
    send1::<_, ()>(item, "setTarget:", NIL);
    item
}
unsafe fn add_menu(main: Id, title: &str, items: &[(&str, &str, &str)]) -> Id {
    let top = new("NSMenuItem");
    send1::<_, ()>(top, "setTitle:", string(title));
    let menu = new("NSMenu");
    send1::<_, ()>(menu, "setTitle:", string(title));
    for (title, action, key) in items {
        send1::<_, ()>(menu, "addItem:", responder_menu_item(title, action, key));
    }
    send1::<_, ()>(top, "setSubmenu:", menu);
    send1::<_, ()>(main, "addItem:", top);
    menu
}
unsafe fn card(parent: Id, position: Rect) -> Id {
    let box_view = new("NSBox");
    frame(box_view, position);
    send1::<_, ()>(box_view, "setBoxType:", 4_usize);
    send1::<_, ()>(box_view, "setBorderType:", 0_usize);
    send1::<_, ()>(box_view, "setFillColor:", color("controlBackgroundColor"));
    send1::<_, ()>(box_view, "setCornerRadius:", 16.0_f64);
    add(parent, box_view);
    box_view
}
unsafe fn brand(parent: Id, x: f64, y: f64, size: f64) -> Id {
    let mark = view(rect(x, y, size, size));
    send1::<_, ()>(mark, "setWantsLayer:", true);
    let backing: Id = send0(mark, "layer");
    let gradient: Id = send0(class("CAGradientLayer"), "layer");
    frame(gradient, rect(0., 0., size, size));
    send1::<_, ()>(gradient, "setCornerRadius:", size * 0.28);
    send1::<_, ()>(gradient, "setStartPoint:", Point { x: 0., y: 1. });
    send1::<_, ()>(gradient, "setEndPoint:", Point { x: 1., y: 0. });
    let blue: Id = send4(class("NSColor"), "colorWithSRGBRed:green:blue:alpha:", 0.12_f64, 0.48_f64, 0.86_f64, 1_f64);
    let aqua: Id = send4(class("NSColor"), "colorWithSRGBRed:green:blue:alpha:", 0.10_f64, 0.67_f64, 0.73_f64, 1_f64);
    let colors: [Id; 2] = [send0(blue, "CGColor"), send0(aqua, "CGColor")];
    let array: Id = send2(class("NSArray"), "arrayWithObjects:count:", colors.as_ptr(), 2_usize);
    send1::<_, ()>(gradient, "setColors:", array);
    send1::<_, ()>(backing, "addSublayer:", gradient);
    let glyph = label(mark, "N", rect(0., size * 0.12, size, size * 0.78), size * 0.55, true);
    send1::<_, ()>(glyph, "setAlignment:", 1_usize);
    send1::<_, ()>(glyph, "setTextColor:", color("whiteColor"));
    add(parent, mark);
    mark
}
unsafe fn status_views(parent: Id, delegate: Id, menu: bool) -> StatusViews {
    let height = if menu { 410. } else { 660. };
    let width = if menu { 320. } else { 300. };
    let inner = width - 40.;
    let brand = brand(parent, 20., height - 60., 36.);
    let brand_title = label(parent, APP_NAME, rect(62., height - 52., 230., 26.), 16., true);
    autoresize(brand, 8);
    autoresize(brand_title, 8);
    let power_y = if menu { 226. } else { 346. };
    let power_x = (width - 110.) / 2.;
    let (ring, ring_layer) = ring_layer(parent, rect(power_x - 17., power_y - 17., 144., 144.));
    let power = button(parent, "⏻", rect(power_x, power_y, 110., 110.), delegate, POWER);
    send1::<_, ()>(power, "setBezelStyle:", 7_usize);
    send1::<_, ()>(power, "setFont:", send1::<_, Id>(class("NSFont"), "systemFontOfSize:", 36_f64));
    let image: Id = send2(
        class("NSImage"),
        "imageWithSystemSymbolName:accessibilityDescription:",
        string("power"),
        string("Connect or disconnect"),
    );
    if !image.is_null() {
        let configuration: Id = send3(
            class("NSImageSymbolConfiguration"),
            "configurationWithPointSize:weight:scale:",
            36_f64,
            0.3_f64,
            3_isize,
        );
        let configured: Id = send1(image, "imageWithSymbolConfiguration:", configuration);
        send1::<_, ()>(power, "setImage:", if configured.is_null() { image } else { configured });
        send1::<_, ()>(power, "setImagePosition:", 1_usize);
    }
    let title = label(parent, "Not Connected", rect(20., power_y - 45., inner, 36.), 17., true);
    send1::<_, ()>(title, "setAlignment:", 1_usize);
    let detail = label(parent, "", rect(20., power_y - 84., inner, 40.), 12., false);
    send1::<_, ()>(detail, "setAlignment:", 1_usize);
    send1::<_, ()>(detail, "setMaximumNumberOfLines:", 3_isize);
    if !menu {
        for element in [power, ring, title, detail] {
            autoresize(element, 40);
        }
    }
    let server = popup(parent, rect(20., if menu { 94. } else { 114. }, inner, 28.), delegate, STATUS_SERVER);
    let proxy = card(parent, rect(20., if menu { 46. } else { 40. }, inner, 62.));
    label(proxy, "SOCKS5 proxy", rect(12., 36., 205., 18.), 11., false);
    let address = label(proxy, "127.0.0.1:1080", rect(12., 12., inner - 75., 22.), 13., false);
    button(proxy, "Copy", rect(inner - 64., 12., 54., 25.), delegate, COPY_ADDRESS);
    if menu {
        button(parent, "Open Main Window", rect(15., 10., 230., 28.), delegate, OPEN_MAIN);
        menu_popup(
            parent,
            "•••",
            &["Quit Network Relay RS", "Erase All Data and Quit…"],
            rect(258., 10., 47., 28.),
            delegate,
            MORE,
        );
    }
    StatusViews { title, detail, power, ring, ring_layer, server, address }
}
unsafe fn settings_view(parent: Id, delegate: Id) -> Editor {
    // The settings form scrolls independently of its Save/Import/Export footer,
    // retaining every field at NF's 820×600 minimum window size.
    let scroll = new("NSScrollView");
    frame(scroll, rect(0., 80., 640., 500.));
    autoresize(scroll, 18);
    send1::<_, ()>(scroll, "setHasVerticalScroller:", true);
    send1::<_, ()>(scroll, "setAutohidesScrollers:", true);
    send1::<_, ()>(scroll, "setDrawsBackground:", false);
    let form = view(rect(0., 0., 640., 530.));
    autoresize(form, 2);
    send1::<_, ()>(scroll, "setDocumentView:", form);
    add(parent, scroll);
    let servers = card(form, rect(24., 196., 592., 328.));
    autoresize(servers, 2);
    label(servers, "Servers", rect(18., 289., 330., 24.), 15., true);
    autoresize(button(servers, "+", rect(499., 286., 36., 28.), delegate, ADD), 1);
    autoresize(button(servers, "−", rect(539., 286., 36., 28.), delegate, REMOVE), 1);
    let rows = [
        ("Server", 265.),
        ("Name", 229.),
        ("Domain", 193.),
        ("IP", 157.),
        ("Username", 121.),
        ("Password", 85.),
        ("Transport", 49.),
    ];
    for (name, y) in rows {
        label(servers, name, rect(18., y, 118., 22.), 13., false);
    }
    let names = popup(servers, rect(137., 259., 435., 28.), delegate, SERVER);
    let name = field(servers, "", rect(138., 225., 434., 26.), false);
    let domain = field(servers, "", rect(138., 189., 434., 26.), false);
    let ip = field(servers, "", rect(138., 153., 434., 26.), false);
    let username = field(servers, "", rect(138., 117., 434., 26.), false);
    let password = field(servers, "", rect(138., 81., 434., 26.), true);
    let transport = popup(servers, rect(137., 43., 435., 28.), delegate, TRANSPORT);
    for element in [names, name, domain, ip, username, password, transport] {
        autoresize(element, 2);
    }
    let hint = label(
        servers,
        "Saved server and transport choices apply immediately. Other edits need Save.",
        rect(18., 10., 554., 23.),
        10.,
        false,
    );
    send1::<_, ()>(hint, "setTextColor:", color("secondaryLabelColor"));
    autoresize(hint, 2);
    send1::<_, ()>(domain, "setPlaceholderString:", string("vpn.example.com"));
    send1::<_, ()>(ip, "setPlaceholderString:", string("Optional"));
    send1::<_, ()>(name, "setPlaceholderString:", string("Optional, such as Tokyo"));
    let proxy = card(form, rect(24., 73., 592., 109.));
    autoresize(proxy, 2);
    label(proxy, "SOCKS5 Proxy on This Mac", rect(18., 70., 500., 24.), 15., true);
    label(proxy, "Listen address", rect(18., 35., 112., 23.), 13., false);
    let listen = field(proxy, "127.0.0.1", rect(137., 31., 210., 27.), false);
    autoresize(label(proxy, "Port", rect(368., 35., 55., 23.), 13., false), 1);
    let port = field(proxy, "1080", rect(427., 31., 145., 27.), false);
    autoresize(listen, 2);
    autoresize(port, 1);
    let lan_warning = label(proxy, "", rect(18., 5., 554., 21.), 10., false);
    send1::<_, ()>(lan_warning, "setTextColor:", color("systemOrangeColor"));
    send1::<_, ()>(listen, "setToolTip:", string("A non-loopback IP exposes this unauthenticated proxy to the LAN."));
    let launch = checkbox(form, "Connect when Network Relay RS opens", rect(40., 33., 560., 28.), delegate, 0);
    let message = label(parent, "", rect(24., 55., 592., 23.), 11., false);
    autoresize(message, 2);
    autoresize(
        menu_popup(
            parent,
            "Import…",
            &["Servers…", "Application Settings…", "All Settings…"],
            rect(24., 18., 89., 32.),
            delegate,
            IMPORT,
        ),
        0,
    );
    autoresize(
        menu_popup(
            parent,
            "Export…",
            &["Servers…", "Application Settings…", "All Settings…"],
            rect(122., 18., 89., 32.),
            delegate,
            EXPORT,
        ),
        0,
    );
    let save = button(parent, "Save", rect(526., 18., 91., 32.), delegate, SAVE);
    autoresize(save, 1);
    send1::<_, ()>(save, "setKeyEquivalent:", string("\r"));
    send1::<_, ()>(save, "setBezelColor:", color("systemBlueColor"));
    let clip: Id = send0(scroll, "contentView");
    let bounds: Rect = send0(clip, "bounds");
    frame(form, rect(0., 0., bounds.size.width, 530.));
    send1::<_, ()>(clip, "scrollToPoint:", Point { x: 0., y: (530. - bounds.size.height).max(0.) });
    send1::<_, ()>(scroll, "reflectScrolledClipView:", clip);
    Editor { names, name, domain, ip, username, password, transport, listen, port, launch, lan_warning, message }
}
unsafe fn log_view(parent: Id, delegate: Id) -> LogViews {
    let scroll = new("NSScrollView");
    autoresize(scroll, 18);
    frame(scroll, rect(24., 119., 592., 435.));
    send1::<_, ()>(scroll, "setHasVerticalScroller:", true);
    send1::<_, ()>(scroll, "setBorderType:", 1_usize);
    let allocated: Id = send0(class("NSTextView"), "alloc");
    let text: Id = send1(allocated, "initWithFrame:", rect(0., 0., 570., 435.));
    send1::<_, ()>(text, "setEditable:", false);
    send1::<_, ()>(text, "setSelectable:", true);
    send1::<_, ()>(text, "setRichText:", false);
    send1::<_, ()>(text, "setVerticallyResizable:", true);
    send1::<_, ()>(text, "setHorizontallyResizable:", false);
    send1::<_, ()>(text, "setMinSize:", Size { width: 0., height: 435. });
    send1::<_, ()>(text, "setMaxSize:", Size { width: f64::MAX, height: f64::MAX });
    send1::<_, ()>(text, "setAutoresizingMask:", 2_usize);
    let container: Id = send0(text, "textContainer");
    send1::<_, ()>(container, "setWidthTracksTextView:", true);
    let font: Id = send2(class("NSFont"), "monospacedSystemFontOfSize:weight:", 11_f64, 0_f64);
    send1::<_, ()>(text, "setFont:", font);
    send1::<_, ()>(scroll, "setDocumentView:", text);
    add(parent, scroll);
    let level = popup(parent, rect(24., 75., 236., 28.), delegate, LEVEL);
    popup_items(level, &levels().iter().map(|level| level.title().to_string()).collect::<Vec<_>>(), 2);
    autoresize(button(parent, "Copy All", rect(427., 75., 90., 29.), delegate, COPY_LOG), 1);
    autoresize(button(parent, "Save…", rect(526., 75., 90., 29.), delegate, SAVE_LOG), 1);
    let follow = checkbox(parent, "Follow latest", rect(24., 37., 200., 28.), delegate, FOLLOW);
    send1::<_, ()>(follow, "setState:", 1_isize);
    autoresize(button(parent, "Latest", rect(526., 37., 90., 29.), delegate, LATEST), 1);
    let count = label(parent, "", rect(24., 1., 592., 34.), 10., false);
    send1::<_, ()>(count, "setMaximumNumberOfLines:", 2_isize);
    autoresize(count, 2);
    LogViews { text, level, follow, count }
}
unsafe fn about_view(parent: Id) {
    autoresize(brand(parent, 32., 477., 64.), 8);
    autoresize(label(parent, APP_NAME, rect(112., 509., 450., 30.), 22., true), 10);
    autoresize(label(parent, "A quiet SOCKS5 proxy for your Mac", rect(112., 484., 450., 23.), 13., false), 10);
    let card = card(parent, rect(24., 245., 592., 215.));
    autoresize(card, 10);
    let built = option_env!("APP_BUILD_TIME").unwrap_or("Unknown");
    let built = chrono::DateTime::parse_from_rfc3339(built)
        .map(|time| time.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S %Z").to_string())
        .unwrap_or_else(|_| built.to_string());
    let values = [
        ("App version", env!("CARGO_PKG_VERSION")),
        ("Protocol core version", env!("CARGO_PKG_VERSION")),
        ("Source revision", option_env!("APP_SOURCE_REVISION").unwrap_or("Unknown")),
        ("Built", built.as_str()),
    ];
    for (index, (name, value)) in values.iter().enumerate() {
        let y = 169. - index as f64 * 45.;
        label(card, name, rect(20., y, 160., 25.), 13., false);
        autoresize(label(card, value, rect(180., y, 391., 25.), 12., false), 2);
    }
    let text = label(
        parent,
        "Rust implements sockets, TLS, QUIC, HTTP CONNECT and CONNECT-UDP. Destination names are resolved by the relay server. AppKit provides this native interface; Network.framework and Swift are not used. This development build is not notarized.",
        rect(32., 155., 572., 72.),
        12.,
        false,
    );
    send1::<_, ()>(text, "setMaximumNumberOfLines:", 4_isize);
    send1::<_, ()>(text, "setTextColor:", color("secondaryLabelColor"));
    autoresize(text, 10);
}
fn scope_at(index: usize) -> Option<TransferScope> {
    match index {
        1 => Some(TransferScope::Servers),
        2 => Some(TransferScope::Application),
        3 => Some(TransferScope::All),
        _ => None,
    }
}
fn transports() -> [Transport; 4] {
    [Transport::Auto, Transport::H3, Transport::H2, Transport::Http1]
}
fn transport_at(index: usize) -> Transport {
    transports()[index.min(3)]
}
fn transport_index(transport: Transport) -> usize {
    transports().iter().position(|mode| *mode == transport).unwrap_or(0)
}
fn levels() -> [LogLevel; 5] {
    [LogLevel::Everything, LogLevel::Detailed, LogLevel::Normal, LogLevel::Warnings, LogLevel::Errors]
}
fn log_level_at(index: usize) -> LogLevel {
    levels()[index.min(4)]
}
fn log_level_index(level: LogLevel) -> usize {
    levels().iter().position(|candidate| *candidate == level).unwrap_or(2)
}
fn active(status: &Status) -> bool {
    matches!(status, Status::Connecting | Status::Connected | Status::Reconnecting)
}
fn server_title(server: &Server) -> String {
    if !server.name.trim().is_empty() {
        server.name.trim().into()
    } else if !server.domain.trim().is_empty() {
        server.domain.trim().into()
    } else {
        "New Server".into()
    }
}
fn blank_server(server: &Server) -> bool {
    server.name.is_empty()
        && server.domain.is_empty()
        && server.server_ip.is_empty()
        && server.username.is_empty()
        && server.password.is_empty()
        && server.transport == Transport::Auto
}
/// Resolve selection against the live controller before removing empty drafts.
/// Preparation uses a copy so a failed disk save leaves the editable form intact.
fn prepare_save(draft: &Configuration, current: &Configuration, requested: Option<Uuid>) -> Configuration {
    let mut saved = draft.clone();
    let previous = current.selected_server().map(|server| server.id);
    saved.servers.retain(|server| !blank_server(server));
    saved.selected_server_id = requested.or(previous);
    if !saved.servers.iter().any(|server| Some(server.id) == saved.selected_server_id) {
        saved.selected_server_id = previous.filter(|id| saved.servers.iter().any(|server| server.id == *id));
    }
    saved.selected_server_id = saved.selected_server().map(|server| server.id);
    saved
}

fn private_write(path: &Path, contents: &[u8]) -> Result<()> {
    crate::model::write_privately(contents, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn configured(name: &str) -> Server {
        Server {
            name: name.into(),
            domain: format!("{name}.example.com"),
            username: "user".into(),
            password: "test-password".into(),
            ..Server::default()
        }
    }
    #[test]
    fn save_after_live_server_choice_preserves_the_live_selection_and_draft_edits() {
        let first = configured("first");
        let second = configured("second");
        let draft = Configuration {
            servers: vec![first.clone(), second.clone()],
            selected_server_id: Some(first.id),
            listen_address: "::1".into(),
            ..Configuration::default()
        };
        let mut current = draft.clone();
        current.selected_server_id = Some(second.id);
        current.listen_address = "127.0.0.1".into();
        let saved = prepare_save(&draft, &current, None);
        assert_eq!(saved.selected_server_id, Some(second.id));
        assert_eq!(saved.listen_address, "::1");
        assert_eq!(draft.selected_server_id, Some(first.id));
    }
    #[test]
    fn saving_selected_empty_new_server_does_not_jump_to_the_first_server() {
        let first = configured("first");
        let active = configured("active");
        let blank = Server::default();
        let current = Configuration {
            servers: vec![first, active.clone()],
            selected_server_id: Some(active.id),
            ..Configuration::default()
        };
        let mut draft = current.clone();
        draft.servers.push(blank.clone());
        let saved = prepare_save(&draft, &current, Some(blank.id));
        assert_eq!(saved.selected_server_id, Some(active.id));
        assert_eq!(saved.servers.len(), 2);
        assert_eq!(draft.servers.len(), 3);
    }
    #[test]
    fn explicit_import_selection_applies_when_the_server_survives() {
        let active = configured("active");
        let imported = configured("imported");
        let current = Configuration {
            servers: vec![active.clone()],
            selected_server_id: Some(active.id),
            ..Configuration::default()
        };
        let mut draft = current.clone();
        draft.servers.push(imported.clone());
        assert_eq!(prepare_save(&draft, &current, Some(imported.id)).selected_server_id, Some(imported.id));
    }
}
