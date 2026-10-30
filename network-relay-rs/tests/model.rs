use network_relay_rs::model::{
    ClientChange, Configuration, LogLevel, Server, TransferScope, Transport, append_client_log, client_change,
    parse_domain, write_privately,
};
use std::fs;
use uuid::Uuid;

fn server(domain: &str) -> Server {
    Server {
        domain: domain.into(),
        username: "macbook".into(),
        password: "test-only-password".into(),
        ..Server::default()
    }
}
fn configuration() -> Configuration {
    let a = server("vpn.example.com:8443");
    let b = Server {
        name: "Frankfurt".into(),
        server_ip: "198.51.100.7".into(),
        transport: Transport::H2,
        ..server("de.example.com")
    };
    Configuration { selected_server_id: Some(a.id), servers: vec![a, b], ..Configuration::default() }
}
fn temporary_folder() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("network-relay-rs-model-{}", Uuid::new_v4()))
}

#[test]
fn saving_new_and_imported_profiles_keeps_an_unchanged_current_connection() {
    let current = configuration();
    let active = current.selected_server_id;
    let mut draft = current.clone();
    let added = server("new.example.com");
    draft.selected_server_id = Some(added.id);
    draft.servers.push(added);
    for imported in [false, true] {
        let (saved, allow_reconnect) = draft.preparing_connection_save(&current, imported);
        assert_eq!(saved.selected_server_id, active);
        assert_eq!(saved.servers, draft.servers);
        assert!(allow_reconnect);
    }
    draft.selected_server_id = Some(draft.servers[1].id);
    let (saved, allow_reconnect) = draft.preparing_connection_save(&current, true);
    assert_eq!(saved.selected_server_id, active);
    assert!(allow_reconnect);
}

#[test]
fn imported_replacement_or_active_settings_change_waits_for_connect() {
    let current = configuration();
    let mut draft = current.clone();
    draft.servers.remove(0);
    assert!(!draft.preparing_connection_save(&current, true).1);
    draft = current.clone();
    draft.servers[0].password = "imported-password".into();
    draft.selected_server_id = Some(draft.servers[1].id);
    let (changed, allow_reconnect) = draft.preparing_connection_save(&current, true);
    assert!(!allow_reconnect);
    assert_eq!(changed.selected_server_id, current.selected_server_id);
    draft = current.clone();
    draft.port = 1081;
    assert!(draft.preparing_connection_save(&current, true).1, "application edits retain their ordinary Save behavior");
    assert!(draft.preparing_connection_save(&current, false).1, "ordinary edits still reconnect on Save");
    assert!(!current.preparing_connection_save(&Configuration::default(), false).1);
}

#[test]
fn imported_inactive_and_display_only_changes_keep_the_current_connection() {
    let current = configuration();
    let mut draft = current.clone();
    draft.servers[0].name = "Renamed".into();
    draft.servers[1].password = "inactive-password".into();
    draft.log_level = LogLevel::Detailed;
    draft.port = 1081;
    let (saved, allow_reconnect) = draft.preparing_connection_save(&current, true);
    assert!(allow_reconnect);
    assert_eq!(saved.selected_server_id, current.selected_server_id);
    assert_eq!(client_change(&current, &saved), ClientChange::Reconnect, "the application port still applies on Save");
}

#[test]
fn selected_server_and_blank_draft_keep_their_identity() {
    let mut c = configuration();
    let first = c.servers[0].id;
    let second = c.servers[1].id;
    c.selected_server_id = Some(second);
    assert_eq!(c.selected_server().unwrap().id, second);
    c.selected_server_id = Some(Uuid::new_v4());
    assert_eq!(c.selected_server().unwrap().id, first);
    let blank = Server::default();
    c.selected_server_id = Some(blank.id);
    c.servers.push(blank.clone());
    assert_eq!(c.selected_server().unwrap().id, blank.id);
    assert!(c.check().is_ok());
    assert!(c.core_config().is_err(), "connecting a blank draft cannot connect the first server");
    let folder = temporary_folder();
    let path = folder.join("configuration.json");
    c.save(&path).unwrap();
    let loaded = Configuration::try_load(&path).unwrap();
    assert_eq!(loaded, c);
    assert_eq!(loaded.selected_server_id, Some(blank.id));
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn endpoint_ip_and_domain_certificate_identity_stay_separate() {
    let mut c = configuration();
    c.selected_server_id = Some(c.servers[1].id);
    c.port = 1081;
    let endpoint = c.core_config().unwrap();
    assert_eq!(endpoint.uri_template, "https://198.51.100.7:443/.well-known/masque/udp/{target_host}/{target_port}/");
    assert_eq!(endpoint.server_name.as_deref(), Some("de.example.com"));
    assert_eq!(endpoint.transport, "h2");
    assert_eq!(endpoint.socks.listen[0].to_string(), "127.0.0.1:1081");
    c.servers[1].server_ip = "2001:db8::17".into();
    assert!(c.client_config_toml().unwrap().contains("https://[2001:db8::17]:443/"));
    c.listen_address = "::1".into();
    assert_eq!(c.proxy_address(), "[::1]:1081");
    assert!(c.listens_only_locally());
    c.listen_address = "0.0.0.0".into();
    assert!(!c.listens_only_locally());
}

#[test]
fn validated_domains_reject_ips_urls_credentials_and_ambiguous_ports() {
    assert_eq!(parse_domain(" VPN.Example.COM.:8443 ").unwrap(), ("vpn.example.com".into(), 8443));
    for input in [
        "",
        "127.0.0.1",
        "[::1]",
        "https://vpn.example.com",
        "vpn.example.com:0",
        "vpn.example.com:65536",
        "vpn.example.com:",
        "vpn..example.com",
        "-vpn.example.com",
        "vpn-.example.com",
        "name@vpn.example.com",
        "vpn.example.com/path",
        "vpn.example.com#fragment",
        "vpn.example.com?x",
        "vpn_example.com",
    ] {
        assert!(parse_domain(input).is_err(), "invalid domain accepted: {input}");
    }
}

#[test]
fn checked_settings_reject_invalid_user_ip_password_and_listen() {
    for name in [".hidden", "user:name", "nonasciié", "line\nbreak"] {
        let mut c = configuration();
        c.servers[0].username = name.into();
        assert!(c.check().is_err());
    }
    let mut c = configuration();
    c.servers[0].username = "a".repeat(65);
    assert!(c.check().is_err());
    let mut c = configuration();
    c.servers[0].password = "pw\n".into();
    assert!(c.check().is_err());
    let mut c = configuration();
    c.servers[0].password = "pw\u{0085}".into();
    assert!(c.check().is_err());
    let mut c = configuration();
    c.servers[0].password = "pw\u{200b}".into();
    assert!(c.check().is_ok());
    for address in ["invalid", "fe80::1%en0", "[::1]", "198.51.100.9:443"] {
        let mut c = configuration();
        c.servers[0].server_ip = address.into();
        assert!(c.check().is_err());
    }
    let mut c = configuration();
    c.listen_address = "localhost".into();
    assert!(c.check().is_err());
    let mut c = configuration();
    c.port = 0;
    assert!(c.check().is_err());
    let mut c = configuration();
    c.servers[1].password.clear();
    assert!(c.check().unwrap_err().to_string().starts_with("Frankfurt:"));
}

#[test]
fn reconnect_only_when_running_endpoint_changes() {
    let old = configuration();
    let cosmetic: [fn(&mut Configuration); 4] = [
        |c: &mut Configuration| c.servers[0].name = "New title".into(),
        |c: &mut Configuration| c.servers[1].password = "other password".into(),
        |c: &mut Configuration| c.connect_on_launch = true,
        |c: &mut Configuration| c.log_level = LogLevel::Everything,
    ];
    for edit in cosmetic {
        let mut new = old.clone();
        edit(&mut new);
        assert_eq!(client_change(&old, &new), ClientChange::None);
    }
    let connecting: [fn(&mut Configuration); 4] = [
        |c: &mut Configuration| c.servers[0].transport = Transport::H3,
        |c: &mut Configuration| c.servers[0].password = "changed password".into(),
        |c: &mut Configuration| c.selected_server_id = Some(c.servers[1].id),
        |c: &mut Configuration| c.port = 1081,
    ];
    for edit in connecting {
        let mut new = old.clone();
        edit(&mut new);
        assert_eq!(client_change(&old, &new), ClientChange::Reconnect);
    }
    let mut new = old.clone();
    new.servers.clear();
    assert_eq!(client_change(&old, &new), ClientChange::Disconnect);
    let mut new = old.clone();
    let blank = Server::default();
    new.selected_server_id = Some(blank.id);
    new.servers.push(blank);
    assert_eq!(client_change(&old, &new), ClientChange::Disconnect);
}

#[test]
fn export_import_roundtrip_with_utf8_and_escaped_content() {
    let mut c = configuration();
    c.servers[0].name = "Tokyo \"one\"\nroute\\path\t\u{007f}".into();
    c.servers[0].password = "test-only-😀".into();
    let imported = Configuration::importing(
        &c.exported_toml(true, TransferScope::All),
        TransferScope::All,
        &Configuration::default(),
    )
    .unwrap();
    assert_eq!(c, imported);
    let no_passwords = c.exported_toml(false, TransferScope::All);
    assert!(!no_passwords.contains("test-only-password"));
    assert!(!no_passwords.contains("test-only-😀"));
    let imported = Configuration::importing(&no_passwords, TransferScope::All, &Configuration::default()).unwrap();
    assert!(imported.servers.iter().all(|s| s.password.is_empty()));
}

#[test]
fn scoped_exports_do_not_expose_or_overwrite_unrelated_settings() {
    let c = configuration();
    let application = c.exported_toml(true, TransferScope::Application);
    assert!(!application.contains("[[server]]"));
    assert!(!application.contains("password ="));
    let servers = c.exported_toml(true, TransferScope::Servers);
    assert!(!servers.contains("[proxy]"));
    let mut base = Configuration::default();
    base.port = 1089;
    base.servers = vec![server("keep.example.com")];
    base.selected_server_id = Some(base.servers[0].id);
    let server_import = Configuration::importing(&servers, TransferScope::Servers, &base).unwrap();
    assert_eq!(server_import.port, 1089);
    let application_import = Configuration::importing(&application, TransferScope::Application, &base).unwrap();
    assert_eq!(application_import.servers, base.servers);
    assert_eq!(application_import.port, c.port);
    let application_all = Configuration::importing(&application, TransferScope::All, &base).unwrap();
    assert_eq!(application_all.servers, base.servers);
}

#[test]
fn import_accepts_nf_toml_and_protocol_core_toml() {
    let nf = r#"
[proxy]
listen_address = "::1"
port = 1080
connect_on_launch = true
log_level = "detailed"
[[server]]
id = "00000000-0000-0000-0000-000000000001"
name = "NF profile"
domain = "relay.example.com"
ip = "198.51.100.7"
username = "macbook"
password = "test-only"
transport = "h3"
selected = true
"#;
    let c = Configuration::importing(nf, TransferScope::All, &Configuration::default()).unwrap();
    assert_eq!(c.proxy_address(), "[::1]:1080");
    assert_eq!(c.selected_server().unwrap().transport, Transport::H3);
    let core = c.client_config_toml().unwrap();
    let imported = Configuration::importing(&core, TransferScope::All, &Configuration::default()).unwrap();
    let s = imported.selected_server().unwrap();
    assert_eq!(s.domain, "relay.example.com");
    assert_eq!(s.server_ip, "198.51.100.7");
    assert_eq!(s.transport, Transport::H3);
    assert_eq!(imported.proxy_address(), "[::1]:1080");
    let c = configuration();
    let core = c.client_config_toml().unwrap();
    let imported = Configuration::importing(&core, TransferScope::All, &Configuration::default()).unwrap();
    assert_eq!(imported.selected_server().unwrap().domain, "vpn.example.com:8443");
}

#[test]
fn nf_admission_probe_targets_survive_import_use_and_export() {
    // The shape of a Network Relay NF export, including its UTF-8 header.
    let nf = "# Network Relay NF settings. Import them in Network Relay NF with Settings \u{2192} Import\u{2026}.\n"
        .to_owned()
        + r#"# The file holds the passwords: keep it private.

[proxy]
listen_address = "127.0.0.1"
port = 1080
connect_on_launch = false
log_level = "normal"

[[server]]
id = "7D3C1F0A-5B2E-4C11-9A6B-0123456789AB"
name = "Tokyo"
domain = "vpn.example.com"
username = "macbook"
password = "test-only"
transport = "h2"
probe_target = "[2606:4700:4700::1111]:53"
selected = true

[[server]]
id = "7D3C1F0A-5B2E-4C11-9A6B-0123456789AC"
domain = "de.example.com"
username = "macbook"
password = "test-only"
transport = "auto"
"#;
    let c = Configuration::importing(&nf, TransferScope::All, &Configuration::default()).unwrap();
    assert_eq!(c.servers[0].probe_target, "[2606:4700:4700::1111]:53");
    assert_eq!(c.servers[1].probe_target, "1.1.1.1:53");
    assert_eq!(c.core_config().unwrap().probe_target, "[2606:4700:4700::1111]:53".parse().unwrap());
    let exported = c.exported_toml(true, TransferScope::All);
    assert!(exported.contains("probe_target = \"[2606:4700:4700::1111]:53\""));
    assert_eq!(exported.matches("probe_target").count(), 1, "the default is left out, as NF does");
    assert_eq!(Configuration::importing(&exported, TransferScope::All, &Configuration::default()).unwrap(), c);
    let core = c.client_config_toml().unwrap();
    assert!(core.contains("probe_target = \"[2606:4700:4700::1111]:53\""));
    let from_core = Configuration::importing(&core, TransferScope::All, &Configuration::default()).unwrap();
    assert_eq!(from_core.servers[0].probe_target, "[2606:4700:4700::1111]:53");
    // A changed probe target is part of the running client configuration.
    let mut changed = c.clone();
    changed.servers[0].probe_target = "9.9.9.9:53".into();
    assert_eq!(client_change(&c, &changed), ClientChange::Reconnect);
    let spaced = Configuration::importing(
        "[[server]]\ndomain = \"a.example.com\"\nprobe_target = \" 8.8.8.8:53 \"",
        TransferScope::All,
        &Configuration::default(),
    )
    .unwrap();
    assert_eq!(spaced.servers[0].probe_target, "8.8.8.8:53");
    for target in [
        "1.1.1.1",
        "dns.example:53",
        "1.1.1.1:0",
        "1.1.1.1:65536",
        "2606:4700::1111:53",
        "[1.1.1.1]:53",
        "[fe80::1%2]:53",
    ] {
        let text = format!("[[server]]\ndomain = \"a.example.com\"\nprobe_target = \"{target}\"");
        assert!(Configuration::importing(&text, TransferScope::All, &Configuration::default()).is_err(), "{target}");
    }
}

#[test]
fn settings_saved_before_probe_targets_load_with_the_default() {
    let folder = temporary_folder();
    let path = folder.join("configuration.json");
    fs::create_dir_all(&folder).unwrap();
    fs::write(&path, r#"{"servers":[{"domain":"vpn.example.com","username":"macbook","password":"x"}]}"#).unwrap();
    let c = Configuration::try_load(&path).unwrap();
    assert_eq!(c.servers[0].probe_target, "1.1.1.1:53");
    assert!(!c.servers[0].is_blank());
    assert!(Server::default().is_blank());
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn import_ipv6_core_endpoint_retains_domain_and_port() {
    let core = r#"uri_template = "https://[2001:db8::7]:8443/.well-known/masque/udp/{target_host}/{target_port}/"
server_name = "relay.example.com"
username = "macbook"
password = "test-only"
transport = "http/1.1"
mode = "socks"
[socks]
listen = ["[::1]:1089"]
"#;
    let c = Configuration::importing(core, TransferScope::All, &Configuration::default()).unwrap();
    let s = c.selected_server().unwrap();
    assert_eq!(s.domain, "relay.example.com:8443");
    assert_eq!(s.server_ip, "2001:db8::7");
    assert_eq!(s.transport, Transport::Http1);
    assert!(c.check().is_ok());
    assert_eq!(
        c.core_config().unwrap().uri_template,
        "https://[2001:db8::7]:8443/.well-known/masque/udp/{target_host}/{target_port}/"
    );
}

#[test]
fn import_rejects_duplicate_ids_bad_types_and_unsupported_values() {
    for text in [
        "[proxy]\nport = \"1080\"",
        "[proxy]\nport = 0",
        "[proxy]\nport = 65536",
        "[proxy]\nlisten_address = \"localhost\"",
        "[proxy]\nconnect_on_launch = 1",
        "[proxy]\nlog_level = \"debug\"",
        "[[server]]\ntransport = \"http3\"",
        "[[server]]\nselected = \"true\"",
        "[[server]]\nid = \"bad\"",
        "server = false",
        "something_else = 42",
        "[[server]]\nid = \"00000000-0000-0000-0000-000000000001\"\n[[server]]\nid = \"00000000-0000-0000-0000-000000000001\"",
        "uri_template = \"http://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/\"",
        "uri_template = \"https://user@relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/\"",
        "uri_template = \"https://relay.example.com/another/template\"",
        "uri_template = \"https://relay.example.com/.well-known/masque/udp/{target_host}/{target_port}/\"\n[socks]\nlisten = [\"127.0.0.1:1080\", \"localhost:1081\"]",
    ] {
        assert!(
            Configuration::importing(text, TransferScope::All, &Configuration::default()).is_err(),
            "accepted: {text}"
        );
    }
}

#[test]
fn merge_updates_by_uuid_and_retains_omitted_passwords_and_selection() {
    let mut base = configuration();
    let selected = base.selected_server_id;
    let preserved = base.servers[1].password.clone();
    let mut imported = base.clone();
    imported.servers[1].domain = "updated.example.com".into();
    imported.servers[1].password.clear();
    imported.selected_server_id = Some(imported.servers[1].id);
    assert_eq!(base.import_servers(&imported, false), 0);
    assert_eq!(base.servers.len(), 2);
    assert_eq!(base.servers[1].domain, "updated.example.com");
    assert_eq!(base.servers[1].password, preserved);
    assert_eq!(base.selected_server_id, selected);
    assert_eq!(base.import_servers(&imported, true), 0);
    assert_eq!(base.selected_server_id, imported.selected_server_id);
    assert_eq!(base.servers[1].password, preserved);
}

#[test]
fn merge_legacy_profiles_retains_ids_and_secrets() {
    let mut base = configuration();
    let ids: Vec<_> = base.servers.iter().map(|s| s.id).collect();
    let legacy = base
        .exported_toml(false, TransferScope::Servers)
        .lines()
        .filter(|line| !line.starts_with("id ="))
        .collect::<Vec<_>>()
        .join("\n");
    let imported = Configuration::importing(&legacy, TransferScope::Servers, &Configuration::default()).unwrap();
    assert_eq!(base.import_servers(&imported, true), 0);
    assert_eq!(base.servers.iter().map(|s| s.id).collect::<Vec<_>>(), ids);
    assert!(base.servers.iter().all(|s| !s.password.is_empty()));
}

#[test]
fn legacy_profile_does_not_steal_an_explicit_uuid_update() {
    let mut base = configuration();
    let original_id = base.servers[0].id;
    let mut legacy = base.servers[0].clone();
    legacy.id = Uuid::new_v4();
    legacy.password.clear();
    let mut update = base.servers[0].clone();
    update.domain = "updated.example.com".into();
    update.password.clear();
    let imported = Configuration {
        servers: vec![legacy, update],
        selected_server_id: Some(original_id),
        ..Configuration::default()
    };
    assert_eq!(base.import_servers(&imported, false), 1);
    assert_eq!(base.servers.iter().find(|s| s.id == original_id).unwrap().domain, "updated.example.com");
    assert_eq!(base.servers.len(), 3);
}

#[test]
fn private_atomic_saves_and_duplicate_saved_ids() {
    let folder = temporary_folder();
    let path = folder.join("configuration.json");
    let c = configuration();
    c.save(&path).unwrap();
    c.save(&path).unwrap();
    assert_eq!(Configuration::try_load(&path).unwrap(), c);
    assert_eq!(fs::read_dir(&folder).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let mut duplicate = c.clone();
    duplicate.servers[1].id = duplicate.servers[0].id;
    fs::write(&path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
    let loaded = Configuration::try_load(&path).unwrap();
    assert_ne!(loaded.servers[0].id, loaded.servers[1].id);
    assert_eq!(loaded.servers[0].domain, duplicate.servers[0].domain);
    fs::write(&path, "{not valid json").unwrap();
    assert!(Configuration::try_load(&path).is_err());
    assert_eq!(Configuration::load(&path), Configuration::default());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{not valid json");
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn default_storage_is_independent_of_nf() {
    let path = Configuration::default_path();
    assert!(path.ends_with("Library/Application Support/NetworkRelayRS/configuration.json"));
    assert!(!path.to_string_lossy().contains("NetworkRelayNF"));
}

#[test]
fn private_exports_do_not_change_existing_directory_permissions() {
    let folder = temporary_folder();
    fs::create_dir_all(&folder).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = folder.join("Settings.toml");
    write_privately(configuration().exported_toml(true, TransferScope::All).as_bytes(), &path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&folder).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    fs::remove_dir_all(folder).unwrap();
}

#[test]
fn log_levels_match_nf_and_do_not_enable_third_party_authentication_traces() {
    let lines = [
        "2026-10-12T11:00:00Z ERROR app: failed",
        "2026-10-12T11:00:00Z WARN core: reconnecting",
        "2026-10-12 11:00:00.000 +00:00 INFO core: relay ready",
        "DEBUG core: SOCKS metadata",
        "TRACE core: stream metadata",
    ];
    for (rank, level) in LogLevel::ALL.into_iter().enumerate() {
        assert_eq!(level.value() as usize, rank);
        for (line_rank, line) in lines.iter().enumerate() {
            assert_eq!(level.shows(line), line_rank <= rank);
        }
        assert!(level.shows("unknown startup diagnostic"));
        assert!(!level.tracing_filter().contains("h3=trace"));
        assert!(!level.tracing_filter().contains("h2=trace"));
    }
    assert_eq!(Transport::ALL.map(Transport::as_str), ["auto", "h3", "h2", "http/1.1"]);
}

#[test]
fn verbose_log_flood_preserves_important_records_in_order() {
    let mut log = vec!["INFO connected".into()];
    for batch in 0..10 {
        append_client_log(&mut log, (0..1000).map(|event| format!("TRACE metadata batch={batch} event={event}")), 5000);
        if batch == 4 {
            append_client_log(&mut log, ["WARN failure".into(), "INFO recovered".into()], 5000);
        }
    }
    assert_eq!(log.len(), 5000);
    assert_eq!(
        log.iter().filter(|line| !line.starts_with("TRACE")).map(String::as_str).collect::<Vec<_>>(),
        ["INFO connected", "WARN failure", "INFO recovered"]
    );
    assert_eq!(log.last().unwrap(), "TRACE metadata batch=9 event=999");
    let mut important = vec!["unknown".into(), "WARN old".into()];
    append_client_log(&mut important, ["INFO new".into(), "ERROR latest".into()], 3);
    assert_eq!(important, ["WARN old", "INFO new", "ERROR latest"]);
}
