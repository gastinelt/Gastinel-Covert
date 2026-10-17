//! Integration tests for covert-native-msg host.

use covert_core::models::{Vault, VaultItem};
use covert_native_msg::{NativeMessagingHost, QueryResponse};
use std::io::Cursor;

#[test]
fn test_wire_framing_encode_decode() {
    let json_msg = r#"{"type":"query","url":"https://github.com/login"}"#;
    let framed = NativeMessagingHost::encode_string_message(json_msg);

    assert!(framed.len() >= 4);
    let decoded = NativeMessagingHost::decode_message(&framed).expect("decode");
    assert_eq!(decoded, json_msg);
}

#[test]
fn test_query_while_locked() {
    let host = NativeMessagingHost::new();
    assert!(!host.is_unlocked());

    let req = r#"{"type":"query","url":"https://github.com"}"#;
    let resp = host.handle_json_message(req);

    let parsed: QueryResponse = serde_json::from_str(&resp).expect("parse response");
    assert_eq!(parsed.status, "locked");
    assert!(parsed.matches.is_empty());
}

#[test]
fn test_query_while_unlocked_strict_domain_matching() {
    let host = NativeMessagingHost::new();

    let mut vault = Vault::new("Work Vault");
    vault.add_item(VaultItem::new_credential(
        "GitHub Work",
        "work_user",
        "work_pass",
        Some("https://github.com/session".to_string()),
    ));
    vault.add_item(VaultItem::new_credential(
        "GitLab Work",
        "gitlab_user",
        "gitlab_pass",
        Some("https://gitlab.com/".to_string()),
    ));
    vault.add_item(VaultItem::new_ssh(
        "SSH Deploy",
        "ed25519",
        "pub",
        "priv",
        None,
        None,
    ));

    host.set_vault(vault);
    assert!(host.is_unlocked());

    // 1. Exact match on github.com
    let resp_gh = host.handle_json_message(r#"{"type":"query","url":"https://github.com/login"}"#);
    let parsed_gh: QueryResponse = serde_json::from_str(&resp_gh).expect("parse gh");
    assert_eq!(parsed_gh.status, "ok");
    assert_eq!(parsed_gh.matches.len(), 1);
    assert_eq!(parsed_gh.matches[0].title, "GitHub Work");
    assert_eq!(parsed_gh.matches[0].username.as_deref(), Some("work_user"));

    // 2. Phishing URL strictly rejected
    let resp_phish = host.handle_json_message(r#"{"type":"query","url":"https://evil-github.com/login"}"#);
    let parsed_phish: QueryResponse = serde_json::from_str(&resp_phish).expect("parse phish");
    assert_eq!(parsed_phish.status, "ok");
    assert!(parsed_phish.matches.is_empty());

    // 3. Different subdomain rejected
    let resp_sub = host.handle_json_message(r#"{"type":"query","url":"https://api.github.com/v1"}"#);
    let parsed_sub: QueryResponse = serde_json::from_str(&resp_sub).expect("parse sub");
    assert_eq!(parsed_sub.status, "ok");
    assert!(parsed_sub.matches.is_empty());

    // 4. Lock vault
    host.lock();
    assert!(!host.is_unlocked());
    let resp_locked = host.handle_json_message(r#"{"type":"query","url":"https://github.com/login"}"#);
    let parsed_locked: QueryResponse = serde_json::from_str(&resp_locked).expect("parse locked");
    assert_eq!(parsed_locked.status, "locked");
}

#[test]
fn test_stdio_loop_roundtrip() {
    let host = NativeMessagingHost::new();

    let mut input_data = Vec::new();
    let msg1 = r#"{"type":"status"}"#;
    let frame1 = NativeMessagingHost::encode_string_message(msg1);
    input_data.extend_from_slice(&frame1);

    let reader = Cursor::new(input_data);
    let mut writer = Cursor::new(Vec::new());

    host.run_stdio_loop(reader, &mut writer).expect("run stdio loop");

    let out_bytes = writer.into_inner();
    let resp_str = NativeMessagingHost::decode_message(&out_bytes).expect("decode output");
    assert!(resp_str.contains(r#""status":"ok""#));
    assert!(resp_str.contains(r#""unlocked":false"#));
}

#[test]
fn test_antiphishing_userinfo_and_url_spoofing() {
    use covert_sentinel::{SecurityEvent, SecurityEventSink};

    let host = NativeMessagingHost::new();
    let mut vault = Vault::new("Security Vault");
    vault.add_item(VaultItem::new_credential(
        "Google Main",
        "theodore@gmail.com",
        "super_secret_pw",
        Some("https://google.com/login".to_string()),
    ));
    host.set_vault(vault);

    // 1. Legitimate login matches
    let legit_resp = host.handle_json_message(r#"{"type":"query","url":"https://google.com/signin"}"#);
    let legit: QueryResponse = serde_json::from_str(&legit_resp).expect("parse legit");
    assert_eq!(legit.matches.len(), 1);
    assert_eq!(legit.matches[0].title, "Google Main");

    // 2. Phishing URL with userinfo spoofing (google.com@phishing.attacker.com)
    let phish1_resp = host.handle_json_message(r#"{"type":"query","url":"https://google.com@attacker.com/login"}"#);
    let phish1: QueryResponse = serde_json::from_str(&phish1_resp).expect("parse phish 1");
    assert_eq!(phish1.matches.len(), 0, "Userinfo spoofing must not match google.com");

    // 3. Phishing URL with port + password spoofing
    let phish2_resp = host.handle_json_message(r#"{"type":"query","url":"https://google.com:password@phishing-target.net/auth"}"#);
    let phish2: QueryResponse = serde_json::from_str(&phish2_resp).expect("parse phish 2");
    assert_eq!(phish2.matches.len(), 0, "Userinfo with port spoofing must not match google.com");

    // 4. Query string boundary
    let legit_query = host.handle_json_message(r#"{"type":"query","url":"https://google.com?session=123"}"#);
    let legit_q: QueryResponse = serde_json::from_str(&legit_query).expect("parse query string");
    assert_eq!(legit_q.matches.len(), 1);

    // 5. Sentinel intrusion alert triggers immediate lockdown
    host.on_security_alert(SecurityEvent::DebuggerAttached);
    assert!(!host.is_unlocked());

    let locked_resp = host.handle_json_message(r#"{"type":"query","url":"https://google.com/login"}"#);
    let locked: QueryResponse = serde_json::from_str(&locked_resp).expect("parse locked");
    assert_eq!(locked.status, "locked");
    assert!(locked.matches.is_empty());
}

#[test]
fn test_manifest_generation_and_allowed_origins_validation() {
    use covert_native_msg::{
        NativeMessagingManifest, NativeMsgError, DEFAULT_ALLOWED_ORIGIN, DEFAULT_MANIFEST_NAME,
    };

    let host = NativeMessagingHost::new();
    let manifest = host
        .generate_manifest(r"C:\Program Files\Gastinel\covert-cli.exe")
        .expect("generate default manifest");
    assert_eq!(manifest.name, DEFAULT_MANIFEST_NAME);
    assert_eq!(manifest.r#type, "stdio");
    assert_eq!(manifest.allowed_origins, vec![DEFAULT_ALLOWED_ORIGIN.to_string()]);

    let json = manifest.to_json_pretty().expect("serialize manifest");
    assert!(json.contains(r#""allowed_origins""#));
    assert!(json.contains(DEFAULT_ALLOWED_ORIGIN));

    // Reject empty allowed_origins
    assert!(matches!(
        NativeMessagingManifest::new(r"C:\covert-cli.exe", vec![]),
        Err(NativeMsgError::InvalidManifest(_))
    ));

    // Reject wildcard origins
    assert!(matches!(
        NativeMessagingManifest::new(
            r"C:\covert-cli.exe",
            vec!["chrome-extension://*/".to_string()]
        ),
        Err(NativeMsgError::InvalidManifest(_))
    ));

    // Reject invalid length or non-lowercase extension IDs
    assert!(matches!(
        NativeMessagingManifest::new(
            r"C:\covert-cli.exe",
            vec!["chrome-extension://shortid/".to_string()]
        ),
        Err(NativeMsgError::InvalidManifest(_))
    ));
}

#[test]
fn test_caller_origin_whitelist_and_unauthorized_caller_rejection() {
    use covert_native_msg::{NativeMsgError, DEFAULT_ALLOWED_ORIGIN, DEFAULT_EXTENSION_ID};

    let host = NativeMessagingHost::with_allowed_origins(vec![DEFAULT_EXTENSION_ID.to_string()])
        .expect("with_allowed_origins");

    let mut vault = Vault::new("Protected Browser Vault");
    vault.add_item(VaultItem::new_credential(
        "GitHub",
        "theo",
        "secret_pw",
        Some("https://github.com/login".to_string()),
    ));
    host.set_vault(vault);

    // 1. Unverified caller without origin in payload is rejected even when vault is unlocked
    let unverified_resp =
        host.handle_json_message(r#"{"type":"query","url":"https://github.com/login"}"#);
    assert!(
        unverified_resp.contains(r#""status":"error""#)
            && unverified_resp.contains("Unauthorized caller"),
        "Unverified caller must be rejected: {}",
        unverified_resp
    );

    // 2. Message with rogue extension_id / origin in JSON payload is rejected
    let rogue_msg = r#"{"type":"query","url":"https://github.com/login","origin":"chrome-extension://rogueattackerextensionid00000000/"}"#;
    let rogue_resp = host.handle_json_message(rogue_msg);
    assert!(
        rogue_resp.contains(r#""status":"error""#)
            && rogue_resp.contains("Unauthorized caller origin"),
        "Rogue extension origin must be rejected: {}",
        rogue_resp
    );

    // 3. verify_caller and run_stdio_loop_for_caller reject unauthorized caller
    let err = host
        .verify_caller("chrome-extension://rogueattackerextensionid00000000/")
        .unwrap_err();
    assert!(matches!(err, NativeMsgError::UnauthorizedCaller(_)));

    let dummy_in = Cursor::new(Vec::<u8>::new());
    let mut dummy_out = Cursor::new(Vec::<u8>::new());
    let loop_err = host
        .run_stdio_loop_for_caller(
            "chrome-extension://rogueattackerextensionid00000000/",
            dummy_in,
            &mut dummy_out,
        )
        .unwrap_err();
    assert!(matches!(loop_err, NativeMsgError::UnauthorizedCaller(_)));

    // 4. Authorized caller passes verify_caller and receives domain-matched credentials
    host.verify_caller(DEFAULT_ALLOWED_ORIGIN)
        .expect("Whitelisted extension origin must be accepted");

    let ok_resp = host.handle_json_message(r#"{"type":"query","url":"https://github.com/login"}"#);
    let parsed: QueryResponse = serde_json::from_str(&ok_resp).expect("parse ok response");
    assert_eq!(parsed.status, "ok");
    assert_eq!(parsed.matches.len(), 1);
    assert_eq!(parsed.matches[0].title, "GitHub");
}

#[test]
fn test_default_deny_without_extension_id_refuses_all_requests() {
    use covert_native_msg::{NativeMsgError, DEFAULT_ALLOWED_ORIGIN, DEFAULT_EXTENSION_ID};

    let host = NativeMessagingHost::new_deny_all();
    assert!(
        host.allowed_origins().is_empty(),
        "new_deny_all must have an empty allowed_origins whitelist"
    );

    let mut vault = Vault::new("Default Deny Vault");
    vault.add_item(VaultItem::new_credential(
        "GitHub",
        "theo",
        "secret_pw",
        Some("https://github.com/login".to_string()),
    ));
    host.set_vault(vault);

    // 1. Request without origin is refused
    let resp_no_origin =
        host.handle_json_message(r#"{"type":"query","url":"https://github.com/login"}"#);
    assert!(resp_no_origin.contains(r#""status":"error""#));
    assert!(resp_no_origin.contains("Unauthorized caller"));

    // 2. Request even with DEFAULT_ALLOWED_ORIGIN in payload is refused because no --extension-id was provided
    let msg_with_default = format!(
        r#"{{"type":"query","url":"https://github.com/login","origin":"{}"}}"#,
        DEFAULT_ALLOWED_ORIGIN
    );
    let resp_with_default = host.handle_json_message(&msg_with_default);
    assert!(resp_with_default.contains(r#""status":"error""#));
    assert!(resp_with_default.contains("Unauthorized caller origin"));

    // 3. verify_caller refuses even DEFAULT_EXTENSION_ID when no --extension-id was configured
    assert!(matches!(
        host.verify_caller(DEFAULT_EXTENSION_ID),
        Err(NativeMsgError::UnauthorizedCaller(_))
    ));
    assert!(matches!(
        host.verify_caller(DEFAULT_ALLOWED_ORIGIN),
        Err(NativeMsgError::UnauthorizedCaller(_))
    ));
}


