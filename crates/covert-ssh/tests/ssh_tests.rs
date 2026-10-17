//! Comprehensive integration tests for covert-ssh OpenSSH agent provider.

use covert_core::models::{Vault, VaultItem};
use covert_sentinel::SecurityEvent;
use covert_sentinel::SecurityEventSink;
use covert_ssh::protocol::{
    WireStream, SSH_AGENTC_REMOVE_ALL_IDENTITIES, SSH_AGENTC_REQUEST_IDENTITIES,
    SSH_AGENTC_SIGN_REQUEST, SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER,
    SSH_AGENT_RSA_SHA2_256, SSH_AGENT_SIGN_RESPONSE, SSH_AGENT_SUCCESS,
};
use covert_ssh::SshAgent;

#[test]
fn test_agent_locked_returns_failure() {
    let agent = SshAgent::new();
    assert!(!agent.is_unlocked());

    let req_identities = WireStream::encode_frame(SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    let resp = agent.process_request(&req_identities);
    let (code, _) = WireStream::decode_frame(&resp).expect("Decode response");
    assert_eq!(code, SSH_AGENT_FAILURE);

    let req_sign = WireStream::encode_frame(SSH_AGENTC_SIGN_REQUEST, b"dummy-sign-request");
    let resp_sign = agent.process_request(&req_sign);
    let (code_sign, _) = WireStream::decode_frame(&resp_sign).expect("Decode response");
    assert_eq!(code_sign, SSH_AGENT_FAILURE);
}

#[test]
fn test_agent_unlocked_with_vault_keys_and_signing() {
    let agent = SshAgent::new();

    let mut vault = Vault::new("Test Vault");
    vault.add_item(VaultItem::new_ssh(
        "Deploy Ed25519 Key",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyBlobProduction",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        None,
        Some("deploy@prod".to_string()),
    ));
    let valid_rsa_pem = {
        use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
        use rsa::{BigUint, RsaPrivateKey};
        let p = BigUint::parse_bytes(
            b"f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b\
              3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03",
            16,
        )
        .unwrap();
        let q = BigUint::parse_bytes(
            b"b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb69\
              6fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947",
            16,
        )
        .unwrap();
        let e = BigUint::from(65537u32);
        let priv_key = RsaPrivateKey::from_p_q(p, q, e).expect("valid RSA test primes");
        priv_key
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode PKCS#1 PEM")
            .to_string()
    };

    vault.add_item(VaultItem::new_ssh(
        "Legacy RSA Key",
        "rsa-1024",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLRSAExampleLegacyKey",
        valid_rsa_pem,
        None,
        Some("admin@bastion".to_string()),
    ));

    // Populate keys from vault
    agent.load_vault_keys(&vault);
    assert!(agent.is_unlocked());

    // 1. Request identities
    let req_identities = WireStream::encode_frame(SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    let resp_identities = agent.process_request(&req_identities);
    let (code, payload) = WireStream::decode_frame(&resp_identities).expect("Decode response");
    assert_eq!(code, SSH_AGENT_IDENTITIES_ANSWER);

    let mut cursor = payload;
    let num_keys = WireStream::read_u32(&mut cursor).expect("num keys");
    assert_eq!(num_keys, 2);

    let key1_blob = WireStream::read_string(&mut cursor).expect("key 1 blob");
    let key1_comment = WireStream::read_string(&mut cursor).expect("key 1 comment");
    assert_eq!(key1_comment, b"deploy@prod");

    let key2_blob = WireStream::read_string(&mut cursor).expect("key 2 blob");
    let key2_comment = WireStream::read_string(&mut cursor).expect("key 2 comment");
    assert_eq!(key2_comment, b"admin@bastion");

    // 2. Sign request with Ed25519 key
    let data_to_sign = b"AuthenticationChallengeBytes2026";
    let mut sign_payload = Vec::new();
    WireStream::write_string(&mut sign_payload, key1_blob);
    WireStream::write_string(&mut sign_payload, data_to_sign);
    WireStream::write_u32(&mut sign_payload, 0); // flags

    let req_sign = WireStream::encode_frame(SSH_AGENTC_SIGN_REQUEST, &sign_payload);
    let resp_sign = agent.process_request(&req_sign);
    let (code_sign, sig_payload) = WireStream::decode_frame(&resp_sign).expect("Decode response");
    assert_eq!(code_sign, SSH_AGENT_SIGN_RESPONSE);

    let mut sig_cursor = sig_payload;
    let sig_algo = WireStream::read_string(&mut sig_cursor).expect("sig algo");
    assert_eq!(sig_algo, b"ssh-ed25519");
    let sig_bytes = WireStream::read_string(&mut sig_cursor).expect("sig bytes");
    assert!(!sig_bytes.is_empty());

    // 3. Sign request with RSA key (SHA2-256 flag)
    let mut sign_rsa_payload = Vec::new();
    WireStream::write_string(&mut sign_rsa_payload, key2_blob);
    WireStream::write_string(&mut sign_rsa_payload, data_to_sign);
    WireStream::write_u32(&mut sign_rsa_payload, SSH_AGENT_RSA_SHA2_256);

    let req_sign_rsa = WireStream::encode_frame(SSH_AGENTC_SIGN_REQUEST, &sign_rsa_payload);
    let resp_sign_rsa = agent.process_request(&req_sign_rsa);
    let (code_rsa, sig_rsa_payload) = WireStream::decode_frame(&resp_sign_rsa).expect("Decode response");
    assert_eq!(code_rsa, SSH_AGENT_SIGN_RESPONSE);

    let mut sig_rsa_cursor = sig_rsa_payload;
    let sig_rsa_algo = WireStream::read_string(&mut sig_rsa_cursor).expect("rsa sig algo");
    assert_eq!(sig_rsa_algo, b"rsa-sha2-256");

    // 4. Sentinel security alert drops keys immediately
    agent.on_security_alert(SecurityEvent::DebuggerAttached);
    assert!(!agent.is_unlocked());

    let resp_after_alert = agent.process_request(&req_identities);
    let (code_alert, _) = WireStream::decode_frame(&resp_after_alert).expect("Decode response");
    assert_eq!(code_alert, SSH_AGENT_FAILURE);
}

#[test]
fn test_remove_all_identities() {
    let agent = SshAgent::new();
    agent.set_unlocked(true);

    let req_clear = WireStream::encode_frame(SSH_AGENTC_REMOVE_ALL_IDENTITIES, &[]);
    let resp_clear = agent.process_request(&req_clear);
    let (code, _) = WireStream::decode_frame(&resp_clear).expect("decode");
    assert_eq!(code, SSH_AGENT_SUCCESS);
}

#[test]
fn test_unknown_key_sign_request_strictly_rejected() {
    let agent = SshAgent::new();
    let mut vault = Vault::new("Single Key Vault");
    vault.add_item(VaultItem::new_ssh(
        "Single Ed25519 Key",
        "ed25519",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIValidKeyHere",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        None,
        Some("deploy@prod".to_string()),
    ));
    agent.load_vault_keys(&vault);
    assert!(agent.is_unlocked());

    // Request signing with a completely different, unassociated key blob
    let fake_key_blob = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDFakeAttackerKeyBlob";
    let data_to_sign = b"AuthenticationChallenge";
    let mut sign_payload = Vec::new();
    WireStream::write_string(&mut sign_payload, fake_key_blob);
    WireStream::write_string(&mut sign_payload, data_to_sign);
    WireStream::write_u32(&mut sign_payload, 0);

    let req_sign = WireStream::encode_frame(SSH_AGENTC_SIGN_REQUEST, &sign_payload);
    let resp_sign = agent.process_request(&req_sign);
    let (code, _) = WireStream::decode_frame(&resp_sign).expect("decode response");
    assert_eq!(code, SSH_AGENT_FAILURE, "Unrecognized key blob must be rejected even with single loaded key");
}

#[test]
fn test_unparseable_and_unsupported_ssh_keys_return_real_error() {
    use covert_core::models::SshKeyData;
    use covert_ssh::error::SshAgentError;
    use covert_ssh::keys::SshKeyEntry;

    // 1. Unparseable Ed25519 key -> must return Err(SshAgentError::KeyError), never a fake SHA256 signature
    let bad_ed25519 = SshKeyEntry::from_ssh_data(
        &SshKeyData {
            key_type: "ed25519".to_string(),
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBadEd25519Key".to_string(),
            private_key: "not-a-valid-ed25519-private-key".to_string(),
            passphrase: None,
            comment: Some("bad-ed25519".to_string()),
        },
        "Bad Ed25519",
    );
    assert!(matches!(
        bad_ed25519.sign(b"challenge", 0),
        Err(SshAgentError::KeyError(_))
    ));

    // 2. Unparseable RSA key -> must return Err(SshAgentError::KeyError)
    let bad_rsa = SshKeyEntry::from_ssh_data(
        &SshKeyData {
            key_type: "rsa-4096".to_string(),
            public_key: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDBadRsaKey".to_string(),
            private_key: "mock_rsa_private_key_pem".to_string(),
            passphrase: None,
            comment: Some("bad-rsa".to_string()),
        },
        "Bad RSA",
    );
    assert!(matches!(
        bad_rsa.sign(b"challenge", SSH_AGENT_RSA_SHA2_256),
        Err(SshAgentError::KeyError(_))
    ));

    // 3. Unsupported SSH key type -> must return Err(SshAgentError::KeyError)
    let unsupported_key = SshKeyEntry::from_ssh_data(
        &SshKeyData {
            key_type: "ssh-dss".to_string(),
            public_key: "ssh-dss AAAAB3NzaC1kc3MAAACB".to_string(),
            private_key: "0123456789abcdef".to_string(),
            passphrase: None,
            comment: Some("unsupported-dsa".to_string()),
        },
        "Unsupported DSA",
    );
    assert!(matches!(
        unsupported_key.sign(b"challenge", 0),
        Err(SshAgentError::KeyError(_))
    ));

    // 4. Through SshAgent wire protocol: signing with an unparseable key returns SSH_AGENT_FAILURE
    let agent = SshAgent::new();
    agent.set_unlocked(true);
    let bad_blob = bad_rsa.public_key_blob.clone();
    agent.add_key(bad_rsa);

    let mut sign_payload = Vec::new();
    WireStream::write_string(&mut sign_payload, &bad_blob);
    WireStream::write_string(&mut sign_payload, b"challenge");
    WireStream::write_u32(&mut sign_payload, SSH_AGENT_RSA_SHA2_256);

    let req_sign = WireStream::encode_frame(SSH_AGENTC_SIGN_REQUEST, &sign_payload);
    let resp_sign = agent.process_request(&req_sign);
    let (code, _) = WireStream::decode_frame(&resp_sign).expect("decode response");
    assert_eq!(
        code, SSH_AGENT_FAILURE,
        "SshAgent must return SSH_AGENT_FAILURE when private key cannot be parsed"
    );
}

#[cfg(windows)]
#[test]
fn test_current_user_sid_resolution() {
    use covert_ssh::pipe::get_current_user_sid;
    let sid = get_current_user_sid();
    assert!(sid.is_some(), "Current user SID should be resolvable under Windows");
    let sid_str = sid.unwrap();
    assert!(sid_str.starts_with("S-1-"), "SID string should have standard format: {}", sid_str);
}

#[cfg(windows)]
#[test]
fn test_named_pipe_multi_request_session() {
    use covert_ssh::pipe::run_named_pipe_listener;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    let pipe_name = format!(r"\\.\pipe\test-covert-multi-req-{}", std::process::id());
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_signal);

    let agent = Arc::new(SshAgent::new());
    agent.set_unlocked(true);

    let server_pipe_name = pipe_name.clone();
    let server_agent = Arc::clone(&agent);
    let server_handle = thread::spawn(move || {
        let _ = run_named_pipe_listener(&server_pipe_name, stop_clone, move |req| {
            server_agent.process_request(req)
        });
    });

    // Wait for server pipe to be created
    thread::sleep(Duration::from_millis(100));

    // Client connects ONCE and sends TWO requests in sequence on the same connection
    let mut client = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&pipe_name)
        .expect("Open named pipe");

    // Request 1: Request identities
    let req1 = WireStream::encode_frame(SSH_AGENTC_REQUEST_IDENTITIES, &[]);
    client.write_all(&req1).expect("Write request 1");
    client.flush().expect("Flush request 1");

    let mut len1 = [0u8; 4];
    client.read_exact(&mut len1).expect("Read response 1 len");
    let msg1_len = u32::from_be_bytes(len1) as usize;
    let mut resp1_payload = vec![0u8; msg1_len];
    client.read_exact(&mut resp1_payload).expect("Read response 1 payload");
    assert_eq!(resp1_payload[0], SSH_AGENT_IDENTITIES_ANSWER);

    // Request 2: Remove all identities on the SAME connection
    let req2 = WireStream::encode_frame(SSH_AGENTC_REMOVE_ALL_IDENTITIES, &[]);
    client.write_all(&req2).expect("Write request 2 on same connection");
    client.flush().expect("Flush request 2");

    let mut len2 = [0u8; 4];
    client.read_exact(&mut len2).expect("Read response 2 len");
    let msg2_len = u32::from_be_bytes(len2) as usize;
    let mut resp2_payload = vec![0u8; msg2_len];
    client.read_exact(&mut resp2_payload).expect("Read response 2 payload");
    assert_eq!(resp2_payload[0], SSH_AGENT_SUCCESS);

    drop(client);
    stop_signal.store(true, Ordering::Relaxed);
    // Connect dummy client to unblock listener if needed
    let _ = OpenOptions::new().read(true).write(true).open(&pipe_name);
    let _ = server_handle.join();
}
