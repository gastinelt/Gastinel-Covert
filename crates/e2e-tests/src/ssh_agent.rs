//! OpenSSH Agent protocol frame encoder, decoder, and lifecycle simulator.

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

#[derive(Debug, PartialEq, Eq)]
pub enum SshAgentMessage {
    RequestIdentities,
    IdentitiesAnswer { keys_count: u32 },
    SignRequest { key_blob: Vec<u8>, data: Vec<u8> },
    SignResponse { signature: Vec<u8> },
    Failure,
}

pub struct SshAgentWire;

impl SshAgentWire {
    /// Encode a message frame with 4-byte big-endian length prefix.
    pub fn encode_frame(msg_code: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = (1 + payload.len()) as u32;
        let mut frame = Vec::with_capacity(4 + total_len as usize);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.push(msg_code);
        frame.extend_from_slice(payload);
        frame
    }

    /// Decode a message frame.
    pub fn decode_frame(data: &[u8]) -> Option<(u8, &[u8])> {
        if data.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return None;
        }
        let msg_code = data[4];
        let payload = &data[5..4 + len];
        Some((msg_code, payload))
    }

    /// Simulate agent request processing.
    pub fn process_request(is_vault_unlocked: bool, request_bytes: &[u8]) -> Vec<u8> {
        if !is_vault_unlocked {
            // When locked, agent unconditionally fails
            return Self::encode_frame(SSH_AGENT_FAILURE, &[]);
        }

        if let Some((code, _payload)) = Self::decode_frame(request_bytes) {
            match code {
                SSH_AGENTC_REQUEST_IDENTITIES => {
                    // Return answer with 1 key
                    let mut payload = Vec::new();
                    payload.extend_from_slice(&1u32.to_be_bytes()); // 1 key
                    Self::encode_frame(SSH_AGENT_IDENTITIES_ANSWER, &payload)
                }
                SSH_AGENTC_SIGN_REQUEST => {
                    // Return mock signature
                    let signature = b"test_ed25519_signature_bytes";
                    Self::encode_frame(SSH_AGENT_SIGN_RESPONSE, signature)
                }
                _ => Self::encode_frame(SSH_AGENT_FAILURE, &[]),
            }
        } else {
            Self::encode_frame(SSH_AGENT_FAILURE, &[])
        }
    }
}
