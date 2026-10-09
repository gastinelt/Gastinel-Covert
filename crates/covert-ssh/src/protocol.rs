//! OpenSSH Agent protocol wire framing and data serialization.

use crate::error::SshAgentError;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;

// OpenSSH RSA signature flags
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Low-level frame reader and serializer.
pub struct WireStream;

impl WireStream {
    /// Encode a message frame with 4-byte big-endian length prefix.
    pub fn encode_frame(msg_code: u8, payload: &[u8]) -> Vec<u8> {
        let total_len = (1 + payload.len()) as u32;
        let mut frame = Vec::with_capacity(4 + total_len as usize);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.push(msg_code);
        frame.extend_from_slice(payload);
        frame
    }

    /// Decode a message frame from a byte buffer.
    pub fn decode_frame(data: &[u8]) -> Option<(u8, &[u8])> {
        if data.len() < 5 {
            return None;
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if len == 0 || data.len() < 4 + len {
            return None;
        }
        let msg_code = data[4];
        let payload = &data[5..4 + len];
        Some((msg_code, payload))
    }

    /// Append a 32-bit big-endian integer to the buffer.
    pub fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a length-prefixed byte string to the buffer.
    pub fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
        Self::write_u32(buf, data.len() as u32);
        buf.extend_from_slice(data);
    }

    /// Read a 32-bit big-endian integer from cursor.
    pub fn read_u32(cursor: &mut &[u8]) -> Result<u32, SshAgentError> {
        if cursor.len() < 4 {
            return Err(SshAgentError::ProtocolError("Unexpected EOF reading u32".to_string()));
        }
        let val = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
        *cursor = &cursor[4..];
        Ok(val)
    }

    /// Read a length-prefixed byte string from cursor.
    pub fn read_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], SshAgentError> {
        let len = Self::read_u32(cursor)? as usize;
        if cursor.len() < len {
            return Err(SshAgentError::ProtocolError(format!(
                "Unexpected EOF reading string of length {}",
                len
            )));
        }
        let slice = &cursor[..len];
        *cursor = &cursor[len..];
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_frame() {
        let payload = b"hello open ssh";
        let frame = WireStream::encode_frame(SSH_AGENTC_REQUEST_IDENTITIES, payload);
        let (code, dec_payload) = WireStream::decode_frame(&frame).expect("decode");
        assert_eq!(code, SSH_AGENTC_REQUEST_IDENTITIES);
        assert_eq!(dec_payload, payload);
    }

    #[test]
    fn test_string_serde() {
        let mut buf = Vec::new();
        WireStream::write_string(&mut buf, b"test-key");
        WireStream::write_u32(&mut buf, 42);

        let mut cursor = &buf[..];
        let str_val = WireStream::read_string(&mut cursor).expect("read string");
        let num_val = WireStream::read_u32(&mut cursor).expect("read u32");
        assert_eq!(str_val, b"test-key");
        assert_eq!(num_val, 42);
        assert!(cursor.is_empty());
    }
}
