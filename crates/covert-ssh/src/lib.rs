//! Gastinel Covert OpenSSH Agent Named Pipe Provider (`covert-ssh`).
//!
//! Provides:
//! - Windows Named Pipe provider on `\\.\pipe\openssh-ssh-agent` with DACL restricted to current user.
//! - OpenSSH Wire protocol encoder/decoder (`SSH_AGENTC_REQUEST_IDENTITIES`, `SSH_AGENTC_SIGN_REQUEST`).
//! - Ed25519 and RSA cryptographic signing engine.
//! - Strict vault lock state machine: immediate refusal with `SSH_AGENT_FAILURE` when locked.
//! - Automatic lock & key zeroization upon receipt of `covert-sentinel` security alerts.

pub mod agent;
pub mod error;
pub mod keys;
pub mod pipe;
pub mod protocol;

pub use agent::SshAgent;
pub use error::SshAgentError;
pub use keys::{build_public_key_blob, SshKeyEntry};
pub use pipe::{run_named_pipe_listener, DEFAULT_SSH_PIPE_NAME};
pub use protocol::{
    WireStream, SSH_AGENTC_ADD_IDENTITY, SSH_AGENTC_REMOVE_ALL_IDENTITIES,
    SSH_AGENTC_REMOVE_IDENTITY, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST,
    SSH_AGENT_FAILURE, SSH_AGENT_IDENTITIES_ANSWER, SSH_AGENT_RSA_SHA2_256,
    SSH_AGENT_RSA_SHA2_512, SSH_AGENT_SIGN_RESPONSE, SSH_AGENT_SUCCESS,
};
