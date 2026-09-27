use thiserror::Error;

pub type Result<T> = std::result::Result<T, FerusaError>;

#[derive(Debug, Error)]
pub enum FerusaError {
    #[error("invalid recovery file: {reason}")]
    RecoveryFormat { reason: &'static str },

    #[error("recovery file authentication failed")]
    RecoveryAuthentication,

    #[error("invalid recovery credentials: {reason}")]
    RecoveryCredentials { reason: &'static str },

    #[error("crypto error: {operation}: {details}")]
    Crypto {
        operation: &'static str,
        details: String,
    },

    #[error("protocol error: {kind}: {details}")]
    Protocol { kind: &'static str, details: String },

    #[error("pairing error: {kind}: {details}")]
    Pairing { kind: &'static str, details: String },

    #[error("auth error: {kind}: {details}")]
    Auth { kind: &'static str, details: String },

    #[error("network error: {operation}: {details}")]
    Network {
        operation: &'static str,
        details: String,
    },

    #[error("vault error: {kind}: {details}")]
    Vault { kind: &'static str, details: String },

    #[error("storage error: {operation}: {details}")]
    Storage {
        operation: &'static str,
        details: String,
    },

    #[error("input error: {kind}: {details}")]
    Input { kind: &'static str, details: String },

    #[error("internal invariant failed: {details}")]
    Internal { details: String },

    #[error("blob too short: {len} bytes")]
    BlobTooShort { len: usize },

    #[error("unsupported vault blob format: {details}")]
    UnsupportedVaultBlob { details: String },

    #[error("argon2 params: {details}")]
    Argon2Params { details: String },

    #[error("argon2 hash failed: {details}")]
    Argon2Hash { details: String },

    #[error("hkdf expand vault_key: {details}")]
    HkdfExpandVaultKey { details: String },

    #[error("hkdf expand iroh_hmac: {details}")]
    HkdfExpandIrohHmac { details: String },

    #[error("build cipher: {details}")]
    BuildCipher { details: String },

    #[error("encrypt failed: {details}")]
    Encrypt { details: String },

    #[error("decrypt failed (wrong key or tampered): {details}")]
    Decrypt { details: String },

    #[error("message too short")]
    MessageTooShort,

    #[error("message truncated: expected {expected} payload bytes, got {got}")]
    MessageTruncated { expected: usize, got: usize },

    #[error("message has trailing bytes: expected {expected} total bytes, got {got}")]
    MessageTrailingBytes { expected: usize, got: usize },

    #[error("{details}")]
    Json { details: String },
}

impl FerusaError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::RecoveryFormat { .. } => "recovery.format",
            Self::RecoveryAuthentication => "recovery.authentication",
            Self::RecoveryCredentials { .. } => "recovery.credentials",
            Self::Crypto { operation, .. } => match *operation {
                "key_derivation" => "crypto.key_derivation",
                "encrypt" => "crypto.encrypt",
                "decrypt" => "crypto.decrypt",
                "hmac_sign" => "crypto.hmac_sign",
                "hmac_verify" => "crypto.hmac_verify",
                _ => "crypto.failed",
            },
            Self::Protocol { kind, .. } => match *kind {
                "message_too_short" => "protocol.message_too_short",
                "message_truncated" => "protocol.message_truncated",
                "unexpected_variant" => "protocol.unexpected_variant",
                "malformed_auth_request" => "protocol.malformed_auth_request",
                "malformed_auth_response" => "protocol.malformed_auth_response",
                "json" => "protocol.json",
                _ => "protocol.failed",
            },
            Self::Pairing { kind, .. } => match *kind {
                "missing_node_id" => "pairing.missing_node_id",
                "invalid_node_id" => "pairing.invalid_node_id",
                "missing_hmac_key" => "pairing.missing_hmac_key",
                "corrupt_hmac_key" => "pairing.corrupt_hmac_key",
                "unexpected_ack" => "pairing.unexpected_ack",
                _ => "pairing.failed",
            },
            Self::Auth { kind, .. } => match *kind {
                "denied" => "auth.denied",
                "unknown_request" => "auth.unknown_request",
                "hmac_mismatch" => "auth.hmac_mismatch",
                "action_mismatch" => "auth.action_mismatch",
                "correlation_mismatch" => "auth.correlation_mismatch",
                _ => "auth.failed",
            },
            Self::Network { operation, .. } => match *operation {
                "bind" => "network.bind",
                "connect" => "network.connect",
                "handshake" => "network.handshake",
                "stream_open" => "network.stream_open",
                "stream_read" => "network.stream_read",
                "stream_write" => "network.stream_write",
                "stream_finish" => "network.stream_finish",
                "timeout" => "network.timeout",
                _ => "network.failed",
            },
            Self::Vault { kind, .. } => match *kind {
                "not_initialized" => "vault.not_initialized",
                "wrong_password_or_corrupt" => "vault.wrong_password_or_corrupt",
                "corrupt_salt" => "vault.corrupt_salt",
                "corrupt_json" => "vault.corrupt_json",
                "entry_missing" => "vault.entry_missing",
                "entry_duplicate" => "vault.entry_duplicate",
                "entry_vanished" => "vault.entry_vanished",
                _ => "vault.failed",
            },
            Self::Storage { operation, .. } => match *operation {
                "read" => "storage.read",
                "write" => "storage.write",
                "rename" => "storage.rename",
                "delete" => "storage.delete",
                "permission" => "storage.permission",
                "keystore" => "storage.keystore",
                _ => "storage.failed",
            },
            Self::Input { kind, .. } => match *kind {
                "bad_pin" => "input.bad_pin",
                "weak_password" => "input.weak_password",
                "mismatch" => "input.mismatch",
                "empty" => "input.empty",
                _ => "input.invalid",
            },
            Self::Internal { .. } => "internal.invariant",
            Self::BlobTooShort { .. } | Self::UnsupportedVaultBlob { .. } => "crypto.blob_parse",
            Self::Argon2Params { .. } | Self::Argon2Hash { .. } => "crypto.key_derivation",
            Self::HkdfExpandVaultKey { .. } | Self::HkdfExpandIrohHmac { .. } => {
                "crypto.key_derivation"
            }
            Self::BuildCipher { .. } => "crypto.cipher",
            Self::Encrypt { .. } => "crypto.encrypt",
            Self::Decrypt { .. } => "crypto.decrypt",
            Self::MessageTooShort => "protocol.message_too_short",
            Self::MessageTruncated { .. } => "protocol.message_truncated",
            Self::MessageTrailingBytes { .. } => "protocol.message_trailing_bytes",
            Self::Json { .. } => "protocol.json",
        }
    }

    pub fn user_message(&self) -> &'static str {
        match self.code() {
            "recovery.format" => "Recovery file format is unsupported or corrupt.",
            "recovery.authentication" => "Recovery credentials are wrong or the file is corrupt.",
            "recovery.credentials" => "Recovery credentials have an invalid format.",
            "vault.not_initialized" => "Vault is not initialized. Run `ferusa init` first.",
            "vault.wrong_password_or_corrupt" | "crypto.decrypt" => {
                "Wrong password or vault data is corrupt."
            }
            "crypto.blob_parse" => "Vault data format is unsupported or corrupt.",
            "pairing.missing_node_id" | "pairing.missing_hmac_key" => {
                "Phone is not paired. Run `ferusa pair` first."
            }
            "pairing.invalid_node_id" | "pairing.corrupt_hmac_key" => {
                "Pairing data is corrupt. Re-pair with the phone app."
            }
            "auth.denied" => "Authorization was denied on the phone.",
            "auth.hmac_mismatch" | "auth.action_mismatch" | "auth.correlation_mismatch" => {
                "Authorization response failed integrity checks."
            }
            "network.timeout" => "Timed out waiting for the phone.",
            "network.connect" => "Could not connect to the phone.",
            "input.bad_pin" => "PIN is invalid.",
            "input.weak_password" => "Password is too weak.",
            "input.mismatch" => "Values do not match.",
            _ => "Ferusa operation failed.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::FerusaError;

    #[test]
    fn shared_error_codes_are_stable() {
        let cases = [
            (
                FerusaError::Pairing {
                    kind: "invalid_node_id",
                    details: "wrong length".into(),
                },
                "pairing.invalid_node_id",
            ),
            (
                FerusaError::Auth {
                    kind: "hmac_mismatch",
                    details: "bad mac".into(),
                },
                "auth.hmac_mismatch",
            ),
            (
                FerusaError::Network {
                    operation: "timeout",
                    details: "120s".into(),
                },
                "network.timeout",
            ),
            (FerusaError::MessageTooShort, "protocol.message_too_short"),
        ];

        for (err, code) in cases {
            assert_eq!(err.code(), code);
            assert!(!err.user_message().is_empty());
        }
    }
}
