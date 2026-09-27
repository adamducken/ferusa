//! Password-and-PIN protected replacement for one phone share.
//!
//! Parsing the fixed header is deliberately cheap: unknown or oversized files
//! never reach Argon2. The vault itself is never stored in this envelope.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{FerusaError, Result};

pub const RECOVERY_FILE_LEN: usize = 148;
pub const RECOVERY_HEADER_LEN: usize = 60;
pub const MAX_RECOVERY_PASSWORD_BYTES: usize = 65_536;
const PAYLOAD_LEN: usize = 72;
const CIPHERTEXT_LEN: usize = 88;
const MAGIC: &[u8; 8] = b"FERUSBK\0";
const INPUT_DOMAIN: &[u8] = b"ferusa-recovery-input-v1";
const KEY_DOMAIN: &[u8] = b"ferusa-usb-recovery-aead-v1";

pub struct RecoveryMaterial {
    pub file_id: Uuid,
    pub created_at_ms: u64,
    pub pairing_id: Uuid,
    pub phone_share: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for RecoveryMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryMaterial")
            .field("file_id", &self.file_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("pairing_id", &self.pairing_id)
            .field("phone_share", &"[redacted]")
            .finish()
    }
}

fn validate_credentials(password: &[u8], pin4: &str, pin6: &str) -> Result<()> {
    if password.len() > MAX_RECOVERY_PASSWORD_BYTES {
        return Err(FerusaError::RecoveryCredentials {
            reason: "master password exceeds 65536 UTF-8 bytes",
        });
    }
    if pin4.len() != 4 || !pin4.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FerusaError::RecoveryCredentials {
            reason: "phone PIN 1 must be four ASCII digits",
        });
    }
    if pin6.len() != 6 || !pin6.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FerusaError::RecoveryCredentials {
            reason: "phone PIN 2 must be six ASCII digits",
        });
    }
    Ok(())
}

fn derive_key(
    password: &[u8],
    pin4: &str,
    pin6: &str,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    validate_credentials(password, pin4, pin6)?;
    let password_len =
        u32::try_from(password.len()).map_err(|_| FerusaError::RecoveryCredentials {
            reason: "master password length is unsupported",
        })?;
    let mut input = Zeroizing::new(Vec::with_capacity(
        INPUT_DOMAIN.len() + 4 + password.len() + 10,
    ));
    input.extend_from_slice(INPUT_DOMAIN);
    input.extend_from_slice(&password_len.to_le_bytes());
    input.extend_from_slice(password);
    input.extend_from_slice(pin4.as_bytes());
    input.extend_from_slice(pin6.as_bytes());

    let params = Params::new(65_536, 3, 1, Some(64)).map_err(|e| FerusaError::Argon2Params {
        details: e.to_string(),
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut intermediate = Zeroizing::new([0u8; 64]);
    argon2
        .hash_password_into(&input, salt, &mut *intermediate)
        .map_err(|e| FerusaError::Argon2Hash {
            details: e.to_string(),
        })?;
    let mut key = Zeroizing::new([0u8; 32]);
    // hkdf 0.12 does not advertise zeroizing drop for internal state.
    Hkdf::<Sha256>::new(None, &*intermediate)
        .expand(KEY_DOMAIN, &mut *key)
        .map_err(|e| FerusaError::HkdfExpandVaultKey {
            details: e.to_string(),
        })?;
    Ok(key)
}

fn checked_header(bytes: &[u8]) -> Result<&[u8]> {
    if bytes.len() != RECOVERY_FILE_LEN {
        return Err(FerusaError::RecoveryFormat {
            reason: "expected exactly 148 bytes",
        });
    }
    if &bytes[..8] != MAGIC {
        return Err(FerusaError::RecoveryFormat {
            reason: "bad magic",
        });
    }
    if u16::from_le_bytes([bytes[8], bytes[9]]) != 1 {
        return Err(FerusaError::RecoveryFormat {
            reason: "unsupported version",
        });
    }
    if u16::from_le_bytes([bytes[10], bytes[11]]) != 1 {
        return Err(FerusaError::RecoveryFormat {
            reason: "unsupported crypto profile",
        });
    }
    if u64::from_le_bytes(bytes[52..60].try_into().expect("fixed header")) != CIPHERTEXT_LEN as u64
    {
        return Err(FerusaError::RecoveryFormat {
            reason: "invalid ciphertext length",
        });
    }
    Ok(&bytes[..RECOVERY_HEADER_LEN])
}

pub fn validate_recovery_envelope(bytes: &[u8]) -> Result<()> {
    checked_header(bytes).map(|_| ())
}

fn seal_with_randomness(
    material: &RecoveryMaterial,
    password: &[u8],
    pin4: &str,
    pin6: &str,
    salt: [u8; 16],
    nonce: [u8; 24],
) -> Result<[u8; RECOVERY_FILE_LEN]> {
    if material.file_id.is_nil() || material.pairing_id.is_nil() {
        return Err(FerusaError::RecoveryFormat {
            reason: "nil recovery or pairing ID",
        });
    }
    let key = derive_key(password, pin4, pin6, &salt)?;
    let mut output = [0u8; RECOVERY_FILE_LEN];
    output[..8].copy_from_slice(MAGIC);
    output[8..10].copy_from_slice(&1u16.to_le_bytes());
    output[10..12].copy_from_slice(&1u16.to_le_bytes());
    output[12..28].copy_from_slice(&salt);
    output[28..52].copy_from_slice(&nonce);
    output[52..60].copy_from_slice(&(CIPHERTEXT_LEN as u64).to_le_bytes());
    let mut plaintext = Zeroizing::new([0u8; PAYLOAD_LEN]);
    plaintext[..16].copy_from_slice(material.file_id.as_bytes());
    plaintext[16..24].copy_from_slice(&material.created_at_ms.to_le_bytes());
    plaintext[24..40].copy_from_slice(material.pairing_id.as_bytes());
    plaintext[40..72].copy_from_slice(&*material.phone_share);
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*key).map_err(|e| FerusaError::BuildCipher {
            details: e.to_string(),
        })?;
    let ciphertext = Zeroizing::new(
        cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &*plaintext,
                    aad: &output[..RECOVERY_HEADER_LEN],
                },
            )
            .map_err(|e| FerusaError::Encrypt {
                details: e.to_string(),
            })?,
    );
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(FerusaError::Internal {
            details: "unexpected recovery ciphertext length".into(),
        });
    }
    output[RECOVERY_HEADER_LEN..].copy_from_slice(&ciphertext);
    Ok(output)
}

pub fn seal_recovery(
    material: &RecoveryMaterial,
    password: &[u8],
    pin4: &str,
    pin6: &str,
) -> Result<[u8; RECOVERY_FILE_LEN]> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rng().fill_bytes(&mut salt);
    rand::rng().fill_bytes(&mut nonce);
    let result = seal_with_randomness(material, password, pin4, pin6, salt, nonce);
    salt.zeroize();
    nonce.zeroize();
    result
}

pub fn open_recovery(
    bytes: &[u8],
    password: &[u8],
    pin4: &str,
    pin6: &str,
) -> Result<RecoveryMaterial> {
    let header = checked_header(bytes)?;
    let salt: [u8; 16] = header[12..28].try_into().expect("fixed header");
    let key = derive_key(password, pin4, pin6, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(&*key).map_err(|e| FerusaError::BuildCipher {
            details: e.to_string(),
        })?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&header[28..52]),
                Payload {
                    msg: &bytes[RECOVERY_HEADER_LEN..],
                    aad: header,
                },
            )
            .map_err(|_| FerusaError::RecoveryAuthentication)?,
    );
    if plaintext.len() != PAYLOAD_LEN {
        return Err(FerusaError::RecoveryFormat {
            reason: "invalid authenticated payload size",
        });
    }
    let file_id = Uuid::from_slice(&plaintext[..16]).expect("fixed payload");
    let pairing_id = Uuid::from_slice(&plaintext[24..40]).expect("fixed payload");
    if file_id.is_nil() || pairing_id.is_nil() {
        return Err(FerusaError::RecoveryFormat {
            reason: "nil recovery or pairing ID",
        });
    }
    let mut phone_share = Zeroizing::new([0u8; 32]);
    phone_share.copy_from_slice(&plaintext[40..72]);
    Ok(RecoveryMaterial {
        file_id,
        created_at_ms: u64::from_le_bytes(plaintext[16..24].try_into().expect("fixed payload")),
        pairing_id,
        phone_share,
    })
}

pub fn recovery_file_digest(bytes: &[u8; RECOVERY_FILE_LEN]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn recovery_vault_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub const MAX_RECOVERY_FRAME_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPurpose {
    Create,
    ConfirmExisting,
    InitialSetup,
    PasswordChange,
    PairingChange,
    LostPhoneRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBegin {
    pub request_id: Uuid,
    pub pairing_id: Uuid,
    pub purpose: RecoveryPurpose,
    pub transaction_id: Option<Uuid>,
    pub credential_revision: Uuid,
    pub file_id: Option<Uuid>,
    pub expected_envelope_digest: Option<[u8; 32]>,
    pub vault_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub correlation_code: u16,
    pub timestamp_ms: u64,
}

impl RecoveryBegin {
    pub fn validate(&self) -> Result<()> {
        if self.request_id.is_nil()
            || self.pairing_id.is_nil()
            || self.credential_revision.is_nil()
            || self.file_id.is_some_and(|id| id.is_nil())
            || self.transaction_id.is_some_and(|id| id.is_nil())
        {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "nil identifier".into(),
            });
        }
        let candidate = matches!(
            self.purpose,
            RecoveryPurpose::InitialSetup
                | RecoveryPurpose::PasswordChange
                | RecoveryPurpose::PairingChange
                | RecoveryPurpose::LostPhoneRecovery
        );
        if candidate != self.transaction_id.is_some() {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "transaction identity does not match purpose".into(),
            });
        }
        if self.purpose == RecoveryPurpose::ConfirmExisting
            && self.expected_envelope_digest.is_none()
        {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "confirmation requires envelope digest".into(),
            });
        }
        if self.purpose != RecoveryPurpose::ConfirmExisting && self.file_id.is_none() {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "new file or candidate requires an ID".into(),
            });
        }
        if self.purpose == RecoveryPurpose::Create && self.expected_envelope_digest.is_some() {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "new file cannot declare a prior digest".into(),
            });
        }
        if !(1000..=9999).contains(&self.correlation_code) || self.nonce == [0; 32] {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "invalid correlation or challenge".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryContext {
    pub begin: RecoveryBegin,
    pub instance_id: Uuid,
    pub desktop_id: [u8; 32],
    pub phone_challenge: [u8; 32],
    pub phone_session_generation: u64,
}

impl RecoveryContext {
    pub fn validate(&self) -> Result<()> {
        self.begin.validate()?;
        if self.instance_id.is_nil()
            || self.desktop_id == [0; 32]
            || self.phone_challenge == [0; 32]
        {
            return Err(FerusaError::Protocol {
                kind: "malformed_recovery",
                details: "invalid phone-bound context".into(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConsent {
    pub context: RecoveryContext,
    pub timestamp_ms: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RecoveryPins {
    #[zeroize(skip)]
    pub instance_id: Uuid,
    #[zeroize(skip)]
    pub request_id: Uuid,
    pub challenge: [u8; 32],
    pub pin4: String,
    pub pin6: String,
}

impl fmt::Debug for RecoveryPins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryPins")
            .field("request_id", &self.request_id)
            .field("instance_id", &self.instance_id)
            .field("pin4", &"[redacted]")
            .field("pin6", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct RecoveryAuthorized {
    #[zeroize(skip)]
    pub context: RecoveryContext,
    pub phone_share: [u8; 32],
    #[zeroize(skip)]
    pub timestamp_ms: u64,
    #[zeroize(skip)]
    pub signature: Vec<u8>,
}

impl fmt::Debug for RecoveryAuthorized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryAuthorized")
            .field("request_id", &self.context.begin.request_id)
            .field("phone_share", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFinish {
    pub instance_id: Uuid,
    pub request_id: Uuid,
    pub challenge: [u8; 32],
    pub file_id: Uuid,
    pub envelope_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFinished {
    pub context: RecoveryContext,
    pub file_id: Uuid,
    pub envelope_digest: [u8; 32],
    pub timestamp_ms: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCancel {
    pub instance_id: Uuid,
    pub request_id: Uuid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryRejectCode {
    Denied,
    Busy,
    Expired,
    Cooldown,
    Protocol,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRejected {
    pub request_id: Uuid,
    pub code: RecoveryRejectCode,
    pub retry_after_ms: Option<u64>,
}

#[derive(Serialize)]
struct SignedRecovery<'a, T: Serialize> {
    domain: &'static str,
    version: u8,
    context: &'a RecoveryContext,
    response: T,
}

#[derive(Serialize)]
struct ConsentFields {
    timestamp_ms: u64,
}

#[derive(Serialize)]
struct AuthorizedFields<'a> {
    phone_share: &'a [u8; 32],
    timestamp_ms: u64,
}

#[derive(Serialize)]
struct FinishedFields {
    file_id: Uuid,
    envelope_digest: [u8; 32],
    timestamp_ms: u64,
}

fn serialize_signed<T: Serialize>(
    domain: &'static str,
    context: &RecoveryContext,
    response: T,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    serde_json::to_writer(
        &mut *out,
        &SignedRecovery {
            domain,
            version: 1,
            context,
            response,
        },
    )
    .map_err(|e| FerusaError::Json {
        details: e.to_string(),
    })?;
    Ok(out)
}

pub fn canonical_recovery_consent(response: &RecoveryConsent) -> Result<Zeroizing<Vec<u8>>> {
    serialize_signed(
        "ferusa-recovery-consent",
        &response.context,
        ConsentFields {
            timestamp_ms: response.timestamp_ms,
        },
    )
}

pub fn canonical_recovery_authorized(response: &RecoveryAuthorized) -> Result<Zeroizing<Vec<u8>>> {
    serialize_signed(
        "ferusa-recovery-authorized",
        &response.context,
        AuthorizedFields {
            phone_share: &response.phone_share,
            timestamp_ms: response.timestamp_ms,
        },
    )
}

pub fn canonical_recovery_finished(response: &RecoveryFinished) -> Result<Zeroizing<Vec<u8>>> {
    serialize_signed(
        "ferusa-recovery-finished",
        &response.context,
        FinishedFields {
            file_id: response.file_id,
            envelope_digest: response.envelope_digest,
            timestamp_ms: response.timestamp_ms,
        },
    )
}

pub fn verify_recovery_signature(public_key_der: &[u8], payload: &[u8], signature: &[u8]) -> bool {
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_der)
        .verify(payload, signature)
        .is_ok()
}

pub fn checked_recovery_frame_len(prefix: [u8; 4]) -> Result<usize> {
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 || length > MAX_RECOVERY_FRAME_BYTES {
        return Err(FerusaError::Protocol {
            kind: "recovery_frame_size",
            details: "recovery frame exceeds 4096-byte limit or is empty".into(),
        });
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };

    fn material() -> RecoveryMaterial {
        RecoveryMaterial {
            file_id: Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            created_at_ms: 1_700_000_000_123,
            pairing_id: Uuid::parse_str("10213243-5465-7687-98a9-bacbdcedfe0f").unwrap(),
            phone_share: Zeroizing::new([0x5a; 32]),
        }
    }

    #[test]
    fn exact_format_round_trip_and_credential_failures() {
        let bytes = seal_with_randomness(
            &material(),
            " passé ".as_bytes(),
            "0012",
            "000345",
            [7; 16],
            [9; 24],
        )
        .unwrap();
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            encoded,
            concat!(
                "4645525553424b000100010007070707070707070707070707070707",
                "0909090909090909090909090909090909090909090909095800000000000000",
                "c423def1753224ef3f3293363d08db5846fcab1a29dab202236c3606021a868d",
                "9b05910ea876a103fd5500ecf1f6cacd2da6f17333b1ad7473907256b2143a5e",
                "24e969f2f10cd55c182bc7e3e3ea2b96a6b6b8fc18484d0a"
            )
        );
        assert_eq!(bytes.len(), 148);
        assert_eq!(&bytes[..8], MAGIC);
        assert_eq!(&bytes[8..12], &[1, 0, 1, 0]);
        assert_eq!(&bytes[12..28], &[7; 16]);
        assert_eq!(&bytes[28..52], &[9; 24]);
        assert_eq!(&bytes[52..60], &88u64.to_le_bytes());
        let opened = open_recovery(&bytes, " passé ".as_bytes(), "0012", "000345").unwrap();
        assert_eq!(opened.file_id, material().file_id);
        assert_eq!(opened.pairing_id, material().pairing_id);
        assert_eq!(opened.created_at_ms, material().created_at_ms);
        assert_eq!(&*opened.phone_share, &[0x5a; 32]);
        for (password, pin4, pin6) in [
            ("passé ", "0012", "000345"),
            (" passé ", "0013", "000345"),
            (" passé ", "0012", "000346"),
        ] {
            assert!(matches!(
                open_recovery(&bytes, password.as_bytes(), pin4, pin6),
                Err(FerusaError::RecoveryAuthentication)
            ));
        }
    }

    #[test]
    fn malformed_header_rejected_before_credentials() {
        let original =
            seal_with_randomness(&material(), b"p", "0000", "000000", [7; 16], [9; 24]).unwrap();
        for index in [0, 8, 10, 52] {
            let mut bytes = original;
            bytes[index] ^= 1;
            assert!(matches!(
                open_recovery(&bytes, b"p", "bad", "bad"),
                Err(FerusaError::RecoveryFormat { .. })
            ));
        }
        for bytes in [&original[..59], &original[..147], &[0u8; 149][..]] {
            assert!(matches!(
                open_recovery(bytes, b"p", "bad", "bad"),
                Err(FerusaError::RecoveryFormat { .. })
            ));
        }
        for index in [12, 28, 60, 147] {
            let mut bytes = original;
            bytes[index] ^= 1;
            assert!(matches!(
                open_recovery(&bytes, b"p", "0000", "000000"),
                Err(FerusaError::RecoveryAuthentication)
            ));
        }
    }

    #[test]
    fn credentials_are_bounded_and_debug_redacted() {
        assert!(matches!(
            seal_recovery(&material(), b"p", "01x2", "000000"),
            Err(FerusaError::RecoveryCredentials { .. })
        ));
        assert!(matches!(
            seal_recovery(
                &material(),
                &vec![b'x'; MAX_RECOVERY_PASSWORD_BYTES + 1],
                "0000",
                "000000"
            ),
            Err(FerusaError::RecoveryCredentials { .. })
        ));
        assert!(!format!("{:?}", material()).contains("5a"));
    }

    fn begin(purpose: RecoveryPurpose) -> RecoveryBegin {
        RecoveryBegin {
            request_id: Uuid::from_u128(1),
            pairing_id: Uuid::from_u128(2),
            purpose,
            transaction_id: None,
            credential_revision: Uuid::from_u128(3),
            file_id: Some(Uuid::from_u128(4)),
            expected_envelope_digest: None,
            vault_digest: [5; 32],
            nonce: [6; 32],
            correlation_code: 1234,
            timestamp_ms: 1_700_000_000_000,
        }
    }

    fn context() -> RecoveryContext {
        RecoveryContext {
            begin: begin(RecoveryPurpose::Create),
            instance_id: Uuid::from_u128(7),
            desktop_id: [8; 32],
            phone_challenge: [9; 32],
            phone_session_generation: 10,
        }
    }

    #[test]
    fn purpose_and_digest_combinations_are_checked() {
        let mut request = begin(RecoveryPurpose::Create);
        assert!(request.validate().is_ok());
        request.expected_envelope_digest = Some([11; 32]);
        assert!(request.validate().is_err());

        request.purpose = RecoveryPurpose::ConfirmExisting;
        request.file_id = None;
        assert!(request.validate().is_ok());
        request.expected_envelope_digest = None;
        assert!(request.validate().is_err());

        request.purpose = RecoveryPurpose::PasswordChange;
        request.transaction_id = Some(Uuid::from_u128(12));
        request.file_id = Some(Uuid::from_u128(4));
        assert!(request.validate().is_ok());
        request.expected_envelope_digest = Some([11; 32]);
        assert!(request.validate().is_ok());
        request.transaction_id = None;
        assert!(request.validate().is_err());

        let mut bound = context();
        assert!(bound.validate().is_ok());
        bound.phone_challenge = [0; 32];
        assert!(bound.validate().is_err());
    }

    #[test]
    fn signed_transcripts_bind_each_security_field() {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, key.as_ref(), &rng).unwrap();
        let public_key = key.public_key().as_ref();

        let mut consent = RecoveryConsent {
            context: context(),
            timestamp_ms: 1_700_000_000_001,
            signature: Vec::new(),
        };
        let consent_payload = canonical_recovery_consent(&consent).unwrap();
        consent.signature = key.sign(&rng, &consent_payload).unwrap().as_ref().to_vec();
        assert!(verify_recovery_signature(
            public_key,
            &consent_payload,
            &consent.signature
        ));
        consent.context.begin.vault_digest[0] ^= 1;
        assert!(!verify_recovery_signature(
            public_key,
            &canonical_recovery_consent(&consent).unwrap(),
            &consent.signature
        ));

        let mut authorized = RecoveryAuthorized {
            context: context(),
            phone_share: [13; 32],
            timestamp_ms: 1_700_000_000_002,
            signature: Vec::new(),
        };
        let authorized_payload = canonical_recovery_authorized(&authorized).unwrap();
        authorized.signature = key
            .sign(&rng, &authorized_payload)
            .unwrap()
            .as_ref()
            .to_vec();
        assert!(verify_recovery_signature(
            public_key,
            &authorized_payload,
            &authorized.signature
        ));
        authorized.phone_share[0] ^= 1;
        assert!(!verify_recovery_signature(
            public_key,
            &canonical_recovery_authorized(&authorized).unwrap(),
            &authorized.signature
        ));
        assert!(!format!("{authorized:?}").contains("13"));

        let mut finished = RecoveryFinished {
            context: context(),
            file_id: Uuid::from_u128(4),
            envelope_digest: [14; 32],
            timestamp_ms: 1_700_000_000_003,
            signature: Vec::new(),
        };
        let finished_payload = canonical_recovery_finished(&finished).unwrap();
        finished.signature = key.sign(&rng, &finished_payload).unwrap().as_ref().to_vec();
        assert!(verify_recovery_signature(
            public_key,
            &finished_payload,
            &finished.signature
        ));
        finished.envelope_digest[0] ^= 1;
        assert!(!verify_recovery_signature(
            public_key,
            &canonical_recovery_finished(&finished).unwrap(),
            &finished.signature
        ));
    }

    #[test]
    fn recovery_frame_length_is_bounded_before_allocation() {
        assert!(checked_recovery_frame_len(1u32.to_le_bytes()).is_ok());
        assert!(checked_recovery_frame_len(4096u32.to_le_bytes()).is_ok());
        assert!(checked_recovery_frame_len(0u32.to_le_bytes()).is_err());
        assert!(checked_recovery_frame_len(4097u32.to_le_bytes()).is_err());
        assert!(checked_recovery_frame_len(u32::MAX.to_le_bytes()).is_err());
    }
}
