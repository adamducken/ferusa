//! Public enrollment bindings and recovery-aware generation transitions.
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::PairingHello;
use crate::error::{FerusaError, Result};
use crate::recovery::{RecoveryFinished, RecoveryPurpose};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentContext {
    pub version: u8,
    pub desktop_id: [u8; 32],
    pub transaction_id: Uuid,
    pub purpose: RecoveryPurpose,
    pub credential_revision: Uuid,
}

impl EnrollmentContext {
    pub fn validate(&self) -> Result<()> {
        if self.version != 5
            || self.desktop_id == [0; 32]
            || self.transaction_id.is_nil()
            || self.credential_revision.is_nil()
            || !matches!(
                self.purpose,
                RecoveryPurpose::InitialSetup
                    | RecoveryPurpose::PairingChange
                    | RecoveryPurpose::LostPhoneRecovery
            )
        {
            return Err(FerusaError::Protocol {
                kind: "enrollment",
                details: "invalid v5 enrollment context".into(),
            });
        }
        Ok(())
    }

    pub fn parse_token(token: &str) -> Result<Self> {
        if token.len() > 2048 {
            return Err(FerusaError::Protocol {
                kind: "enrollment",
                details: "enrollment token exceeds 2048 bytes".into(),
            });
        }
        let context: Self = serde_json::from_str(token).map_err(|_| FerusaError::Protocol {
            kind: "enrollment",
            details: "paste the full v5 enrollment token from the CLI".into(),
        })?;
        context.validate()?;
        Ok(context)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentHello {
    pub context: EnrollmentContext,
    pub hello: PairingHello,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentPrepared {
    pub context: EnrollmentContext,
    pub pairing_id: Uuid,
    pub vault_digest: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentReady {
    pub prepared: EnrollmentPrepared,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReference {
    pub transaction_id: Uuid,
    pub pairing_id: Uuid,
    pub credential_revision: Uuid,
    pub vault_digest: [u8; 32],
    pub file_id: Uuid,
    pub envelope_digest: [u8; 32],
}

impl RecoveryReference {
    pub fn from_finished(finished: &RecoveryFinished) -> Result<Self> {
        finished.context.validate()?;
        let begin = &finished.context.begin;
        let transaction_id = begin.transaction_id.ok_or_else(|| FerusaError::Protocol {
            kind: "enrollment",
            details: "candidate recovery receipt has no transaction".into(),
        })?;
        if finished.file_id.is_nil()
            || begin.file_id != Some(finished.file_id)
            || begin
                .expected_envelope_digest
                .is_some_and(|digest| digest != finished.envelope_digest)
        {
            return Err(FerusaError::Protocol {
                kind: "enrollment",
                details: "recovery receipt file binding mismatch".into(),
            });
        }
        Ok(Self {
            transaction_id,
            pairing_id: begin.pairing_id,
            credential_revision: begin.credential_revision,
            vault_digest: begin.vault_digest,
            file_id: finished.file_id,
            envelope_digest: finished.envelope_digest,
        })
    }

    pub fn matches(&self, prepared: &EnrollmentPrepared) -> bool {
        self.transaction_id == prepared.context.transaction_id
            && self.pairing_id == prepared.pairing_id
            && self.credential_revision == prepared.context.credential_revision
            && self.vault_digest == prepared.vault_digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentTransition {
    pub pairing_id: Uuid,
    pub recovery: RecoveryReference,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentActivated {
    pub transition: EnrollmentTransition,
    pub signature: Vec<u8>,
}

fn canonical<T: Serialize>(domain: &'static str, value: &T) -> Result<Zeroizing<Vec<u8>>> {
    #[derive(Serialize)]
    struct Transcript<'a, T> {
        domain: &'static str,
        version: u8,
        value: &'a T,
    }
    let mut bytes = Zeroizing::new(Vec::new());
    serde_json::to_writer(
        &mut *bytes,
        &Transcript {
            domain,
            version: 1,
            value,
        },
    )
    .map_err(|e| FerusaError::Json {
        details: e.to_string(),
    })?;
    Ok(bytes)
}

pub fn canonical_enrollment_ready(prepared: &EnrollmentPrepared) -> Result<Zeroizing<Vec<u8>>> {
    prepared.context.validate()?;
    canonical("ferusa-enrollment-ready-v5", prepared)
}

pub fn canonical_enrollment_activated(
    transition: &EnrollmentTransition,
) -> Result<Zeroizing<Vec<u8>>> {
    canonical("ferusa-enrollment-activated-v5", transition)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{verify_recovery_signature, RecoveryBegin, RecoveryContext};
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING},
    };

    fn prepared() -> EnrollmentPrepared {
        EnrollmentPrepared {
            context: EnrollmentContext {
                version: 5,
                desktop_id: [3; 32],
                transaction_id: Uuid::new_v4(),
                purpose: RecoveryPurpose::LostPhoneRecovery,
                credential_revision: Uuid::new_v4(),
            },
            pairing_id: Uuid::new_v4(),
            vault_digest: [4; 32],
        }
    }
    fn signer() -> EcdsaKeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap()
    }

    #[test]
    fn enrollment_token_requires_exact_v5_transaction_identity() {
        let original = prepared().context;
        assert_eq!(
            EnrollmentContext::parse_token(&serde_json::to_string(&original).unwrap()).unwrap(),
            original
        );
        let mut invalid = original.clone();
        invalid.version = 4;
        assert!(invalid.validate().is_err());
        invalid = original.clone();
        invalid.transaction_id = Uuid::nil();
        assert!(invalid.validate().is_err());
        invalid = original.clone();
        invalid.desktop_id = [0; 32];
        assert!(invalid.validate().is_err());
        invalid = original;
        invalid.purpose = RecoveryPurpose::Create;
        assert!(invalid.validate().is_err());
        assert!(EnrollmentContext::parse_token(&" ".repeat(2049)).is_err());
        assert!(EnrollmentContext::parse_token(&"a".repeat(64)).is_err());
    }

    #[test]
    fn ready_signature_binds_every_enrollment_and_vault_field() {
        let original = prepared();
        let key = signer();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &canonical_enrollment_ready(&original).unwrap(),
            )
            .unwrap();
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.context.desktop_id[0] ^= 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.context.transaction_id = Uuid::new_v4();
        variants.push(changed);
        let mut changed = original.clone();
        changed.context.credential_revision = Uuid::new_v4();
        variants.push(changed);
        let mut changed = original.clone();
        changed.context.purpose = RecoveryPurpose::InitialSetup;
        variants.push(changed);
        let mut changed = original.clone();
        changed.pairing_id = Uuid::new_v4();
        variants.push(changed);
        let mut changed = original.clone();
        changed.vault_digest[0] ^= 1;
        variants.push(changed);
        assert!(verify_recovery_signature(
            key.public_key().as_ref(),
            &canonical_enrollment_ready(&original).unwrap(),
            signature.as_ref()
        ));
        for changed in variants {
            assert!(!verify_recovery_signature(
                key.public_key().as_ref(),
                &canonical_enrollment_ready(&changed).unwrap(),
                signature.as_ref()
            ));
        }
    }

    #[test]
    fn activation_requires_the_exact_confirmed_recovery_reference() {
        let prepared = prepared();
        let file_id = Uuid::new_v4();
        let finished = RecoveryFinished {
            context: RecoveryContext {
                begin: RecoveryBegin {
                    request_id: Uuid::new_v4(),
                    pairing_id: prepared.pairing_id,
                    purpose: prepared.context.purpose,
                    transaction_id: Some(prepared.context.transaction_id),
                    credential_revision: prepared.context.credential_revision,
                    file_id: Some(file_id),
                    expected_envelope_digest: Some([8; 32]),
                    vault_digest: prepared.vault_digest,
                    nonce: [5; 32],
                    correlation_code: 1234,
                    timestamp_ms: 1,
                },
                instance_id: Uuid::new_v4(),
                desktop_id: prepared.context.desktop_id,
                phone_challenge: [6; 32],
                phone_session_generation: 7,
            },
            file_id,
            envelope_digest: [8; 32],
            timestamp_ms: 2,
            signature: Vec::new(),
        };
        let reference = RecoveryReference::from_finished(&finished).unwrap();
        assert!(reference.matches(&prepared));
        let mut invalid = finished.clone();
        invalid.file_id = Uuid::new_v4();
        assert!(RecoveryReference::from_finished(&invalid).is_err());
        invalid = finished;
        invalid.envelope_digest[0] ^= 1;
        assert!(RecoveryReference::from_finished(&invalid).is_err());
        let transition = EnrollmentTransition {
            pairing_id: prepared.pairing_id,
            recovery: reference,
        };
        let key = signer();
        let signature = key
            .sign(
                &SystemRandom::new(),
                &canonical_enrollment_activated(&transition).unwrap(),
            )
            .unwrap();
        for field in 0..7 {
            let mut changed = transition.clone();
            match field {
                0 => changed.pairing_id = Uuid::new_v4(),
                1 => changed.recovery.pairing_id = Uuid::new_v4(),
                2 => changed.recovery.transaction_id = Uuid::new_v4(),
                3 => changed.recovery.credential_revision = Uuid::new_v4(),
                4 => changed.recovery.vault_digest[0] ^= 1,
                5 => changed.recovery.file_id = Uuid::new_v4(),
                _ => changed.recovery.envelope_digest[0] ^= 1,
            }
            assert!(!verify_recovery_signature(
                key.public_key().as_ref(),
                &canonical_enrollment_activated(&changed).unwrap(),
                signature.as_ref()
            ));
        }
        assert!(!verify_recovery_signature(
            key.public_key().as_ref(),
            &canonical_enrollment_ready(&prepared).unwrap(),
            signature.as_ref()
        ));
    }
}
