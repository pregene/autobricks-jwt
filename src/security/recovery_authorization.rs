use ring::digest::{SHA256, digest};

use crate::service_error::ServiceError;

const RECOVERY_KEY_BYTES: usize = 32;
const VERIFIER_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryKeyVerifier([u8; VERIFIER_BYTES]);

#[derive(Debug)]
pub struct GeneratedRecoveryKey {
    plaintext_hex: String,
    verifier: RecoveryKeyVerifier,
}

impl GeneratedRecoveryKey {
    pub fn generate() -> Result<Self, ServiceError> {
        let mut key = [0_u8; RECOVERY_KEY_BYTES];
        getrandom::fill(&mut key)
            .map_err(|_| ServiceError::internal("recovery authorization key generation failed"))?;
        let plaintext_hex = encode_hex(&key);
        let verifier = RecoveryKeyVerifier::from_key_bytes(&key);
        key.fill(0);
        Ok(Self {
            plaintext_hex,
            verifier,
        })
    }

    pub fn expose_once(self) -> (String, RecoveryKeyVerifier) {
        (self.plaintext_hex, self.verifier)
    }
}

impl RecoveryKeyVerifier {
    fn from_key_bytes(key: &[u8; RECOVERY_KEY_BYTES]) -> Self {
        let value = digest(&SHA256, key);
        Self(value.as_ref().try_into().expect("SHA-256 is 32 bytes"))
    }

    pub fn from_bytes(bytes: [u8; VERIFIER_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; VERIFIER_BYTES] {
        &self.0
    }

    pub fn verify(&self, submitted_hex: &str) -> Result<(), ServiceError> {
        let submitted = decode_hex_key(submitted_hex).ok_or_else(authorization_failed)?;
        let candidate = Self::from_key_bytes(&submitted);
        let mut difference = 0_u8;
        for (expected, actual) in self.0.iter().zip(candidate.0) {
            difference |= expected ^ actual;
        }
        if difference == 0 {
            Ok(())
        } else {
            Err(authorization_failed())
        }
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_key(value: &str) -> Option<[u8; RECOVERY_KEY_BYTES]> {
    if value.len() != RECOVERY_KEY_BYTES * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let mut decoded = [0_u8; RECOVERY_KEY_BYTES];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(decoded)
}

fn authorization_failed() -> ServiceError {
    ServiceError::invalid_request("recovery authorization failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_256_bit_key_and_retains_only_verifier() {
        let generated = GeneratedRecoveryKey::generate().unwrap();
        let (plaintext, verifier) = generated.expose_once();
        assert_eq!(plaintext.len(), 64);
        assert!(
            plaintext
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_eq!(verifier.as_bytes().len(), 32);
        verifier.verify(&plaintext).unwrap();
    }

    #[test]
    fn rejects_malformed_and_incorrect_keys_with_same_classification() {
        let (plaintext, verifier) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let malformed = verifier.verify("short").unwrap_err();
        let mut incorrect = plaintext;
        incorrect.replace_range(0..2, if &incorrect[0..2] == "00" { "01" } else { "00" });
        let mismatch = verifier.verify(&incorrect).unwrap_err();
        assert_eq!(malformed.code(), 8001);
        assert_eq!(mismatch.code(), 8001);
        assert_eq!(malformed.public_message(), mismatch.public_message());
    }

    #[test]
    fn independent_installations_receive_independent_keys() {
        let (first, _) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        let (second, _) = GeneratedRecoveryKey::generate().unwrap().expose_once();
        assert_ne!(first, second);
    }
}
