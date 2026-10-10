use std::{collections::BTreeSet, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::service_error::ServiceError;

const IV_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptionProfile {
    A128Gcm,
    A192Gcm,
    A256Gcm,
}

impl EncryptionProfile {
    pub fn from_registration(value: &str) -> Result<Self, ServiceError> {
        match value {
            "JWE_DIR_A128GCM" => Ok(Self::A128Gcm),
            "JWE_DIR_A192GCM" => Ok(Self::A192Gcm),
            "JWE_DIR_A256GCM" => Ok(Self::A256Gcm),
            _ => Err(ServiceError::configuration_invalid(
                "the registered encryption profile is not available",
            )),
        }
    }

    fn enc(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    pub(crate) fn encryption_name(self) -> &'static str {
        self.enc()
    }

    fn key_length(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
            Self::A256Gcm => 32,
        }
    }

    fn cipher(self) -> Cipher {
        match self {
            Self::A128Gcm => Cipher::aes_128_gcm(),
            Self::A192Gcm => Cipher::aes_192_gcm(),
            Self::A256Gcm => Cipher::aes_256_gcm(),
        }
    }

    fn from_enc(value: &str) -> Result<Self, ServiceError> {
        match value {
            "A128GCM" => Ok(Self::A128Gcm),
            "A192GCM" => Ok(Self::A192Gcm),
            "A256GCM" => Ok(Self::A256Gcm),
            _ => Err(ServiceError::jwt_invalid("JWE encryption is not permitted")),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ProtectedHeader {
    alg: String,
    enc: String,
    typ: String,
    kid: Uuid,
}

#[derive(Debug)]
pub struct IssuedToken {
    pub token_id: Uuid,
    pub token: String,
    pub(crate) kid: Uuid,
    pub(crate) key: Vec<u8>,
    pub(crate) profile: EncryptionProfile,
    pub(crate) iv: [u8; IV_LENGTH],
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenPayload {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    nbf: u64,
    exp: u64,
    jti: Uuid,
    subject_type: String,
    claims: Map<String, Value>,
}

impl IssuedToken {
    pub fn issue(
        issuer: &str,
        audience: &str,
        subject: &str,
        claims: Map<String, Value>,
        issued_at: u64,
        lifetime: Duration,
    ) -> Result<Self, ServiceError> {
        if issuer.is_empty() || audience.is_empty() || subject.is_empty() {
            return Err(ServiceError::invalid_subject(
                "issuer, audience, and subject are required",
            ));
        }

        let token_id = Uuid::new_v4();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs())
            .ok_or_else(|| ServiceError::jwt_encryption_failed("token expiration overflowed"))?;
        let payload = TokenPayload {
            iss: issuer.to_owned(),
            sub: subject.to_owned(),
            aud: audience.to_owned(),
            iat: issued_at,
            nbf: issued_at,
            exp: expires_at,
            jti: token_id,
            subject_type: "USER".to_owned(),
            claims,
        };
        Self::encrypt_payload(payload, EncryptionProfile::A256Gcm)
    }

    pub fn issue_with_profile(
        issuer: &str,
        audience: &str,
        subject: &str,
        claims: Map<String, Value>,
        issued_at: u64,
        lifetime: Duration,
        profile: EncryptionProfile,
    ) -> Result<Self, ServiceError> {
        if issuer.is_empty() || audience.is_empty() || subject.is_empty() {
            return Err(ServiceError::invalid_subject(
                "issuer, audience, and subject are required",
            ));
        }
        let token_id = Uuid::new_v4();
        let expires_at = issued_at
            .checked_add(lifetime.as_secs())
            .ok_or_else(|| ServiceError::jwt_encryption_failed("token expiration overflowed"))?;
        Self::encrypt_payload(
            TokenPayload {
                iss: issuer.into(),
                sub: subject.into(),
                aud: audience.into(),
                iat: issued_at,
                nbf: issued_at,
                exp: expires_at,
                jti: token_id,
                subject_type: "USER".into(),
                claims,
            },
            profile,
        )
    }

    fn encrypt_payload(
        payload: TokenPayload,
        profile: EncryptionProfile,
    ) -> Result<Self, ServiceError> {
        let token_id = payload.jti;
        let kid = Uuid::new_v4();
        let issued_at = payload.iat;
        let expires_at = payload.exp;
        let plaintext = serde_json::to_vec(&payload).map_err(|_| {
            ServiceError::jwt_encryption_failed("token payload serialization failed")
        })?;

        let mut key = vec![0_u8; profile.key_length()];
        let mut iv = [0_u8; IV_LENGTH];
        getrandom::fill(&mut key)
            .map_err(|_| ServiceError::jwt_encryption_failed("token key generation failed"))?;
        getrandom::fill(&mut iv)
            .map_err(|_| ServiceError::jwt_encryption_failed("token IV generation failed"))?;

        let protected_header = ProtectedHeader {
            alg: "dir".to_owned(),
            enc: profile.enc().to_owned(),
            typ: "autobricks+jwt".to_owned(),
            kid,
        };
        let protected_json = serde_json::to_vec(&protected_header).map_err(|_| {
            ServiceError::jwt_encryption_failed("JWE protected header serialization failed")
        })?;
        let protected = URL_SAFE_NO_PAD.encode(protected_json);
        let (encrypted, tag) = encrypt(profile, &key, &iv, protected.as_bytes(), &plaintext)?;

        let token = format!(
            "{}..{}.{}.{}",
            protected,
            URL_SAFE_NO_PAD.encode(iv),
            URL_SAFE_NO_PAD.encode(encrypted),
            URL_SAFE_NO_PAD.encode(tag)
        );

        Ok(Self {
            token_id,
            token,
            kid,
            key,
            profile,
            iv,
            issued_at,
            expires_at,
        })
    }

    pub(crate) fn replace_claims(
        &self,
        updates: &Map<String, Value>,
        now: u64,
    ) -> Result<Self, ServiceError> {
        let mut payload = decrypt(&self.token, &self.key)?;
        if now < payload.nbf || now >= payload.exp {
            return Err(
                ServiceError::classified(8060, "session is not found or expired")
                    .expect("8060 must be assigned"),
            );
        }
        for (field, value) in updates {
            if field.is_empty() {
                return Err(ServiceError::invalid_request("update field is empty"));
            }
            payload.claims.insert(field.clone(), value.clone());
        }
        Self::encrypt_payload(payload, self.profile)
    }

    pub(crate) fn subject_type(&self) -> Result<String, ServiceError> {
        Ok(decrypt(&self.token, &self.key)?.subject_type)
    }

    pub(crate) fn restore(
        token_id: Uuid,
        token: String,
        kid: Uuid,
        key: Vec<u8>,
        iv: [u8; IV_LENGTH],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, ServiceError> {
        let (header, encoded_iv) = inspect_compact(&token)?;
        let profile = EncryptionProfile::from_enc(&header.enc)?;
        if header.kid != kid
            || encoded_iv != iv
            || issued_at >= expires_at
            || key.len() != profile.key_length()
        {
            return Err(ServiceError::jwt_invalid(
                "persisted token metadata does not match the JWE",
            ));
        }
        let payload = decrypt(&token, &key)?;
        if payload.jti != token_id
            || payload.iat != issued_at
            || payload.exp != expires_at
            || payload.nbf != issued_at
        {
            return Err(ServiceError::jwt_invalid(
                "persisted token claims do not match the token record",
            ));
        }
        Ok(Self {
            token_id,
            token,
            kid,
            key,
            profile,
            iv,
            issued_at,
            expires_at,
        })
    }

    pub fn verify_and_query(
        &self,
        submitted_token: &str,
        audience: &str,
        now: u64,
        authorized_fields: &[&str],
    ) -> Result<Map<String, Value>, ServiceError> {
        if submitted_token != self.token {
            return Err(ServiceError::jwt_invalid("encrypted token does not match"));
        }

        let payload = decrypt(submitted_token, &self.key)?;
        if payload.jti != self.token_id {
            return Err(ServiceError::jwt_invalid("token identifier does not match"));
        }
        if payload.aud != audience {
            return Err(ServiceError::jwt_audience_invalid(
                "token audience does not match",
            ));
        }
        if now < payload.nbf || now >= payload.exp {
            return Err(ServiceError::jwt_invalid("token is outside its valid time"));
        }

        let mut unique = BTreeSet::new();
        let mut result = Map::new();
        for field in authorized_fields {
            if !unique.insert(*field) {
                return Err(ServiceError::field_not_authorized(
                    "duplicate query field is not authorized",
                ));
            }
            let value = payload.claims.get(*field).ok_or_else(|| {
                ServiceError::field_not_authorized("query field is not authorized")
            })?;
            result.insert((*field).to_owned(), value.clone());
        }
        Ok(result)
    }

    pub(crate) fn inspect_payload(&self) -> Result<Value, ServiceError> {
        serde_json::to_value(decrypt(&self.token, &self.key)?)
            .map_err(|_| ServiceError::jwt_invalid("JWT payload is invalid"))
    }
}

fn decrypt(token: &str, key: &[u8]) -> Result<TokenPayload, ServiceError> {
    let (_, _) = inspect_compact(token)?;
    let components: Vec<&str> = token.split('.').collect();

    let iv = decode_fixed::<IV_LENGTH>(components[2], "JWE IV is invalid")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(components[3])
        .map_err(|_| ServiceError::jwt_invalid("JWE ciphertext is invalid"))?;
    let tag = decode_fixed::<TAG_LENGTH>(components[4], "JWE authentication tag is invalid")?;

    let (header, _) = inspect_compact(token)?;
    let profile = EncryptionProfile::from_enc(&header.enc)?;
    if key.len() != profile.key_length() {
        return Err(ServiceError::jwt_invalid("token key length is invalid"));
    }
    let plaintext = decrypt_bytes(
        profile,
        key,
        &iv,
        components[0].as_bytes(),
        &ciphertext,
        &tag,
    )?;
    serde_json::from_slice(&plaintext)
        .map_err(|_| ServiceError::jwt_invalid("JWT payload is invalid"))
}

fn inspect_compact(token: &str) -> Result<(ProtectedHeader, [u8; IV_LENGTH]), ServiceError> {
    let components: Vec<&str> = token.split('.').collect();
    if components.len() != 5 || !components[1].is_empty() {
        return Err(ServiceError::jwt_invalid(
            "JWE compact structure is invalid",
        ));
    }
    let protected = URL_SAFE_NO_PAD
        .decode(components[0])
        .map_err(|_| ServiceError::jwt_invalid("JWE protected header is invalid"))?;
    let header: ProtectedHeader = serde_json::from_slice(&protected)
        .map_err(|_| ServiceError::jwt_invalid("JWE protected header is invalid"))?;
    if header.alg != "dir"
        || EncryptionProfile::from_enc(&header.enc).is_err()
        || header.typ != "autobricks+jwt"
    {
        return Err(ServiceError::jwt_invalid(
            "JWE protected header is not permitted",
        ));
    }
    let iv = decode_fixed::<IV_LENGTH>(components[2], "JWE IV is invalid")?;
    Ok((header, iv))
}

fn encrypt(
    profile: EncryptionProfile,
    key: &[u8],
    iv: &[u8; IV_LENGTH],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LENGTH]), ServiceError> {
    let mut crypter = Crypter::new(profile.cipher(), Mode::Encrypt, key, Some(iv))
        .map_err(|_| ServiceError::jwt_encryption_failed("token encryption failed"))?;
    crypter.pad(false);
    crypter
        .aad_update(aad)
        .map_err(|_| ServiceError::jwt_encryption_failed("token encryption failed"))?;
    let mut output = vec![0; plaintext.len() + profile.cipher().block_size()];
    let mut count = crypter
        .update(plaintext, &mut output)
        .map_err(|_| ServiceError::jwt_encryption_failed("token encryption failed"))?;
    count += crypter
        .finalize(&mut output[count..])
        .map_err(|_| ServiceError::jwt_encryption_failed("token encryption failed"))?;
    output.truncate(count);
    let mut tag = [0_u8; TAG_LENGTH];
    crypter
        .get_tag(&mut tag)
        .map_err(|_| ServiceError::jwt_encryption_failed("token encryption failed"))?;
    Ok((output, tag))
}

fn decrypt_bytes(
    profile: EncryptionProfile,
    key: &[u8],
    iv: &[u8; IV_LENGTH],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LENGTH],
) -> Result<Vec<u8>, ServiceError> {
    let mut crypter = Crypter::new(profile.cipher(), Mode::Decrypt, key, Some(iv))
        .map_err(|_| ServiceError::jwt_invalid("token key cannot be used"))?;
    crypter.pad(false);
    crypter
        .set_tag(tag)
        .map_err(|_| ServiceError::jwt_invalid("JWE authentication tag is invalid"))?;
    crypter
        .aad_update(aad)
        .map_err(|_| ServiceError::jwt_invalid("JWE integrity validation failed"))?;
    let mut output = vec![0; ciphertext.len() + profile.cipher().block_size()];
    let mut count = crypter
        .update(ciphertext, &mut output)
        .map_err(|_| ServiceError::jwt_invalid("JWE integrity validation failed"))?;
    count += crypter
        .finalize(&mut output[count..])
        .map_err(|_| ServiceError::jwt_invalid("JWE integrity validation failed"))?;
    output.truncate(count);
    Ok(output)
}

fn decode_fixed<const LENGTH: usize>(
    value: &str,
    message: &'static str,
) -> Result<[u8; LENGTH], ServiceError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ServiceError::jwt_invalid(message))?;
    decoded
        .try_into()
        .map_err(|_| ServiceError::jwt_invalid(message))
}

#[cfg(test)]
mod tests {
    use super::{EncryptionProfile, IssuedToken, decrypt};
    use serde_json::{Map, Value};
    use std::time::Duration;

    fn token() -> IssuedToken {
        IssuedToken::issue(
            "autobricks-jwt",
            "service-1",
            "user-0001",
            Map::from_iter([
                ("role".to_owned(), Value::String("member".to_owned())),
                ("user_id".to_owned(), Value::String("user-0001".to_owned())),
            ]),
            1_000,
            Duration::from_secs(300),
        )
        .unwrap()
    }

    #[test]
    fn issues_five_component_jwe_compact_token() {
        let token = token();
        assert_eq!(token.token.split('.').count(), 5);
        assert!(!token.token.contains("user-0001"));
        let (header, iv) = super::inspect_compact(&token.token).unwrap();
        assert_eq!(header.kid, token.kid);
        assert_eq!(iv, token.iv);
    }

    #[test]
    fn issues_and_verifies_every_registered_aes_gcm_profile() {
        for (profile, enc, key_length) in [
            (EncryptionProfile::A128Gcm, "A128GCM", 16),
            (EncryptionProfile::A192Gcm, "A192GCM", 24),
            (EncryptionProfile::A256Gcm, "A256GCM", 32),
        ] {
            let token = IssuedToken::issue_with_profile(
                "autobricks-jwt",
                "service-profile",
                "user-profile",
                Map::from_iter([("user_id".into(), Value::String("user-profile".into()))]),
                1_000,
                Duration::from_secs(300),
                profile,
            )
            .unwrap();
            assert_eq!(token.key.len(), key_length);
            let (header, _) = super::inspect_compact(&token.token).unwrap();
            assert_eq!(header.enc, enc);
            assert_eq!(
                token
                    .verify_and_query(&token.token, "service-profile", 1_001, &["user_id"])
                    .unwrap()["user_id"],
                "user-profile"
            );
        }
    }

    #[test]
    fn verifies_and_returns_only_requested_fields() {
        let token = token();
        let fields = token
            .verify_and_query(&token.token, "service-1", 1_100, &["user_id"])
            .unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields["user_id"], "user-0001");
    }

    #[test]
    fn rejects_modified_token() {
        let token = token();
        let mut modified = token.token.clone();
        modified.push('A');
        let error = token
            .verify_and_query(&modified, "service-1", 1_100, &["user_id"])
            .unwrap_err();
        assert_eq!(error.code(), 8061);
    }

    #[test]
    fn rejects_modified_ciphertext_during_aead_validation() {
        let token = token();
        let mut components: Vec<String> = token.token.split('.').map(str::to_owned).collect();
        let replacement = if components[3].starts_with('A') {
            "B"
        } else {
            "A"
        };
        components[3].replace_range(0..1, replacement);
        let modified = components.join(".");

        let error = decrypt(&modified, &token.key).unwrap_err();
        assert_eq!(error.code(), 8061);
    }

    #[test]
    fn each_token_uses_independent_key_material() {
        let first = token();
        let second = token();
        assert_ne!(first.key, second.key);
        assert_ne!(first.token, second.token);
    }

    #[test]
    fn rejects_wrong_audience() {
        let token = token();
        let error = token
            .verify_and_query(&token.token, "service-2", 1_100, &["user_id"])
            .unwrap_err();
        assert_eq!(error.code(), 8062);
    }

    #[test]
    fn rejects_expired_token() {
        let token = token();
        let error = token
            .verify_and_query(&token.token, "service-1", 1_300, &["user_id"])
            .unwrap_err();
        assert_eq!(error.code(), 8061);
    }
}
