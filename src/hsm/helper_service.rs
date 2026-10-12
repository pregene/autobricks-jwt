use std::io::{Read, Write};

use cryptoki::types::AuthPin;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    service_error::ServiceError,
    soft_hsm2::{DatabaseKeyRole, SoftHsm2KeyStore},
};

#[derive(Deserialize)]
struct HelperRequest {
    operation: String,
    namespace: String,
    #[serde(default)]
    slot: Option<String>,
    #[serde(default)]
    bits: Option<u16>,
    #[serde(default)]
    previous_key_hex: Option<String>,
    #[serde(default)]
    current_key_hex: Option<String>,
}

pub fn run_from_environment() -> Result<(), ServiceError> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(65_536)
        .read_to_end(&mut input)
        .map_err(|_| hsm_error("HSM helper request cannot be read"))?;
    let request: HelperRequest =
        serde_json::from_slice(&input).map_err(|_| hsm_error("HSM helper request is invalid"))?;
    if request.namespace.trim().is_empty() {
        return Err(hsm_error("HSM key namespace is empty"));
    }

    let module = required_environment("AUTOBRICKS_JWT_PKCS11_MODULE")?;
    let token = required_environment("AUTOBRICKS_JWT_HSM_TOKEN")?;
    let pin = required_environment("AUTOBRICKS_JWT_HSM_PIN")?;
    let store =
        SoftHsm2KeyStore::open(module, &token, AuthPin::new(pin.into()), &request.namespace)?;
    let response = execute(&store, request)?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &response)
        .map_err(|_| hsm_error("HSM helper response cannot be encoded"))?;
    output
        .write_all(b"\n")
        .map_err(|_| hsm_error("HSM helper response cannot be written"))
}

fn execute(store: &SoftHsm2KeyStore, request: HelperRequest) -> Result<Value, ServiceError> {
    match request.operation.as_str() {
        "INITIALIZE" => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key)
                .map_err(|_| hsm_error("initial HSM Database key cannot be generated"))?;
            let created = store.initialize_wrapped_current(key)?;
            key.fill(0);
            Ok(json!({ "initialized": created }))
        }
        "READ" => {
            let role = parse_role(request.slot.as_deref())?;
            match store.read_wrapped_database_key(role)? {
                Some(mut key) => {
                    let encoded = encode_key(&key);
                    key.fill(0);
                    Ok(json!({ "key_hex": encoded }))
                }
                None => Ok(json!({ "present": false })),
            }
        }
        "GENERATE" if request.bits == Some(256) => {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key)
                .map_err(|_| hsm_error("next HSM Database key cannot be generated"))?;
            let encoded = encode_key(&key);
            key.fill(0);
            Ok(json!({ "key_hex": encoded }))
        }
        "COMMIT_TWO_SLOTS" => {
            let mut previous = decode_key(request.previous_key_hex.as_deref())?;
            let mut current = decode_key(request.current_key_hex.as_deref())?;
            let result = store.replace_wrapped_database_keys(previous, current);
            previous.fill(0);
            current.fill(0);
            result?;
            Ok(json!({ "committed": true }))
        }
        _ => Err(hsm_error("HSM helper operation is unsupported")),
    }
}

fn required_environment(name: &str) -> Result<String, ServiceError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| hsm_error("HSM helper environment is incomplete"))
}

fn parse_role(slot: Option<&str>) -> Result<DatabaseKeyRole, ServiceError> {
    match slot {
        Some("CURRENT") => Ok(DatabaseKeyRole::Current),
        Some("PREVIOUS") => Ok(DatabaseKeyRole::Previous),
        _ => Err(hsm_error("HSM Database-key slot is invalid")),
    }
}

fn encode_key(key: &[u8; 32]) -> String {
    key.iter().map(|value| format!("{value:02x}")).collect()
}

fn decode_key(value: Option<&str>) -> Result<[u8; 32], ServiceError> {
    let value = value.ok_or_else(|| hsm_error("HSM Database key is missing"))?;
    if value.len() != 64 || !value.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(hsm_error("HSM Database key has an invalid encoding"));
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| hsm_error("HSM Database key has an invalid encoding"))?;
    }
    Ok(output)
}

fn hsm_error(message: &'static str) -> ServiceError {
    ServiceError::assigned(8085, message)
}
