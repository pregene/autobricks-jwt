use std::{
    ffi::CString,
    fs,
    io::Write,
    os::raw::{c_char, c_int},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use serde_json::Value;
use uuid::Uuid;

use crate::{
    database_source::{
        DatabaseConnectionInput, DatabaseSourceInput, DatabaseTlsMode, QueryBinding,
    },
    registration_workflow::{
        ClientRegistrationForm, ServiceRegistrationForm, ServiceSourceForm, comma_fields,
    },
    service_registry::{ClientJsonField, ClientJsonValueType, OperationClass},
};
use crate::{management_protocol::ManagementRequest, management_service};

const KEY_DOWN: c_int = 258;
const KEY_UP: c_int = 259;
const SPACE: c_int = 32;

#[link(name = "ncurses")]
unsafe extern "C" {
    fn initscr() -> *mut libc::c_void;
    fn endwin() -> c_int;
    fn cbreak() -> c_int;
    fn noecho() -> c_int;
    fn echo() -> c_int;
    fn curs_set(visibility: c_int) -> c_int;
    fn keypad(window: *mut libc::c_void, enabled: bool) -> c_int;
    fn erase() -> c_int;
    fn refresh() -> c_int;
    fn getch() -> c_int;
    fn getnstr(value: *mut c_char, length: c_int) -> c_int;
    fn mvaddnstr(y: c_int, x: c_int, value: *const c_char, length: c_int) -> c_int;
}

struct Screen;
impl Screen {
    fn open() -> Result<Self, String> {
        // SAFETY: ncurses owns its global terminal state until Screen is dropped.
        let screen = unsafe { initscr() };
        if screen.is_null() {
            return Err("curses terminal initialization failed".into());
        }
        unsafe {
            cbreak();
            noecho();
            keypad(screen, true);
        }
        Ok(Self)
    }
}
impl Drop for Screen {
    fn drop(&mut self) {
        unsafe {
            endwin();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Page {
    Clients,
    Services(Uuid),
}

#[derive(Debug, Eq, PartialEq)]
struct Navigation {
    selected: usize,
    count: usize,
}
impl Navigation {
    fn new(count: usize) -> Self {
        Self { selected: 0, count }
    }
    fn key(&mut self, key: c_int) {
        match key {
            KEY_UP if self.selected > 0 => self.selected -= 1,
            KEY_DOWN if self.selected + 1 < self.count => self.selected += 1,
            _ => {}
        }
    }
}

pub fn run(socket: &Path) -> Result<(), String> {
    let _screen = Screen::open()?;
    let mut page = Page::Clients;
    let mut selected = 0;
    loop {
        let (title, records) = load(socket, page)?;
        let mut navigation = Navigation::new(records.len());
        navigation.selected = selected.min(records.len().saturating_sub(1));
        draw(&title, &records, navigation.selected);
        let key = unsafe { getch() };
        match key {
            27 | 113 => match page {
                Page::Clients => return Ok(()),
                Page::Services(_) => {
                    page = Page::Clients;
                    selected = 0;
                }
            },
            10 | 13 if !records.is_empty() => match page {
                Page::Clients => {
                    let id = records[navigation.selected]
                        .get("client_id")
                        .and_then(Value::as_str)
                        .ok_or("client record has no client_id")?;
                    page = Page::Services(Uuid::parse_str(id).map_err(|_| "client_id is invalid")?);
                    selected = 0;
                }
                Page::Services(_) => {}
            },
            110 => {
                match page {
                    Page::Clients => register_client(socket)?,
                    Page::Services(client_id) => {
                        let clients = load(socket, Page::Clients)?.1;
                        let client = clients
                            .iter()
                            .find(|record| record["client_id"] == client_id.to_string())
                            .ok_or("selected client is unavailable")?;
                        register_service(socket, client_id, client)?;
                    }
                }
                selected = 0;
            }
            101 if !records.is_empty() && matches!(page, Page::Clients) => {
                modify_client(socket, &records[navigation.selected])?;
            }
            114 if matches!(page, Page::Clients) => recovery(socket)?,
            100 if !records.is_empty() => {
                delete(socket, page, &records[navigation.selected])?;
                selected = navigation.selected.saturating_sub(1);
            }
            _ => {
                navigation.key(key);
                selected = navigation.selected;
            }
        }
    }
}

fn load(socket: &Path, page: Page) -> Result<(String, Vec<Value>), String> {
    let (title, request) = match page {
        Page::Clients => (
            "JWT Clients - n: new  e: edit  Enter: services  d: delete  r: recovery  q: quit"
                .to_owned(),
            ManagementRequest::ListClients,
        ),
        Page::Services(client_id) => (
            format!("Services for {client_id} - n: new  d: delete  q: back"),
            ManagementRequest::ListServices { client_id },
        ),
    };
    let response = management_service::request(socket, &request)?;
    if response.status != "SUCCESS" {
        return Err(response
            .error
            .map(|error| error.message)
            .unwrap_or_else(|| "management request failed".into()));
    }
    let records = response
        .result
        .and_then(|value| value.as_array().cloned())
        .ok_or("management list response is invalid")?;
    Ok((title, records))
}

fn recovery(socket: &Path) -> Result<(), String> {
    match choose_one(
        "Database recovery operations",
        &[
            "List recovery points",
            "Force backup and key rotation",
            "Restore recovery point",
        ],
        0,
    )? {
        0 => show_result(successful(management_service::request(
            socket,
            &ManagementRequest::ListRecoveryPoints,
        )?)?),
        1 => {
            let mut key = prompt_secret("Recovery authorization key")?;
            let result = management_service::request(
                socket,
                &ManagementRequest::ForceBackupAndRotate {
                    recovery_key: key.clone(),
                },
            );
            key.replace_range(.., "");
            show_result(successful(result?)?)
        }
        _ => {
            let generation = number(&prompt("Recovery generation", None)?)?;
            let mut key = prompt_secret("Recovery authorization key")?;
            let result = management_service::request(
                socket,
                &ManagementRequest::RestoreDatabase {
                    recovery_key: key.clone(),
                    generation,
                },
            );
            key.replace_range(.., "");
            show_result(successful(result?)?)
        }
    }
}

fn capabilities(socket: &Path) -> Result<Value, String> {
    successful(management_service::request(
        socket,
        &ManagementRequest::GetCapabilities,
    )?)
}

fn register_client(socket: &Path) -> Result<(), String> {
    let capabilities = capabilities(socket)?;
    let enabled = strings(&capabilities, "transports")?;
    let operation = match choose_one("Operation permission", &["READ", "WRITE"], 0)? {
        0 => OperationClass::Read,
        _ => OperationClass::Write,
    };
    let transports = choose_transports(&enabled)?;
    let unix = transports.iter().any(|transport| transport == "UNIX");
    let form = ClientRegistrationForm {
        client_name: prompt("Client name", None)?,
        operation_class: operation,
        allowed_source_cidr: prompt("Source CIDR", None)?,
        transports,
        keep_alive_timeout: number(&prompt("Keep-alive timeout", Some("3600"))?)?,
        peer_uid: if unix {
            optional_number(&prompt_optional("Peer UID")?)?
        } else {
            None
        },
        peer_gid: if unix {
            optional_number(&prompt_optional("Peer GID")?)?
        } else {
            None
        },
    };
    let request = form
        .register_request(&enabled)
        .map_err(|error| error.to_string())?;
    show_result(successful(management_service::request(socket, &request)?)?)
}

fn modify_client(socket: &Path, record: &Value) -> Result<(), String> {
    let enabled = strings(&capabilities(socket)?, "transports")?;
    let transports = choose_transports(&enabled)?;
    let unix = transports.iter().any(|transport| transport == "UNIX");
    let operation = if record["operation_class"] == "READ" {
        OperationClass::Read
    } else {
        OperationClass::Write
    };
    let timeout_default = record["keep_alive_timeout"]
        .as_u64()
        .unwrap_or(3600)
        .to_string();
    let form = ClientRegistrationForm {
        client_name: prompt("Client name", record["client_name"].as_str())?,
        operation_class: operation,
        allowed_source_cidr: prompt("Source CIDR", record["allowed_source_cidr"].as_str())?,
        transports,
        keep_alive_timeout: number(&prompt("Keep-alive timeout", Some(&timeout_default))?)?,
        peer_uid: if unix {
            optional_number(&prompt_optional("Peer UID")?)?
        } else {
            None
        },
        peer_gid: if unix {
            optional_number(&prompt_optional("Peer GID")?)?
        } else {
            None
        },
    };
    let request = form
        .modification_request(uuid_field(record, "client_id")?, &enabled)
        .map_err(|error| error.to_string())?;
    show_result(successful(management_service::request(socket, &request)?)?)
}

fn register_service(socket: &Path, client_id: Uuid, client: &Value) -> Result<(), String> {
    let capabilities = capabilities(socket)?;
    let operation = if client["operation_class"] == "READ" {
        OperationClass::Read
    } else {
        OperationClass::Write
    };
    let service_name = prompt("Service name", None)?;
    let subject_type = ["USER", "DEVICE", "WORKLOAD"]
        [choose_one("Subject type", &["USER", "DEVICE", "WORKLOAD"], 0)?]
    .to_owned();
    let source = match operation {
        OperationClass::Read => ServiceSourceForm::Read {
            allowed_fields: comma_fields(&prompt(
                "Allowed JWT query fields (comma-separated)",
                None,
            )?)
            .map_err(|error| error.to_string())?,
            allowed_issuer_service_ids: prompt(
                "Allowed WRITE service UUIDs (comma-separated)",
                None,
            )?
            .split(',')
            .map(str::trim)
            .map(Uuid::parse_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "allowed WRITE service UUID is invalid".to_owned())?,
        },
        OperationClass::Write => {
            let profile_values = strings(&capabilities, "encryption_profiles")?;
            let profile_refs = profile_values
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let profile = profile_values[choose_one(
                "JWT encryption profile",
                &profile_refs,
                profile_values.len() - 1,
            )?]
            .clone();
            match choose_one("Subject source", &["CLIENT_JSON", "DATABASE"], 0)? {
                0 => ServiceSourceForm::ClientJson {
                    encryption_profile: profile,
                    fields: client_json_fields(&prompt(
                        "JSON fields name:type:required (comma-separated)",
                        None,
                    )?)?,
                },
                _ => ServiceSourceForm::Database {
                    encryption_profile: profile,
                    source: database_source_form()?,
                },
            }
        }
    };
    let form = ServiceRegistrationForm {
        client_id,
        service_name,
        subject_type,
        operation_class: operation,
        source,
    };
    if matches!(form.source, ServiceSourceForm::Database { .. }) {
        let library = prompt("Autobricks Cache library path", None)?;
        form.test_database_connection(Path::new(&library))
            .map_err(|error| error.to_string())?;
    }
    let request = form.request().map_err(|error| error.to_string())?;
    let (response, attachment) = management_service::request_with_attachment(socket, &request)?;
    let mut result = successful(response)?;
    if let Some(attachment) = attachment {
        let directory =
            std::env::current_dir().map_err(|_| "invocation directory is unavailable")?;
        let path = write_certificate_package(&directory, &attachment)?;
        if let Some(object) = result.as_object_mut() {
            object.insert(
                "certificate_package".into(),
                Value::String(path.to_string_lossy().into_owned()),
            );
        }
    }
    show_result(result)
}

fn write_certificate_package(
    directory: &Path,
    attachment: &management_service::ReceivedAttachment,
) -> Result<std::path::PathBuf, String> {
    let path = directory.join(&attachment.file_name);
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| "certificate package cannot be created in the invocation directory")?;
    file.write_all(&attachment.bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "certificate package cannot be written")?;
    Ok(path)
}

fn database_source_form() -> Result<DatabaseSourceInput, String> {
    let driver = ["postgresql", "mariadb", "sqlite"]
        [choose_one("Database driver", &["postgresql", "mariadb", "sqlite"], 0)?]
    .to_owned();
    let tls_mode = if driver == "sqlite" {
        DatabaseTlsMode::Disabled
    } else {
        match choose_one("Database transport", &["DISABLED", "TLS", "MTLS"], 1)? {
            0 => DatabaseTlsMode::Disabled,
            1 => DatabaseTlsMode::Tls,
            _ => DatabaseTlsMode::Mtls,
        }
    };
    let ca_file = matches!(tls_mode, DatabaseTlsMode::Tls | DatabaseTlsMode::Mtls)
        .then(|| prompt("Database trust chain", None))
        .transpose()?;
    let certificate = (tls_mode == DatabaseTlsMode::Mtls)
        .then(|| prompt("Database client certificate", None))
        .transpose()?;
    let private_key = (tls_mode == DatabaseTlsMode::Mtls)
        .then(|| prompt("Database client private key", None))
        .transpose()?;
    let update_query = prompt("UPDATE query (empty to disable)", None)?;
    let update = if update_query.trim().is_empty() {
        None
    } else {
        Some(QueryBinding {
            query: update_query,
            fields: comma_fields(&prompt(
                "UPDATE fields (comma-separated, binding order)",
                None,
            )?)
            .map_err(|error| error.to_string())?,
        })
    };
    Ok(DatabaseSourceInput {
        connection: DatabaseConnectionInput {
            name: prompt("Connection name", None)?,
            driver: driver.clone(),
            host: if driver == "sqlite" { String::new() } else { prompt("Database host", None)? },
            port: if driver == "sqlite" { 0 } else { number(&prompt("Database port", None)?)? as u16 },
            database: prompt("Database name or file", None)?,
            queue_directory: prompt("Cache queue directory", None)?,
            username: if driver == "sqlite" { String::new() } else { prompt("Database username", None)? },
            password: if driver == "sqlite" { String::new() } else { prompt_secret("Database password")? },
            tls_mode,
            ca_file,
            certificate,
            private_key,
            connect_timeout_ms: number(&prompt("Connect timeout milliseconds", Some("2000"))?)?,
            query_timeout_ms: number(&prompt("Query timeout milliseconds", Some("5000"))?)?,
            pool_size: number(&prompt("Connection pool size", Some("4"))?)? as u16,
            sqlite_options: (driver == "sqlite").then(|| serde_json::json!({"open_mode":"READ_WRITE","mutex":"FULL","uri":false,"cache":"DEFAULT","journal_mode":"WAL","synchronous":"FULL","foreign_keys":true})),
        },
        primary_key: comma_fields(&prompt("Primary Key fields (comma-separated)", None)?).map_err(|error| error.to_string())?,
        maps: vec![comma_fields(&prompt("MAP fields (comma-separated)", None)?).map_err(|error| error.to_string())?],
        select: QueryBinding {
            query: prompt("SELECT query", None)?,
            fields: comma_fields(&prompt("SELECT fields (comma-separated, binding order)", None)?).map_err(|error| error.to_string())?,
        },
        update,
        retention_seconds: number(&prompt("Cache retention seconds", Some("3600"))?)?,
    })
}

fn delete(socket: &Path, page: Page, record: &Value) -> Result<(), String> {
    let request = match page {
        Page::Clients => ManagementRequest::DeleteClient {
            client_id: uuid_field(record, "client_id")?,
        },
        Page::Services(client_id) => ManagementRequest::DeleteService {
            client_id,
            service_id: uuid_field(record, "service_id")?,
        },
    };
    let response = management_service::request(socket, &request)?;
    if response.status == "SUCCESS" {
        Ok(())
    } else {
        Err(response
            .error
            .map(|error| error.message)
            .unwrap_or_else(|| "delete failed".into()))
    }
}

fn uuid_field(record: &Value, field: &str) -> Result<Uuid, String> {
    Uuid::parse_str(
        record
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{field} is missing"))?,
    )
    .map_err(|_| format!("{field} is invalid"))
}

fn successful(response: crate::management_protocol::ManagementResponse) -> Result<Value, String> {
    if response.status == "SUCCESS" {
        response.result.ok_or("management result is missing".into())
    } else {
        Err(response
            .error
            .map(|error| error.message)
            .unwrap_or_else(|| "management request failed".into()))
    }
}

fn strings(value: &Value, field: &str) -> Result<Vec<String>, String> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} capability is missing"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{field} capability is invalid"))
        })
        .collect()
}

fn choose_one(title: &str, choices: &[&str], initial: usize) -> Result<usize, String> {
    if choices.is_empty() {
        return Err("selection has no available value".into());
    }
    let mut selected = initial.min(choices.len() - 1);
    loop {
        unsafe { erase() };
        line(
            0,
            2,
            &format!("Autobricks JWT Management {}", crate::VERSION),
        );
        line(2, 2, title);
        for (index, choice) in choices.iter().enumerate() {
            line(
                4 + index as i32,
                4,
                &format!("{} {choice}", if index == selected { ">" } else { " " }),
            );
        }
        line(6 + choices.len() as i32, 4, "Enter: select  q: cancel");
        unsafe { refresh() };
        match unsafe { getch() } {
            KEY_UP if selected > 0 => selected -= 1,
            KEY_DOWN if selected + 1 < choices.len() => selected += 1,
            10 | 13 => return Ok(selected),
            27 | 113 => return Err("operation cancelled".into()),
            _ => {}
        }
    }
}

fn choose_transports(enabled: &[String]) -> Result<Vec<String>, String> {
    let all = ["UNIX", "TCP", "TLS", "MTLS"];
    let mut selected = 0;
    let mut checked = [false; 4];
    loop {
        unsafe { erase() };
        line(
            0,
            2,
            &format!("Autobricks JWT Management {}", crate::VERSION),
        );
        line(2, 2, "Service transports");
        for (index, transport) in all.iter().enumerate() {
            let available = enabled.iter().any(|value| value == transport);
            let mark = if !available {
                "[-]"
            } else if checked[index] {
                "[x]"
            } else {
                "[ ]"
            };
            line(
                4 + index as i32,
                4,
                &format!(
                    "{} {mark} {transport}{}",
                    if index == selected { ">" } else { " " },
                    if available { "" } else { " (unavailable)" }
                ),
            );
        }
        line(10, 4, "Space: toggle  Enter: continue  q: cancel");
        unsafe { refresh() };
        match unsafe { getch() } {
            KEY_UP if selected > 0 => selected -= 1,
            KEY_DOWN if selected + 1 < all.len() => selected += 1,
            SPACE if enabled.iter().any(|value| value == all[selected]) => {
                checked[selected] = !checked[selected]
            }
            10 | 13 if checked.iter().any(|value| *value) => {
                return Ok(all
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| checked[*index])
                    .map(|(_, value)| (*value).to_owned())
                    .collect());
            }
            27 | 113 => return Err("operation cancelled".into()),
            _ => {}
        }
    }
}

fn prompt(label: &str, default: Option<&str>) -> Result<String, String> {
    prompt_with_echo(label, default, true)
}

fn prompt_secret(label: &str) -> Result<String, String> {
    prompt_with_echo(label, None, false)
}

fn prompt_optional(label: &str) -> Result<String, String> {
    prompt_with_echo(label, Some(""), true)
}

fn prompt_with_echo(label: &str, default: Option<&str>, visible: bool) -> Result<String, String> {
    unsafe {
        erase();
        curs_set(1);
        if visible {
            echo();
        } else {
            noecho();
        }
    }
    line(
        0,
        2,
        &format!("Autobricks JWT Management {}", crate::VERSION),
    );
    line(2, 2, label);
    if let Some(default) = default {
        line(3, 2, &format!("Default: {default}"));
    }
    line(5, 2, "> ");
    unsafe { refresh() };
    let mut buffer = vec![0_i8; 4097];
    let status = unsafe { getnstr(buffer.as_mut_ptr(), 4096) };
    unsafe {
        noecho();
        curs_set(0);
    }
    if status == -1 {
        return Err("text input failed".into());
    }
    let length = buffer.iter().position(|byte| *byte == 0).unwrap_or(4096);
    let bytes = buffer[..length]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    let value = String::from_utf8(bytes).map_err(|_| "text input is not UTF-8".to_owned())?;
    if value.is_empty() {
        default
            .map(str::to_owned)
            .ok_or_else(|| format!("{label} is required"))
    } else {
        Ok(value)
    }
}

fn number(value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| "numeric input is invalid".to_owned())
}

fn optional_number(value: &str) -> Result<Option<u32>, String> {
    if value.trim().is_empty() {
        Ok(None)
    } else {
        value
            .parse()
            .map(Some)
            .map_err(|_| "peer identifier is invalid".to_owned())
    }
}

fn client_json_fields(value: &str) -> Result<Vec<ClientJsonField>, String> {
    value
        .split(',')
        .map(str::trim)
        .map(|entry| {
            let parts = entry.split(':').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 3 || parts[0].is_empty() {
                return Err("JSON field must use name:type:required".into());
            }
            let value_type = match parts[1].to_ascii_uppercase().as_str() {
                "STRING" => ClientJsonValueType::String,
                "NUMBER" => ClientJsonValueType::Number,
                "BOOLEAN" => ClientJsonValueType::Boolean,
                _ => return Err("JSON field type is invalid".into()),
            };
            let required = match parts[2].to_ascii_lowercase().as_str() {
                "true" | "yes" | "required" => true,
                "false" | "no" | "optional" => false,
                _ => return Err("JSON field requirement is invalid".into()),
            };
            Ok(ClientJsonField {
                name: parts[0].into(),
                value_type,
                required,
            })
        })
        .collect()
}

fn show_result(value: Value) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(&value)
        .map_err(|_| "management result cannot be displayed".to_owned())?;
    unsafe { erase() };
    line(
        0,
        2,
        &format!("Autobricks JWT Management {}", crate::VERSION),
    );
    line(2, 2, "Operation result");
    for (index, content) in rendered.lines().take(30).enumerate() {
        line(4 + index as i32, 2, content);
    }
    line(35, 2, "Press any key to continue");
    unsafe {
        refresh();
        getch();
    }
    Ok(())
}

fn draw(title: &str, records: &[Value], selected: usize) {
    unsafe {
        erase();
    }
    line(
        0,
        2,
        &format!("Autobricks JWT Management {}", crate::VERSION),
    );
    line(2, 2, title);
    if records.is_empty() {
        line(4, 4, "No registered records");
    }
    for (index, record) in records.iter().enumerate() {
        let marker = if index == selected { ">" } else { " " };
        let name = record
            .get("client_name")
            .or_else(|| record.get("service_name"))
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let id = record
            .get("client_id")
            .or_else(|| record.get("service_id"))
            .and_then(Value::as_str)
            .unwrap_or("-");
        line(4 + index as i32, 2, &format!("{marker} {name:<28} {id}"));
    }
    unsafe {
        refresh();
    }
}

fn line(y: i32, x: i32, value: &str) {
    let sanitized = value.replace('\0', "?");
    let value = CString::new(sanitized).expect("NUL removed");
    unsafe {
        mvaddnstr(
            y,
            x,
            value.as_ptr(),
            value.as_bytes().len().min(i32::MAX as usize) as i32,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn arrow_navigation_is_bounded() {
        let mut navigation = Navigation::new(3);
        navigation.key(KEY_UP);
        assert_eq!(navigation.selected, 0);
        navigation.key(KEY_DOWN);
        navigation.key(KEY_DOWN);
        navigation.key(KEY_DOWN);
        assert_eq!(navigation.selected, 2);
    }

    #[test]
    fn writes_verified_certificate_package_once_with_private_permissions() {
        let directory = std::env::temp_dir().join(format!("ab-jwt-cli-package-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let attachment = management_service::ReceivedAttachment {
            file_name: "registered-service.tar.gz".into(),
            bytes: b"verified-package".to_vec(),
        };
        let path = write_certificate_package(&directory, &attachment).unwrap();
        assert_eq!(path, directory.join("registered-service.tar.gz"));
        assert_eq!(fs::read(&path).unwrap(), b"verified-package");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(write_certificate_package(&directory, &attachment).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
