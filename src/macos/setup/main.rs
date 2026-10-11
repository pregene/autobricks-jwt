use flate2::read::GzDecoder;
use getrandom::fill as random_fill;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CONFIG_ROOT: &str = "/usr/local/etc/autobricks-jwt";
const STATE_ROOT: &str = "/usr/local/var/lib/autobricks-jwt";
const CONFIG: &str = "/usr/local/etc/autobricks-jwt/server.conf";
const SOFTHSM_CONFIG: &str = "/usr/local/etc/autobricks-jwt/softhsm2.conf";
const TOKEN_DIRECTORY: &str = "/usr/local/var/lib/autobricks-jwt/softhsm-tokens";
const TOKEN_LABEL: &str = "autobricks-jwt";
const CONFIGURED_MARKER: &str = "/usr/local/share/autobricks-jwt/configured";

#[derive(Deserialize)]
struct SetupInput {
    runtime_transports: Vec<String>,
    tcp_address: String,
    tls_address: String,
    mtls_address: String,
    timeout: u64,
    backup_directory: PathBuf,
    backup_interval_days: u64,
    server_certificate: PathBuf,
    server_private_key: PathBuf,
    server_trust_chain: PathBuf,
    client_trust_chain: PathBuf,
    certificate_renewal_time: String,
    use_pki: bool,
    use_truelog: bool,
    pki_issuer: String,
    server_certificate_ip: String,
    log_request: bool,
    log_query: bool,
    log_issuance: bool,
    log_audit: bool,
    require_token: bool,
}

fn fail(message: impl Into<String>) -> String {
    message.into()
}

fn executable(candidates: &[&str]) -> Result<PathBuf, String> {
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| fail("Required executable is unavailable."))
}

fn run(command: &mut Command) -> Result<Output, String> {
    command
        .output()
        .map_err(|error| fail(error.to_string()))
        .and_then(|output| {
            if output.status.success() {
                Ok(output)
            } else {
                let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
                Err(fail(if message.is_empty() {
                    "A required setup command failed.".to_owned()
                } else {
                    message
                }))
            }
        })
}

fn run_quiet(command: &mut Command) -> Result<(), String> {
    run(command).map(|_| ())
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| fail(error.to_string()))?;
    }
    fs::write(path, contents).map_err(|error| fail(error.to_string()))?;
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .map_err(|error| fail(error.to_string()))
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut value = vec![0u8; bytes];
    random_fill(&mut value).map_err(|error| fail(error.to_string()))?;
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn validate_address(value: &str) -> Result<&str, String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| fail("Listener address is invalid."))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| fail("Listener address is invalid."))?;
    if host.is_empty() || port == 0 {
        return Err(fail("Listener address is invalid."));
    }
    Ok(value)
}

fn find_fingerprint(value: &Value) -> Option<String> {
    match value {
        Value::Object(values) => values.iter().find_map(|(key, value)| {
            if key.eq_ignore_ascii_case("fingerprint") {
                value
                    .as_str()
                    .filter(|text| {
                        text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                    .map(str::to_ascii_lowercase)
            } else {
                find_fingerprint(value)
            }
        }),
        Value::Array(values) => values.iter().find_map(find_fingerprint),
        _ => None,
    }
}

fn console_user() -> Result<String, String> {
    let output = run(Command::new("/usr/bin/stat").args(["-f", "%Su", "/dev/console"]))?;
    let name = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if name.is_empty() || name == "root" {
        Err(fail(
            "An interactive installation user is required for PKI provisioning.",
        ))
    } else {
        Ok(name)
    }
}

fn temporary_directory() -> Result<PathBuf, String> {
    let path = PathBuf::from(format!(
        "/private/tmp/autobricks-jwt-pki-{}",
        random_hex(12)?
    ));
    fs::create_dir(&path).map_err(|error| fail(error.to_string()))?;
    fs::set_permissions(&path, Permissions::from_mode(0o700))
        .map_err(|error| fail(error.to_string()))?;
    Ok(path)
}

fn parse_octal(field: &[u8]) -> Result<usize, String> {
    let value = field
        .iter()
        .copied()
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    let text = std::str::from_utf8(&value)
        .map_err(|_| fail("Autobricks PKI certificate archive contents are invalid."))?
        .trim();
    usize::from_str_radix(text, 8)
        .map_err(|_| fail("Autobricks PKI certificate archive contents are invalid."))
}

fn extract_identity_archive(archive: &Path) -> Result<HashMap<String, Vec<u8>>, String> {
    let compressed = fs::read(archive).map_err(|error| fail(error.to_string()))?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut tar = Vec::new();
    decoder
        .read_to_end(&mut tar)
        .map_err(|_| fail("Autobricks PKI certificate archive contents are invalid."))?;
    let expected: HashSet<&str> = ["certificate.pem", "private-key.pem", "trust-chain"]
        .into_iter()
        .collect();
    let mut files = HashMap::new();
    let mut offset = 0usize;
    while offset + 512 <= tar.len() {
        let header = &tar[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let stored_checksum = parse_octal(&header[148..156])?;
        let calculated_checksum: usize = header
            .iter()
            .enumerate()
            .map(|(index, byte)| if (148..156).contains(&index) { b' ' } else { *byte } as usize)
            .sum();
        if stored_checksum != calculated_checksum {
            return Err(fail(
                "Autobricks PKI certificate archive contents are invalid.",
            ));
        }
        let name_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let name = std::str::from_utf8(&header[..name_end])
            .map_err(|_| fail("Autobricks PKI certificate archive contents are invalid."))?
            .trim_start_matches("./");
        if !expected.contains(name) || !matches!(header[156], 0 | b'0') || files.contains_key(name)
        {
            return Err(fail(
                "Autobricks PKI certificate archive contents are invalid.",
            ));
        }
        let size = parse_octal(&header[124..136])?;
        let start = offset + 512;
        let end = start
            .checked_add(size)
            .ok_or_else(|| fail("Autobricks PKI certificate archive contents are invalid."))?;
        if end > tar.len() {
            return Err(fail(
                "Autobricks PKI certificate archive contents are invalid.",
            ));
        }
        files.insert(name.to_owned(), tar[start..end].to_vec());
        offset = start + size.div_ceil(512) * 512;
    }
    if files.len() != expected.len() {
        return Err(fail(
            "Autobricks PKI certificate archive contents are invalid.",
        ));
    }
    Ok(files)
}

fn install_server_identity(input: &SetupInput, pki: &Path) -> Result<(), String> {
    input
        .server_certificate_ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| fail("Server certificate IP is invalid."))?;
    let user = console_user()?;
    let staging = temporary_directory()?;
    let result = (|| {
        run_quiet(Command::new("/usr/sbin/chown").args([&user, staging.to_str().unwrap()]))?;
        let request = json!({
            "issuer": input.pki_issuer,
            "profile": {"kind": "server", "common_name": format!("jwt-{}", random_hex(6)?), "ip_addresses": [input.server_certificate_ip]}
        }).to_string();
        let mut child = Command::new("/usr/bin/sudo")
            .args(["-H", "-u", &user])
            .arg(pki)
            .arg("create")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| fail(error.to_string()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| fail("Autobricks PKI input is unavailable."))?
            .write_all(request.as_bytes())
            .map_err(|error| fail(error.to_string()))?;
        let created = child
            .wait_with_output()
            .map_err(|error| fail(error.to_string()))?;
        if !created.status.success() {
            return Err(fail(
                String::from_utf8_lossy(&created.stderr).trim().to_owned(),
            ));
        }
        let response: Value = serde_json::from_slice(&created.stdout)
            .map_err(|_| fail("Autobricks PKI did not return valid JSON."))?;
        let fingerprint = find_fingerprint(&response).ok_or_else(|| {
            fail("Autobricks PKI did not return a valid certificate fingerprint.")
        })?;
        let target = staging.join("server");
        run_quiet(
            Command::new("/usr/bin/sudo")
                .args(["-H", "-u", &user])
                .arg(pki)
                .arg("download")
                .args([&fingerprint, target.to_str().unwrap()]),
        )?;
        let archive = staging.join("server.tar.gz");
        if !archive.is_file() {
            return Err(fail("Autobricks PKI certificate archive was not created."));
        }
        let files = extract_identity_archive(&archive)?;
        let extracted = staging.join("identity");
        fs::create_dir(&extracted).map_err(|error| fail(error.to_string()))?;
        for (name, contents) in files {
            write_private(&extracted.join(name), &contents)?;
        }
        let issued_certificate = extracted.join("certificate.pem");
        let issued_key = extracted.join("private-key.pem");
        let issued_chain = extracted.join("trust-chain");
        let reported = run(Command::new("/usr/bin/openssl").args([
            "x509",
            "-in",
            issued_certificate.to_str().unwrap(),
            "-noout",
            "-fingerprint",
            "-sha256",
        ]))?;
        let reported = String::from_utf8_lossy(&reported.stdout)
            .split_once('=')
            .map(|(_, value)| value.replace(':', "").trim().to_ascii_lowercase())
            .unwrap_or_default();
        if reported != fingerprint {
            return Err(fail(
                "Downloaded certificate fingerprint does not match the issued certificate.",
            ));
        }
        let certificate_key = run(Command::new("/usr/bin/openssl").args([
            "x509",
            "-in",
            issued_certificate.to_str().unwrap(),
            "-pubkey",
            "-noout",
        ]))?;
        let private_public = run(Command::new("/usr/bin/openssl").args([
            "pkey",
            "-in",
            issued_key.to_str().unwrap(),
            "-pubout",
        ]))?;
        if certificate_key.stdout != private_public.stdout {
            return Err(fail("Downloaded certificate and private key do not match."));
        }
        run_quiet(Command::new("/usr/bin/openssl").args([
            "verify",
            "-CAfile",
            issued_chain.to_str().unwrap(),
            issued_certificate.to_str().unwrap(),
        ]))?;
        write_private(
            &input.server_certificate,
            &fs::read(&issued_certificate).map_err(|error| fail(error.to_string()))?,
        )?;
        write_private(
            &input.server_private_key,
            &fs::read(&issued_key).map_err(|error| fail(error.to_string()))?,
        )?;
        let chain = fs::read(&issued_chain).map_err(|error| fail(error.to_string()))?;
        write_private(&input.server_trust_chain, &chain)?;
        if input.runtime_transports.iter().any(|value| value == "MTLS") {
            write_private(&input.client_trust_chain, &chain)?;
        }
        Ok(())
    })();
    let _ = fs::remove_dir_all(staging);
    result
}

fn setup() -> Result<String, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(fail("Administrator authorization is required."));
    }
    let source = env::args_os()
        .nth(1)
        .ok_or_else(|| fail("Setup input is required."))?;
    if env::args_os().nth(2).is_some() {
        return Err(fail("Setup input is required."));
    }
    let metadata = fs::metadata(&source).map_err(|_| fail("Setup input is invalid."))?;
    if !metadata.is_file() || metadata.len() > 65_536 {
        return Err(fail("Setup input is invalid."));
    }
    let input: SetupInput =
        serde_json::from_slice(&fs::read(source).map_err(|_| fail("Setup input is invalid."))?)
            .map_err(|_| fail("Setup input is invalid."))?;
    if input.runtime_transports.first().map(String::as_str) != Some("UNIX") {
        return Err(fail("UNIX transport is required."));
    }
    let transports: HashSet<&str> = input
        .runtime_transports
        .iter()
        .map(String::as_str)
        .collect();
    if transports.len() != input.runtime_transports.len()
        || transports
            .iter()
            .any(|item| !["UNIX", "TCP", "TLS", "MTLS"].contains(item))
    {
        return Err(fail("Transport selection is invalid."));
    }
    if !(1..=86400).contains(&input.timeout) || !(7..=30).contains(&input.backup_interval_days) {
        return Err(fail("Timeout or backup interval is invalid."));
    }
    if !input.backup_directory.is_absolute() {
        return Err(fail("Backup directory must be absolute."));
    }
    let secure = transports.contains("TLS") || transports.contains("MTLS");
    if secure && !input.use_pki {
        return Err(fail("TLS transports require Autobricks PKI."));
    }
    if input.use_pki
        && (input.pki_issuer.trim().is_empty() || input.pki_issuer.contains(['\r', '\n', ':']))
    {
        return Err(fail("PKI issuer is invalid."));
    }
    if secure
        && [
            &input.server_certificate,
            &input.server_private_key,
            &input.server_trust_chain,
        ]
        .iter()
        .any(|path| !path.is_absolute())
    {
        return Err(fail("TLS file paths must be absolute."));
    }
    if transports.contains("MTLS") && !input.client_trust_chain.is_absolute() {
        return Err(fail("The client trust chain path must be absolute."));
    }
    let pki = if input.use_pki {
        Some(executable(&[
            "/usr/local/bin/abpki-cli",
            "/opt/homebrew/bin/abpki-cli",
        ])?)
    } else {
        None
    };
    let softhsm = executable(&[
        "/opt/homebrew/bin/softhsm2-util",
        "/usr/local/bin/softhsm2-util",
    ])?;
    let module = [
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.dylib",
        "/usr/local/lib/softhsm/libsofthsm2.dylib",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
    .ok_or_else(|| fail("SoftHSM2 PKCS#11 module is unavailable."))?;
    for (path, mode) in [
        (CONFIG_ROOT, 0o750),
        (STATE_ROOT, 0o750),
        (input.backup_directory.to_str().unwrap(), 0o750),
        (TOKEN_DIRECTORY, 0o700),
    ] {
        fs::create_dir_all(path).map_err(|error| fail(error.to_string()))?;
        fs::set_permissions(path, Permissions::from_mode(mode))
            .map_err(|error| fail(error.to_string()))?;
    }
    write_private(Path::new(SOFTHSM_CONFIG), format!("directories.tokendir = {TOKEN_DIRECTORY}\nobjectstore.backend = file\nlog.level = ERROR\n").as_bytes())?;
    let listing = run(Command::new(&softhsm)
        .arg("--show-slots")
        .env("SOFTHSM2_CONF", SOFTHSM_CONFIG))?;
    if !String::from_utf8_lossy(&listing.stdout)
        .contains(&format!("Label:            {TOKEN_LABEL}"))
    {
        let so_pin = random_hex(24)?;
        let mut pin_bytes = [0u8; 16];
        random_fill(&mut pin_bytes).map_err(|error| fail(error.to_string()))?;
        let user_pin: String = pin_bytes
            .iter()
            .map(|byte| char::from(b'0' + byte % 10))
            .collect();
        run_quiet(
            Command::new(&softhsm)
                .args([
                    "--init-token",
                    "--free",
                    "--label",
                    TOKEN_LABEL,
                    "--so-pin",
                    &so_pin,
                    "--pin",
                    &user_pin,
                ])
                .env("SOFTHSM2_CONF", SOFTHSM_CONFIG),
        )?;
        run_quiet(Command::new("/usr/bin/security").args([
            "add-generic-password",
            "-U",
            "-s",
            "com.autobricks.jwt.hsm",
            "-a",
            "runtime",
            "-w",
            &user_pin,
            "/Library/Keychains/System.keychain",
        ]))?;
    }
    let keychain_pin = run(Command::new("/usr/bin/security").args([
        "find-generic-password",
        "-s",
        "com.autobricks.jwt.hsm",
        "-a",
        "runtime",
        "-w",
        "/Library/Keychains/System.keychain",
    ]))?;
    if secure {
        let required = [
            &input.server_certificate,
            &input.server_private_key,
            &input.server_trust_chain,
        ];
        let missing = required.iter().any(|path| !path.is_file())
            || (transports.contains("MTLS") && !input.client_trust_chain.is_file());
        if missing {
            install_server_identity(&input, pki.as_ref().unwrap())?;
        }
    }
    let yes_no = |value| if value { "true" } else { "false" };
    let mut lines = vec![
        format!("timeout: {}", input.timeout),
        format!("backup_directory: {}", input.backup_directory.display()),
        format!("backup_interval_days: {}", input.backup_interval_days),
        format!("log_request: {}", yes_no(input.log_request)),
        format!("log_query: {}", yes_no(input.log_query)),
        format!("log_issuance: {}", yes_no(input.log_issuance)),
        format!("log_audit: {}", yes_no(input.log_audit)),
        format!(
            "require_token_for_query_and_revoke: {}",
            yes_no(input.require_token)
        ),
        "management_socket: /var/run/autobricks-jwt/management.sock".into(),
        "inspection_socket: /var/run/autobricks-jwt/inspection.sock".into(),
        "audit_query_socket: /var/run/autobricks-jwt/audit-query.sock".into(),
        "database_path: /usr/local/var/lib/autobricks-jwt/autobricks-jwt.db".into(),
        "hsm_helper: /usr/local/libexec/autobricks-jwt-hsm".into(),
        "hsm_key_namespace: autobricks-jwt/database".into(),
        format!("runtime_transports: {}", input.runtime_transports.join(",")),
        "service_socket: /var/run/autobricks-jwt/service.sock".into(),
        "cache_library: /usr/local/lib/libautobricks_cache.dylib".into(),
        "openssl: /usr/bin/openssl".into(),
        format!(
            "certificate_renewal_time: {}",
            input.certificate_renewal_time
        ),
    ];
    if transports.contains("TCP") {
        lines.push(format!(
            "tcp_address: {}",
            validate_address(&input.tcp_address)?
        ));
    }
    if transports.contains("TLS") {
        lines.push(format!(
            "tls_address: {}",
            validate_address(&input.tls_address)?
        ));
    }
    if transports.contains("MTLS") {
        lines.push(format!(
            "mtls_address: {}",
            validate_address(&input.mtls_address)?
        ));
    }
    if secure {
        lines.extend([
            format!("server_certificate: {}", input.server_certificate.display()),
            format!("server_private_key: {}", input.server_private_key.display()),
            format!("server_trust_chain: {}", input.server_trust_chain.display()),
        ]);
    }
    if transports.contains("MTLS") {
        lines.push(format!(
            "client_trust_chain: {}",
            input.client_trust_chain.display()
        ));
    }
    if let Some(pki) = pki {
        fs::create_dir_all(format!("{STATE_ROOT}/pki")).map_err(|error| fail(error.to_string()))?;
        lines.extend([
            format!("pki_client: {}", pki.display()),
            format!("pki_issuer: {}", input.pki_issuer),
            format!("pki_staging_directory: {STATE_ROOT}/pki"),
        ]);
    }
    if input.use_truelog {
        lines.push(format!(
            "truelog_client: {}",
            executable(&[
                "/usr/local/bin/ab-truelog-cli",
                "/opt/homebrew/bin/ab-truelog-cli"
            ])?
            .display()
        ));
    }
    let new_config = PathBuf::from(format!("{CONFIG}.new"));
    write_private(&new_config, format!("{}\n", lines.join("\n")).as_bytes())?;
    run_quiet(
        Command::new("/usr/local/sbin/ab-jwtd")
            .args(["--check-config", new_config.to_str().unwrap()]),
    )?;
    fs::rename(&new_config, CONFIG).map_err(|error| fail(error.to_string()))?;
    let database = Path::new(STATE_ROOT).join("autobricks-jwt.db");
    let initialized = if !database.exists() {
        let output = run(Command::new("/usr/local/sbin/ab-jwtd")
            .args(["--initialize", CONFIG])
            .env("SOFTHSM2_CONF", SOFTHSM_CONFIG)
            .env("AUTOBRICKS_JWT_PKCS11_MODULE", module)
            .env("AUTOBRICKS_JWT_HSM_TOKEN", TOKEN_LABEL)
            .env(
                "AUTOBRICKS_JWT_HSM_PIN",
                String::from_utf8_lossy(&keychain_pin.stdout).trim(),
            ))?;
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        "Protected storage already exists.".into()
    };
    for directory in ["/var/run/autobricks-jwt", "/var/run/autobricks-jwt-cli"] {
        fs::create_dir_all(directory).map_err(|error| fail(error.to_string()))?;
    }
    for (label, plist) in [
        (
            "com.autobricks.jwt.server",
            "/Library/LaunchDaemons/com.autobricks.jwt.server.plist",
        ),
        (
            "com.autobricks.jwt.cli",
            "/Library/LaunchDaemons/com.autobricks.jwt.cli.plist",
        ),
    ] {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &format!("system/{label}")])
            .output();
        run_quiet(Command::new("/bin/launchctl").args(["bootstrap", "system", plist]))?;
        run_quiet(Command::new("/bin/launchctl").args(["enable", &format!("system/{label}")]))?;
    }
    fs::write(CONFIGURED_MARKER, b"configured\n").map_err(|error| fail(error.to_string()))?;
    fs::set_permissions(CONFIGURED_MARKER, Permissions::from_mode(0o644))
        .map_err(|error| fail(error.to_string()))?;
    Ok(format!(
        "Autobricks JWT is configured and running.\n{initialized}"
    ))
}

fn main() {
    match setup() {
        Ok(message) => println!("{message}"),
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::extract_identity_archive;
    use flate2::{Compression, write::GzEncoder};
    use std::fs;
    use std::io::Write;

    fn archive(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, kind, contents) in entries {
            let mut header = [0u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[100..108].copy_from_slice(b"0000600\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            let size = format!("{:011o}\0", contents.len());
            header[124..136].copy_from_slice(size.as_bytes());
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].fill(b' ');
            header[156] = *kind;
            header[257..263].copy_from_slice(b"ustar\0");
            let checksum: usize = header.iter().map(|byte| *byte as usize).sum();
            header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&header);
            tar.extend_from_slice(contents);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extracts_only_the_three_required_identity_files() {
        let temporary =
            std::env::temp_dir().join(format!("jwt-native-archive-{}", std::process::id()));
        fs::write(
            &temporary,
            archive(&[
                ("certificate.pem", b'0', b"certificate"),
                ("private-key.pem", b'0', b"key"),
                ("trust-chain", b'0', b"chain"),
            ]),
        )
        .unwrap();
        let files = extract_identity_archive(&temporary).unwrap();
        fs::remove_file(temporary).unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(files["private-key.pem"], b"key");
    }

    #[test]
    fn rejects_archive_path_and_link_injection() {
        let temporary =
            std::env::temp_dir().join(format!("jwt-native-archive-reject-{}", std::process::id()));
        fs::write(
            &temporary,
            archive(&[
                ("../certificate.pem", b'0', b"certificate"),
                ("private-key.pem", b'2', b"key"),
                ("trust-chain", b'0', b"chain"),
            ]),
        )
        .unwrap();
        assert!(extract_identity_archive(&temporary).is_err());
        fs::remove_file(temporary).unwrap();
    }
}
