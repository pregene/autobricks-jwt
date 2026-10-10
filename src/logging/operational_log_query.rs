use std::{path::Path, process::Command};

use crate::service_error::ServiceError;

pub fn query_journal(since: Option<&str>, lines: Option<u32>) -> Result<String, ServiceError> {
    query_with(Path::new("journalctl"), since, lines)
}

fn query_with(
    executable: &Path,
    since: Option<&str>,
    lines: Option<u32>,
) -> Result<String, ServiceError> {
    let mut command = Command::new(executable);
    command.args([
        "--unit",
        "autobricks-jwt.service",
        "--no-pager",
        "--output",
        "short-iso",
    ]);
    if let Some(since) = since {
        if since.is_empty() || since.starts_with('-') || since.contains('\0') {
            return Err(ServiceError::invalid_request(
                "journal start time is invalid",
            ));
        }
        command.arg("--since").arg(since);
    }
    if let Some(lines) = lines {
        if lines == 0 || lines > 100_000 {
            return Err(ServiceError::invalid_request(
                "journal line limit is invalid",
            ));
        }
        command.arg("--lines").arg(lines.to_string());
    }
    let output = command
        .output()
        .map_err(|_| ServiceError::service_unavailable("journalctl is unavailable"))?;
    if !output.status.success() {
        return Err(ServiceError::service_unavailable(
            "operational journal query failed",
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| ServiceError::service_unavailable("journal output is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use uuid::Uuid;

    use super::*;

    #[test]
    fn executes_fixed_unit_query_without_shell_interpolation() {
        let root = std::env::temp_dir().join(format!("ab-jwt-journal-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let executable = root.join("journalctl-test");
        fs::write(&executable, "#!/bin/sh\nprintf '%s\\n' \"$@\"\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let output = query_with(&executable, Some("2026-10-11 00:00:00"), Some(50)).unwrap();
        let arguments = output.lines().collect::<Vec<_>>();
        assert_eq!(
            arguments,
            [
                "--unit",
                "autobricks-jwt.service",
                "--no-pager",
                "--output",
                "short-iso",
                "--since",
                "2026-10-11 00:00:00",
                "--lines",
                "50"
            ]
        );
        fs::remove_file(executable).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_option_injection_and_unbounded_line_requests() {
        assert_eq!(
            query_with(Path::new("journalctl"), Some("--unit attacker"), None)
                .unwrap_err()
                .code(),
            8001
        );
        assert_eq!(
            query_with(Path::new("journalctl"), None, Some(0))
                .unwrap_err()
                .code(),
            8001
        );
        assert_eq!(
            query_with(Path::new("journalctl"), None, Some(100_001))
                .unwrap_err()
                .code(),
            8001
        );
    }
}
