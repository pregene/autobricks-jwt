use std::{path::PathBuf, process::ExitCode};

use autobricks_jwt::{
    VERSION,
    audit_log_repository::AuditLogFilter,
    audit_query::request_audit_query,
    curses_ui,
    management_protocol::ManagementRequest,
    management_service, operational_log_query,
    token_inspection::{TokenInspectionRequest, request_inspection},
};
use uuid::Uuid;

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, String> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [flag] if flag == "--version" || flag == "-V" => {
            Ok(format!("Autobricks JWT Management Client {VERSION}"))
        }
        [flag] if flag == "--help" || flag == "-h" => Ok(help()),
        [
            command,
            client_flag,
            client_socket,
            server_flag,
            server_socket,
        ] if command == "broker"
            && client_flag == "--client-socket"
            && server_flag == "--server-socket" =>
        {
            management_service::serve_broker(
                &PathBuf::from(client_socket),
                &PathBuf::from(server_socket),
                usize::MAX,
            )
            .map_err(|error| error.to_string())?;
            Ok("Management broker stopped".into())
        }
        [command, socket, request_count] if command == "broker" => {
            let request_count = parse_count(request_count)?;
            let server_socket = std::env::var("AUTOBRICKS_JWT_SERVER_MANAGEMENT_SOCKET")
                .map(PathBuf::from)
                .map_err(|_| "AUTOBRICKS_JWT_SERVER_MANAGEMENT_SOCKET is required".to_owned())?;
            management_service::serve_broker(&PathBuf::from(socket), &server_socket, request_count)
                .map_err(|error| error.to_string())?;
            Ok("Management broker stopped".into())
        }
        [command, socket, request_count] if command == "broker-test" => {
            let request_count = parse_count(request_count)?;
            let server_socket = std::env::var("AUTOBRICKS_JWT_SERVER_MANAGEMENT_SOCKET")
                .map(PathBuf::from)
                .map_err(|_| "AUTOBRICKS_JWT_SERVER_MANAGEMENT_SOCKET is required".to_owned())?;
            management_service::serve_broker(&PathBuf::from(socket), &server_socket, request_count)
                .map_err(|error| error.to_string())?;
            Ok("Management broker stopped".into())
        }
        [command, socket, json] if command == "request" => {
            let request: ManagementRequest = serde_json::from_str(json)
                .map_err(|error| format!("management request JSON is invalid: {error}"))?;
            let response = management_service::request(&PathBuf::from(socket), &request)?;
            serde_json::to_string_pretty(&response)
                .map_err(|error| format!("management response serialization failed: {error}"))
        }
        [command, socket] if command == "tui" => {
            curses_ui::run(&PathBuf::from(socket))?;
            Ok("Management interface closed".into())
        }
        [command] if command == "operational-logs" => {
            operational_log_query::query_journal(None, Some(200)).map_err(|error| error.to_string())
        }
        [command, since] if command == "operational-logs" => {
            operational_log_query::query_journal(Some(since), Some(200))
                .map_err(|error| error.to_string())
        }
        [command, socket, request_id, token_id, event_at] if command == "inspect-token" => {
            let request_id =
                Uuid::parse_str(request_id).map_err(|_| "request_id must be a UUID".to_owned())?;
            let token_id =
                Uuid::parse_str(token_id).map_err(|_| "token_id must be a UUID".to_owned())?;
            let response = request_inspection(
                &PathBuf::from(socket),
                &TokenInspectionRequest {
                    request_id,
                    token_id,
                    event_at: event_at.clone(),
                },
            )
            .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&response)
                .map_err(|error| format!("inspection response serialization failed: {error}"))
        }
        [command, socket, filter] if command == "audit-logs" => {
            let filter: AuditLogFilter = serde_json::from_str(filter)
                .map_err(|error| format!("audit filter JSON is invalid: {error}"))?;
            let response = request_audit_query(&PathBuf::from(socket), &filter)
                .map_err(|error| error.to_string())?;
            serde_json::to_string_pretty(&response)
                .map_err(|error| format!("audit response serialization failed: {error}"))
        }
        _ => Err("invalid ab-jwt-cli command-line arguments".into()),
    }
}

fn parse_count(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "request count must be a positive integer".into())
}

fn help() -> String {
    format!(
        "Autobricks JWT Management Client {VERSION} (C) 2026 Autobricks, Co.\n\
Usage:\n\
  ab-jwt-cli request SOCKET JSON\n\
  ab-jwt-cli tui SOCKET\n\
  ab-jwt-cli broker --client-socket SOCKET --server-socket SOCKET\n\
  ab-jwt-cli operational-logs [SINCE]\n\
  ab-jwt-cli audit-logs SOCKET FILTER_JSON\n\
  sudo ab-jwt-cli inspect-token SOCKET REQUEST_ID TOKEN_ID EVENT_AT\n\
  ab-jwt-cli --help\n\
  ab-jwt-cli --version"
    )
}
