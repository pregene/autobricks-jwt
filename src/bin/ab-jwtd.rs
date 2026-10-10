use std::process::ExitCode;

use autobricks_jwt::{server_application, service_error::ServiceError};

fn main() -> ExitCode {
    match server_application::execute(std::env::args_os().skip(1)) {
        Ok(output) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", render_error(&error));
            ExitCode::from(1)
        }
    }
}

fn render_error(error: &ServiceError) -> String {
    format!(
        "error_code={} error_name={} message={}",
        error.code(),
        error.name(),
        error.public_message()
    )
}
