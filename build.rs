use std::{env, fs, path::PathBuf, process};

fn main() {
    if let Err(error) = configure_build() {
        eprintln!("build configuration failed: {error}");
        process::exit(1);
    }
}

fn configure_build() -> Result<(), String> {
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| "CARGO_MANIFEST_DIR is required".to_owned())?,
    );
    let version_path = manifest_dir.join("VERSION");
    let version = fs::read_to_string(&version_path)
        .map_err(|error| format!("VERSION must be readable: {error}"))?
        .trim()
        .to_owned();
    let package_version =
        env::var("CARGO_PKG_VERSION").map_err(|_| "CARGO_PKG_VERSION is required".to_owned())?;

    if version != package_version {
        return Err(format!(
            "Cargo.toml version {package_version} does not match VERSION {version}"
        ));
    }

    println!("cargo:rerun-if-changed={}", version_path.display());
    println!("cargo:rustc-env=AUTOBRICKS_JWT_VERSION={version}");
    Ok(())
}
