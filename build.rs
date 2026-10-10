use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"));
    let version_path = manifest_dir.join("VERSION");
    let version = fs::read_to_string(&version_path)
        .expect("VERSION must be readable")
        .trim()
        .to_owned();
    let package_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION is required");

    if version != package_version {
        panic!("Cargo.toml version {package_version} does not match VERSION {version}");
    }

    println!("cargo:rerun-if-changed={}", version_path.display());
    println!("cargo:rustc-env=AUTOBRICKS_JWT_VERSION={version}");
}
