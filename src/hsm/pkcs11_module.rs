use std::path::{Path, PathBuf};

use libloading::Library;

use crate::service_error::ServiceError;

const REQUIRED_SYMBOLS: [&[u8]; 3] = [b"C_Initialize\0", b"C_Finalize\0", b"C_GetFunctionList\0"];

pub struct Pkcs11Module {
    _library: Library,
    path: PathBuf,
}

impl Pkcs11Module {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ServiceError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(ServiceError::configuration_invalid(
                "PKCS#11 module path must be absolute",
            ));
        }

        // SAFETY: Loading a configured native module is the intended PKCS#11
        // boundary. No symbol is invoked here; required ABI entry points are
        // resolved and the Library remains owned for the full module lifetime.
        let library = unsafe { Library::new(path) }
            .map_err(|_| hsm_unavailable("PKCS#11 module cannot be loaded"))?;

        for symbol in REQUIRED_SYMBOLS {
            // SAFETY: Symbol lookup does not invoke the entry point. The raw
            // pointer is used only to prove that the required ABI is exported.
            unsafe { library.get::<*const ()>(symbol) }
                .map_err(|_| hsm_unavailable("PKCS#11 module ABI is incomplete"))?;
        }

        Ok(Self {
            _library: library,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn hsm_unavailable(message: &'static str) -> ServiceError {
    ServiceError::classified(8085, message).expect("8085 assigned")
}

#[cfg(test)]
mod tests {
    use super::Pkcs11Module;
    use std::path::PathBuf;

    #[test]
    fn rejects_relative_module_paths() {
        let error = Pkcs11Module::load("libsofthsm2.so").err().unwrap();
        assert_eq!(error.code(), 8090);
    }

    #[test]
    #[ignore = "requires an installed PKCS#11 module"]
    fn loads_configured_pkcs11_module_and_required_abi() {
        let path = PathBuf::from(
            std::env::var_os("AUTOBRICKS_JWT_PKCS11_MODULE")
                .expect("AUTOBRICKS_JWT_PKCS11_MODULE is required"),
        );
        let module = Pkcs11Module::load(&path).unwrap();
        assert_eq!(module.path(), path);
    }
}
