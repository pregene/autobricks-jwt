use std::{
    fs::{self, DirBuilder, Permissions},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
};

use crate::service_error::ServiceError;

const DIRECTORY_MODE: u32 = 0o750;
const SOCKET_MODE: u32 = 0o660;

pub struct UnixSocketEndpoint {
    listener: UnixListener,
    path: PathBuf,
    created_parent: bool,
}

impl UnixSocketEndpoint {
    pub fn bind(path: &Path) -> Result<Self, ServiceError> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(ServiceError::configuration_invalid(
                "Unix socket path must be an absolute file path",
            ));
        }
        let parent = path.parent().ok_or_else(|| {
            ServiceError::configuration_invalid("Unix socket parent directory is missing")
        })?;
        let created_parent = if parent.exists() {
            validate_parent(parent)?;
            false
        } else {
            let mut builder = DirBuilder::new();
            builder.mode(DIRECTORY_MODE);
            builder.create(parent).map_err(|_| {
                ServiceError::service_unavailable("Unix socket directory cannot be created")
            })?;
            true
        };

        if path.exists() {
            if created_parent {
                let _ = fs::remove_dir(parent);
            }
            return Err(ServiceError::service_unavailable(
                "Unix socket path is already in use",
            ));
        }

        let listener = match UnixListener::bind(path) {
            Ok(listener) => listener,
            Err(_) => {
                if created_parent {
                    let _ = fs::remove_dir(parent);
                }
                return Err(ServiceError::service_unavailable(
                    "Unix socket cannot be created",
                ));
            }
        };
        if fs::set_permissions(path, Permissions::from_mode(SOCKET_MODE)).is_err() {
            let _ = fs::remove_file(path);
            if created_parent {
                let _ = fs::remove_dir(parent);
            }
            return Err(ServiceError::service_unavailable(
                "Unix socket permissions cannot be applied",
            ));
        }

        Ok(Self {
            listener,
            path: path.to_path_buf(),
            created_parent,
        })
    }

    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UnixSocketEndpoint {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        if self.created_parent
            && let Some(parent) = self.path.parent()
        {
            let _ = fs::remove_dir(parent);
        }
    }
}

fn validate_parent(parent: &Path) -> Result<(), ServiceError> {
    let metadata = fs::metadata(parent).map_err(|_| {
        ServiceError::service_unavailable("Unix socket directory cannot be inspected")
    })?;
    if !metadata.is_dir() {
        return Err(ServiceError::configuration_invalid(
            "Unix socket parent path is not a directory",
        ));
    }
    if metadata.mode() & 0o007 != 0 {
        return Err(ServiceError::configuration_invalid(
            "Unix socket directory permits world access",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{FileTypeExt, MetadataExt},
        path::PathBuf,
    };

    use uuid::Uuid;

    use super::UnixSocketEndpoint;

    #[test]
    #[ignore = "creates a local Unix socket under /tmp"]
    fn creates_restricts_and_removes_unix_socket() {
        let directory = PathBuf::from(format!(
            "/tmp/autobricks-jwt-unix-socket-test-{}",
            Uuid::new_v4()
        ));
        let socket_path = directory.join("ab-jwtd.sock");

        let endpoint = UnixSocketEndpoint::bind(&socket_path).unwrap();
        endpoint.listener().local_addr().unwrap();
        assert_eq!(endpoint.path(), socket_path);

        let socket_metadata = fs::symlink_metadata(&socket_path).unwrap();
        let parent_metadata = fs::metadata(&directory).unwrap();
        assert!(socket_metadata.file_type().is_socket());
        assert_eq!(socket_metadata.mode() & 0o777, 0o660);
        assert_eq!(parent_metadata.mode() & 0o777, 0o750);
        assert_eq!(socket_metadata.mode() & 0o007, 0);
        assert_eq!(parent_metadata.mode() & 0o007, 0);

        println!("Unix socket created: {}", socket_path.display());
        println!("Unix socket file type: socket");
        println!("Unix socket mode: 0660");
        println!("Unix socket parent mode: 0750");
        println!("Unix socket world access: denied");

        drop(endpoint);
        assert!(!socket_path.exists());
        assert!(!directory.exists());
        println!("Unix socket cleanup: removed");
    }
}
