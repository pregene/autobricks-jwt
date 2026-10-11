use std::path::Path;

use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};

use crate::service_error::ServiceError;

const PREVIOUS_ID: &[u8] = &[0x01];
const CURRENT_ID: &[u8] = &[0x02];
const AES_256_BYTES: usize = 32;
const WRAPPED_PREFIX: &[u8] = b"wrapped:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseKeyRole {
    Previous,
    Current,
}

impl DatabaseKeyRole {
    fn id(self) -> &'static [u8] {
        match self {
            Self::Previous => PREVIOUS_ID,
            Self::Current => CURRENT_ID,
        }
    }
}

pub struct SoftHsm2KeyStore {
    _context: Pkcs11,
    session: Session,
    object_label: Vec<u8>,
}

impl SoftHsm2KeyStore {
    pub fn open(
        module: impl AsRef<Path>,
        token_label: &str,
        user_pin: AuthPin,
        object_label: &str,
    ) -> Result<Self, ServiceError> {
        if !module.as_ref().is_absolute()
            || token_label.trim().is_empty()
            || object_label.trim().is_empty()
        {
            return Err(ServiceError::configuration_invalid(
                "SoftHSM2 module, token label, and object label are required",
            ));
        }

        let context = Pkcs11::new(module.as_ref())
            .map_err(|_| hsm_unavailable("SoftHSM2 PKCS#11 module cannot be loaded"))?;
        context
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|_| hsm_unavailable("SoftHSM2 PKCS#11 module cannot be initialized"))?;
        let slot = context
            .get_slots_with_token()
            .map_err(|_| hsm_unavailable("SoftHSM2 token slots cannot be listed"))?
            .into_iter()
            .find(|slot| {
                context
                    .get_token_info(*slot)
                    .map(|info| info.label() == token_label)
                    .unwrap_or(false)
            })
            .ok_or_else(|| hsm_unavailable("configured SoftHSM2 token is unavailable"))?;
        let session = context
            .open_rw_session(slot)
            .map_err(|_| hsm_unavailable("SoftHSM2 session cannot be opened"))?;
        session
            .login(UserType::User, Some(&user_pin))
            .map_err(|_| hsm_unavailable("SoftHSM2 token login failed"))?;

        Ok(Self {
            _context: context,
            session,
            object_label: object_label.as_bytes().to_vec(),
        })
    }

    pub fn generate(&self, role: DatabaseKeyRole) -> Result<(), ServiceError> {
        if !self.objects(role)?.is_empty() {
            return Err(key_failure("HSM Database-key role already exists"));
        }
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::ValueLen((AES_256_BYTES as u64).into()),
            Attribute::Encrypt(true),
            Attribute::Decrypt(true),
            Attribute::Label(self.object_label.clone()),
            Attribute::Id(role.id().to_vec()),
        ];
        self.session
            .generate_key(&Mechanism::AesKeyGen, &template)
            .map_err(|_| key_failure("HSM Database key cannot be generated"))?;
        self.require_exactly_one(role)
    }

    pub fn roles(&self) -> Result<(usize, usize), ServiceError> {
        Ok((
            self.objects(DatabaseKeyRole::Previous)?.len(),
            self.objects(DatabaseKeyRole::Current)?.len(),
        ))
    }

    pub fn rotate(&self) -> Result<(), ServiceError> {
        let current = self.require_exactly_one_handle(DatabaseKeyRole::Current)?;
        for previous in self.objects(DatabaseKeyRole::Previous)? {
            self.session
                .destroy_object(previous)
                .map_err(|_| key_failure("HSM PREVIOUS key cannot be removed"))?;
        }
        self.session
            .update_attributes(current, &[Attribute::Id(PREVIOUS_ID.to_vec())])
            .map_err(|_| key_failure("HSM CURRENT key cannot become PREVIOUS"))?;
        self.generate(DatabaseKeyRole::Current)?;
        match self.roles()? {
            (1, 1) => Ok(()),
            _ => Err(key_failure("HSM rotation did not preserve two key roles")),
        }
    }

    pub fn encrypt_current(
        &self,
        initialization_vector: [u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let current = self.require_exactly_one_handle(DatabaseKeyRole::Current)?;
        self.session
            .encrypt(
                &Mechanism::AesCbcPad(initialization_vector),
                current,
                plaintext,
            )
            .map_err(|_| key_failure("HSM encryption failed"))
    }

    pub fn decrypt_current(
        &self,
        initialization_vector: [u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        let current = self.require_exactly_one_handle(DatabaseKeyRole::Current)?;
        self.session
            .decrypt(
                &Mechanism::AesCbcPad(initialization_vector),
                current,
                ciphertext,
            )
            .map_err(|_| key_failure("HSM decryption failed"))
    }

    pub fn delete_database_keys(&self) -> Result<(), ServiceError> {
        for role in [DatabaseKeyRole::Previous, DatabaseKeyRole::Current] {
            let mut objects = self.objects(role)?;
            objects.extend(self.wrapped_objects(role)?);
            for object in objects {
                self.session
                    .destroy_object(object)
                    .map_err(|_| key_failure("HSM Database key cannot be deleted"))?;
            }
        }
        match self.roles()? {
            (0, 0)
                if self.wrapped_objects(DatabaseKeyRole::Previous)?.is_empty()
                    && self.wrapped_objects(DatabaseKeyRole::Current)?.is_empty() =>
            {
                Ok(())
            }
            _ => Err(key_failure(
                "HSM Database-key objects remain after deletion",
            )),
        }
    }

    pub fn read_wrapped_database_key(
        &self,
        role: DatabaseKeyRole,
    ) -> Result<Option<[u8; AES_256_BYTES]>, ServiceError> {
        let keys = self.objects(role)?;
        let wrapped = self.wrapped_objects(role)?;
        if keys.is_empty() && wrapped.is_empty() {
            return Ok(None);
        }
        if keys.len() != 1 || wrapped.len() != 1 {
            return Err(key_failure(
                "HSM Database-key role is incomplete or duplicated",
            ));
        }
        let attributes = self
            .session
            .get_attributes(wrapped[0], &[AttributeType::Value])
            .map_err(|_| key_failure("wrapped HSM Database key cannot be read"))?;
        let value = attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(value),
                _ => None,
            })
            .ok_or_else(|| key_failure("wrapped HSM Database key is incomplete"))?;
        if value.len() <= 16 {
            return Err(key_failure("wrapped HSM Database key is invalid"));
        }
        let mut initialization_vector = [0_u8; 16];
        initialization_vector.copy_from_slice(&value[..16]);
        let plaintext = self
            .session
            .decrypt(
                &Mechanism::AesCbcPad(initialization_vector),
                keys[0],
                &value[16..],
            )
            .map_err(|_| key_failure("HSM Database key cannot be unwrapped"))?;
        plaintext
            .try_into()
            .map(Some)
            .map_err(|_| key_failure("unwrapped HSM Database key has an invalid length"))
    }

    pub fn replace_wrapped_database_keys(
        &self,
        previous: [u8; AES_256_BYTES],
        current: [u8; AES_256_BYTES],
    ) -> Result<(), ServiceError> {
        self.delete_database_keys()?;
        if let Err(error) = self
            .create_wrapped_slot(DatabaseKeyRole::Previous, &previous)
            .and_then(|_| self.create_wrapped_slot(DatabaseKeyRole::Current, &current))
        {
            let _ = self.delete_database_keys();
            return Err(error);
        }
        Ok(())
    }

    pub fn initialize_wrapped_current(
        &self,
        current: [u8; AES_256_BYTES],
    ) -> Result<bool, ServiceError> {
        match self.read_wrapped_database_key(DatabaseKeyRole::Current)? {
            Some(_) => Ok(false),
            None => {
                if self.roles()? != (0, 0)
                    || !self.wrapped_objects(DatabaseKeyRole::Previous)?.is_empty()
                {
                    return Err(key_failure("HSM Database-key roles are inconsistent"));
                }
                self.create_wrapped_slot(DatabaseKeyRole::Current, &current)?;
                Ok(true)
            }
        }
    }

    fn create_wrapped_slot(
        &self,
        role: DatabaseKeyRole,
        plaintext: &[u8; AES_256_BYTES],
    ) -> Result<(), ServiceError> {
        self.generate(role)?;
        let key = self.require_exactly_one_handle(role)?;
        let mut initialization_vector = [0_u8; 16];
        getrandom::fill(&mut initialization_vector)
            .map_err(|_| key_failure("HSM wrapping IV cannot be generated"))?;
        let ciphertext = self
            .session
            .encrypt(&Mechanism::AesCbcPad(initialization_vector), key, plaintext)
            .map_err(|_| key_failure("HSM Database key cannot be wrapped"))?;
        let mut value = initialization_vector.to_vec();
        value.extend_from_slice(&ciphertext);
        let label = self.wrapped_label(role);
        self.session
            .create_object(&[
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Private(true),
                Attribute::Label(label),
                Attribute::Value(value),
            ])
            .map_err(|_| key_failure("wrapped HSM Database key cannot be stored"))?;
        Ok(())
    }

    fn wrapped_objects(&self, role: DatabaseKeyRole) -> Result<Vec<ObjectHandle>, ServiceError> {
        let label = self.wrapped_label(role);
        self.session
            .find_objects(&[Attribute::Class(ObjectClass::DATA), Attribute::Label(label)])
            .map_err(|_| key_failure("wrapped HSM Database keys cannot be listed"))
    }

    fn wrapped_label(&self, role: DatabaseKeyRole) -> Vec<u8> {
        let mut label = WRAPPED_PREFIX.to_vec();
        label.extend_from_slice(&self.object_label);
        label.extend_from_slice(match role {
            DatabaseKeyRole::Previous => b":previous",
            DatabaseKeyRole::Current => b":current",
        });
        label
    }

    fn objects(&self, role: DatabaseKeyRole) -> Result<Vec<ObjectHandle>, ServiceError> {
        self.session
            .find_objects(&[
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Label(self.object_label.clone()),
                Attribute::Id(role.id().to_vec()),
            ])
            .map_err(|_| key_failure("HSM Database-key objects cannot be listed"))
    }

    fn require_exactly_one(&self, role: DatabaseKeyRole) -> Result<(), ServiceError> {
        self.require_exactly_one_handle(role).map(|_| ())
    }

    fn require_exactly_one_handle(
        &self,
        role: DatabaseKeyRole,
    ) -> Result<ObjectHandle, ServiceError> {
        let objects = self.objects(role)?;
        if objects.len() == 1 {
            Ok(objects[0])
        } else {
            Err(key_failure(
                "HSM Database-key role is missing or duplicated",
            ))
        }
    }
}

fn hsm_unavailable(message: &'static str) -> ServiceError {
    ServiceError::classified(8085, message).expect("8085 assigned")
}

fn key_failure(message: &'static str) -> ServiceError {
    ServiceError::classified(8086, message).expect("8086 assigned")
}

#[cfg(test)]
mod tests {
    use super::{DatabaseKeyRole, SoftHsm2KeyStore};
    use cryptoki::types::AuthPin;
    use std::{fs, path::PathBuf, process::Command};
    use uuid::Uuid;

    struct TestDirectory(PathBuf);

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    #[ignore = "requires installed SoftHSM2"]
    fn executes_the_complete_isolated_softhsm2_object_lifecycle() {
        let module = PathBuf::from(
            std::env::var_os("AUTOBRICKS_JWT_PKCS11_MODULE")
                .expect("AUTOBRICKS_JWT_PKCS11_MODULE is required"),
        );
        let utility = PathBuf::from(
            std::env::var_os("AUTOBRICKS_JWT_SOFTHSM2_UTIL")
                .expect("AUTOBRICKS_JWT_SOFTHSM2_UTIL is required"),
        );
        let root = std::env::temp_dir().join(format!("abjwt-hsm-{}", Uuid::new_v4()));
        let cleanup = TestDirectory(root.clone());
        let token_directory = root.join("tokens");
        let configuration = root.join("softhsm2.conf");
        fs::create_dir_all(&token_directory).unwrap();
        fs::write(
            &configuration,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
                token_directory.display()
            ),
        )
        .unwrap();

        // SAFETY: This ignored integration test runs as one exact test process
        // before PKCS#11 initialization and removes the isolated configuration.
        unsafe { std::env::set_var("SOFTHSM2_CONF", &configuration) };
        let token_identity = Uuid::new_v4().to_string();
        let token_label = format!("abjwt-{}", &token_identity[..16]);
        let so_pin = "24893175";
        let user_pin = "73916428";
        let initialized = Command::new(&utility)
            .args([
                "--init-token",
                "--free",
                "--label",
                &token_label,
                "--so-pin",
                so_pin,
                "--pin",
                user_pin,
            ])
            .output()
            .unwrap();
        assert!(initialized.status.success());

        let store = SoftHsm2KeyStore::open(
            &module,
            &token_label,
            AuthPin::new(user_pin.into()),
            "autobricks-jwt/database",
        )
        .unwrap();
        println!("SOFTHSM2_LIBRARY_LOAD=PASS");

        store.generate(DatabaseKeyRole::Previous).unwrap();
        println!("SOFTHSM2_KEY_GENERATION=PASS");
        store.generate(DatabaseKeyRole::Current).unwrap();
        assert_eq!(store.roles().unwrap(), (1, 1));
        println!("SOFTHSM2_CURRENT_PREVIOUS=PASS");

        store.rotate().unwrap();
        assert_eq!(store.roles().unwrap(), (1, 1));
        println!("SOFTHSM2_KEY_ROTATION=PASS");

        let initialization_vector = [0x5a; 16];
        let plaintext = b"Autobricks JWT HSM integration verification";
        let ciphertext = store
            .encrypt_current(initialization_vector, plaintext)
            .unwrap();
        assert!(!ciphertext.is_empty());
        assert_ne!(ciphertext, plaintext);
        println!("SOFTHSM2_ENCRYPT=PASS");

        let recovered = store
            .decrypt_current(initialization_vector, &ciphertext)
            .unwrap();
        assert_eq!(recovered, plaintext);
        println!("SOFTHSM2_DECRYPT=PASS");

        store.delete_database_keys().unwrap();
        assert_eq!(store.roles().unwrap(), (0, 0));
        println!("SOFTHSM2_OBJECT_DELETE=PASS");

        let first = [0x31; 32];
        let second = [0x42; 32];
        assert!(store.initialize_wrapped_current(first).unwrap());
        assert_eq!(
            store
                .read_wrapped_database_key(DatabaseKeyRole::Current)
                .unwrap(),
            Some(first)
        );
        store.replace_wrapped_database_keys(first, second).unwrap();
        assert_eq!(
            store
                .read_wrapped_database_key(DatabaseKeyRole::Previous)
                .unwrap(),
            Some(first)
        );
        assert_eq!(
            store
                .read_wrapped_database_key(DatabaseKeyRole::Current)
                .unwrap(),
            Some(second)
        );
        println!("SOFTHSM2_WRAPPED_DATABASE_KEYS=PASS");
        store.delete_database_keys().unwrap();

        drop(store);
        drop(cleanup);
        assert!(!root.exists());
    }
}
