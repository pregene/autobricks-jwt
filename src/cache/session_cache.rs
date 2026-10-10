use serde_json::json;
use uuid::Uuid;

use crate::{autobricks_cache::AutobricksCache, service_error::ServiceError};

pub trait SessionCache {
    fn insert(&mut self, token_id: Uuid, token: &str, expires_at: u64) -> Result<(), ServiceError>;
    fn touch(&mut self, token_id: Uuid) -> Result<(), ServiceError>;
    fn remove(&mut self, token_id: Uuid) -> Result<(), ServiceError>;
}

pub struct AutobricksSessionCache<'a> {
    cache: &'a AutobricksCache,
    cache_id: String,
}

impl<'a> AutobricksSessionCache<'a> {
    pub fn new(cache: &'a AutobricksCache, cache_id: impl Into<String>) -> Self {
        Self {
            cache,
            cache_id: cache_id.into(),
        }
    }
}

impl SessionCache for AutobricksSessionCache<'_> {
    fn insert(&mut self, token_id: Uuid, token: &str, expires_at: u64) -> Result<(), ServiceError> {
        self.cache.insert(
            &self.cache_id,
            &json!({
                "token_id": token_id,
                "token": token,
                "expires_at": expires_at
            }),
        )
    }

    fn touch(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
        let records = self
            .cache
            .query(&self.cache_id, &json!({ "token_id": token_id }))?;
        if records.len() == 1 {
            Ok(())
        } else {
            Err(
                ServiceError::classified(8060, "session is not found or expired")
                    .expect("8060 must be assigned"),
            )
        }
    }

    fn remove(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
        self.cache
            .delete(&self.cache_id, &json!({ "token_id": token_id }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[derive(Default)]
    pub(crate) struct MemorySessionCache {
        pub(crate) inserted: Vec<Uuid>,
        pub(crate) touched: Vec<Uuid>,
        pub(crate) removed: Vec<Uuid>,
    }

    impl SessionCache for MemorySessionCache {
        fn insert(
            &mut self,
            token_id: Uuid,
            _token: &str,
            _expires_at: u64,
        ) -> Result<(), ServiceError> {
            self.inserted.push(token_id);
            Ok(())
        }

        fn touch(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
            self.touched.push(token_id);
            Ok(())
        }

        fn remove(&mut self, token_id: Uuid) -> Result<(), ServiceError> {
            self.removed.push(token_id);
            Ok(())
        }
    }
}
