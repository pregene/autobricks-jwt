use std::{
    ffi::{CStr, CString, c_char},
    path::Path,
};

use libloading::Library;
use serde_json::Value;

use crate::service_error::ServiceError;

type Initialize = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;
type Query = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;
type Status = unsafe extern "C" fn(*const c_char) -> *mut c_char;
type Uninitialize = unsafe extern "C" fn() -> *mut c_char;
type StringFree = unsafe extern "C" fn(*mut c_char);

pub struct AutobricksCache {
    _library: Library,
    query: Query,
    insert: Query,
    update: Query,
    delete: Query,
    status: Status,
    uninitialize: Uninitialize,
    string_free: StringFree,
    initialized: bool,
}

impl AutobricksCache {
    pub fn initialize(
        library_path: &Path,
        connection_config: &str,
        cache_config: &str,
    ) -> Result<Self, ServiceError> {
        let library = unsafe { Library::new(library_path) }.map_err(|_| {
            ServiceError::service_unavailable("Autobricks Cache library cannot be loaded")
        })?;
        let initialize: Initialize = unsafe { load_symbol(&library, b"ab_cache_initialize\0")? };
        let query: Query = unsafe { load_symbol(&library, b"ab_cache_query\0")? };
        let insert: Query = unsafe { load_symbol(&library, b"ab_cache_insert\0")? };
        let update: Query = unsafe { load_symbol(&library, b"ab_cache_update\0")? };
        let delete: Query = unsafe { load_symbol(&library, b"ab_cache_delete\0")? };
        let status: Status = unsafe { load_symbol(&library, b"ab_cache_status\0")? };
        let uninitialize: Uninitialize =
            unsafe { load_symbol(&library, b"ab_cache_uninitialize\0")? };
        let string_free: StringFree = unsafe { load_symbol(&library, b"ab_cache_string_free\0")? };

        let connection_config = c_string(connection_config, "Cache Connection configuration")?;
        let cache_config = c_string(cache_config, "Cache Definition configuration")?;
        let response = unsafe {
            call_json(
                initialize(connection_config.as_ptr(), cache_config.as_ptr()),
                string_free,
            )?
        };
        ensure_success(&response, "Autobricks Cache initialization failed")?;

        Ok(Self {
            _library: library,
            query,
            insert,
            update,
            delete,
            status,
            uninitialize,
            string_free,
            initialized: true,
        })
    }

    pub fn query(&self, cache_id: &str, input: &Value) -> Result<Vec<Value>, ServiceError> {
        let cache_id = c_string(cache_id, "cache_id")?;
        let input = c_string(&input.to_string(), "Cache query input")?;
        let response = unsafe {
            call_json(
                (self.query)(cache_id.as_ptr(), input.as_ptr()),
                self.string_free,
            )?
        };
        ensure_success(&response, "Autobricks Cache query failed")?;
        response
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| ServiceError::source_data_unavailable("Cache records are missing"))
    }

    pub fn status(&self, cache_id: &str) -> Result<Value, ServiceError> {
        let cache_id = c_string(cache_id, "cache_id")?;
        let response = unsafe { call_json((self.status)(cache_id.as_ptr()), self.string_free)? };
        ensure_success(&response, "Autobricks Cache status failed")?;
        Ok(response)
    }

    pub fn insert(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        self.mutate(
            self.insert,
            cache_id,
            input,
            "Autobricks Cache insert failed",
        )
    }

    pub fn update(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        self.mutate(
            self.update,
            cache_id,
            input,
            "Autobricks Cache update failed",
        )
    }

    pub fn delete(&self, cache_id: &str, input: &Value) -> Result<(), ServiceError> {
        self.mutate(
            self.delete,
            cache_id,
            input,
            "Autobricks Cache delete failed",
        )
    }

    fn mutate(
        &self,
        operation: Query,
        cache_id: &str,
        input: &Value,
        message: &'static str,
    ) -> Result<(), ServiceError> {
        let cache_id = c_string(cache_id, "cache_id")?;
        let input = c_string(&input.to_string(), "Cache mutation input")?;
        let response = unsafe {
            call_json(
                operation(cache_id.as_ptr(), input.as_ptr()),
                self.string_free,
            )?
        };
        ensure_success(&response, message)
    }

    pub fn uninitialize(mut self) -> Result<(), ServiceError> {
        self.stop()
    }

    fn stop(&mut self) -> Result<(), ServiceError> {
        if !self.initialized {
            return Ok(());
        }
        let response = unsafe { call_json((self.uninitialize)(), self.string_free)? };
        ensure_success(&response, "Autobricks Cache shutdown failed")?;
        self.initialized = false;
        Ok(())
    }
}

impl Drop for AutobricksCache {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

unsafe fn load_symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, ServiceError> {
    unsafe { library.get::<T>(name) }
        .map(|symbol| *symbol)
        .map_err(|_| ServiceError::service_unavailable("Autobricks Cache ABI symbol is missing"))
}

unsafe fn call_json(pointer: *mut c_char, string_free: StringFree) -> Result<Value, ServiceError> {
    if pointer.is_null() {
        return Err(ServiceError::service_unavailable(
            "Autobricks Cache returned no response",
        ));
    }
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes().to_vec();
    unsafe { string_free(pointer) };
    serde_json::from_slice(&bytes)
        .map_err(|_| ServiceError::source_data_unavailable("Cache response JSON is invalid"))
}

fn ensure_success(response: &Value, message: &'static str) -> Result<(), ServiceError> {
    if response.get("code").and_then(Value::as_i64) == Some(0) {
        Ok(())
    } else {
        Err(ServiceError::source_data_unavailable(message))
    }
}

fn c_string(value: &str, name: &'static str) -> Result<CString, ServiceError> {
    CString::new(value)
        .map_err(|_| ServiceError::configuration_invalid(format!("{name} contains a null byte")))
}
