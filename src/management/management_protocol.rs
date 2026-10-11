use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    database_source::DatabaseSourceInput,
    service_registry::{ClientJsonField, ClientUpdate, OperationClass},
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManagementRequest {
    GetCapabilities,
    RegisterClient {
        client_name: String,
        operation_class: OperationClass,
        allowed_source_cidr: String,
        transports: Vec<String>,
        keep_alive_timeout: u64,
        peer_uid: Option<u32>,
        peer_gid: Option<u32>,
    },
    ListClients,
    ModifyClient {
        client_id: Uuid,
        update: ClientUpdate,
    },
    SetClientActive {
        client_id: Uuid,
        active: bool,
    },
    RegisterService {
        client_id: Uuid,
        service_name: String,
        subject_type: String,
        #[serde(default)]
        allowed_jwt_query_fields: Vec<String>,
        #[serde(default)]
        allowed_issuer_service_ids: Vec<Uuid>,
        source_type: Option<String>,
        encryption_profile: Option<String>,
        #[serde(default)]
        client_json_schema: Option<Vec<ClientJsonField>>,
        #[serde(default)]
        database_source: Option<DatabaseSourceInput>,
    },
    ListServices {
        client_id: Uuid,
    },
    DeleteService {
        client_id: Uuid,
        service_id: Uuid,
    },
    DeleteClient {
        client_id: Uuid,
    },
    ListRecoveryPoints,
    ForceBackupAndRotate {
        recovery_key: String,
    },
    RestoreDatabase {
        recovery_key: String,
        generation: u64,
    },
}

impl ManagementRequest {
    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::GetCapabilities => "GET_CAPABILITIES",
            Self::RegisterClient { .. } => "REGISTER_CLIENT",
            Self::ListClients => "LIST_CLIENTS",
            Self::ModifyClient { .. } => "MODIFY_CLIENT",
            Self::SetClientActive { .. } => "SET_CLIENT_ACTIVE",
            Self::RegisterService { .. } => "REGISTER_SERVICE",
            Self::ListServices { .. } => "LIST_SERVICES",
            Self::DeleteService { .. } => "DELETE_SERVICE",
            Self::DeleteClient { .. } => "DELETE_CLIENT",
            Self::ListRecoveryPoints => "LIST_RECOVERY_POINTS",
            Self::ForceBackupAndRotate { .. } => "FORCE_BACKUP_AND_ROTATE",
            Self::RestoreDatabase { .. } => "RESTORE_DATABASE",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManagementResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ManagementError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachment: Option<ManagementAttachment>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManagementAttachment {
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManagementError {
    pub code: u16,
    pub name: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defines_recovery_key_commands_as_distinct_management_operations() {
        let recovery_key = "ab".repeat(32);
        let backup = ManagementRequest::ForceBackupAndRotate {
            recovery_key: recovery_key.clone(),
        };
        let restore = ManagementRequest::RestoreDatabase {
            recovery_key,
            generation: 7,
        };
        assert_eq!(backup.operation_name(), "FORCE_BACKUP_AND_ROTATE");
        assert_eq!(restore.operation_name(), "RESTORE_DATABASE");
        let serialized = serde_json::to_value(restore).unwrap();
        assert_eq!(serialized["generation"], 7);
    }
}
