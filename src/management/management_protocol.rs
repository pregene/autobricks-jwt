use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::service_registry::{ClientUpdate, OperationClass};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManagementRequest {
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
        source_type: Option<String>,
        encryption_profile: Option<String>,
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
}

impl ManagementRequest {
    pub fn operation_name(&self) -> &'static str {
        match self {
            Self::RegisterClient { .. } => "REGISTER_CLIENT",
            Self::ListClients => "LIST_CLIENTS",
            Self::ModifyClient { .. } => "MODIFY_CLIENT",
            Self::SetClientActive { .. } => "SET_CLIENT_ACTIVE",
            Self::RegisterService { .. } => "REGISTER_SERVICE",
            Self::ListServices { .. } => "LIST_SERVICES",
            Self::DeleteService { .. } => "DELETE_SERVICE",
            Self::DeleteClient { .. } => "DELETE_CLIENT",
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
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManagementError {
    pub code: u16,
    pub name: String,
    pub message: String,
}
