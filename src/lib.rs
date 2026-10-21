#[path = "command/server_arguments.rs"]
pub mod server_arguments;

#[path = "configuration/server_configuration.rs"]
pub mod server_configuration;

#[path = "cache/autobricks_cache.rs"]
pub mod autobricks_cache;
#[path = "cache/database_source.rs"]
pub mod database_source;
#[path = "cache/session_cache.rs"]
pub mod session_cache;
#[path = "cache/session_worker.rs"]
pub mod session_worker;
#[path = "cache/worker_process.rs"]
pub mod worker_process;

#[path = "audit/audit_log_repository.rs"]
pub mod audit_log_repository;

#[path = "audit/audit_query.rs"]
pub mod audit_query;
#[path = "audit/truelog_audit.rs"]
pub mod truelog_audit;

#[path = "audit/activity_log_repository.rs"]
pub mod activity_log_repository;

#[path = "logging/operational_logger.rs"]
pub mod operational_logger;

#[path = "logging/operational_log_query.rs"]
pub mod operational_log_query;
#[path = "logging/production_audit.rs"]
pub mod production_audit;

#[path = "retention/sqlcipher_drain.rs"]
pub mod sqlcipher_drain;

#[path = "error/error_boundary.rs"]
pub mod error_boundary;
#[path = "error/service_error.rs"]
pub mod service_error;

#[path = "error/error_registry.rs"]
pub mod error_registry;

#[path = "registration/service_registry.rs"]
pub mod service_registry;

#[path = "registration/pki_provisioning.rs"]
pub mod pki_provisioning;
#[path = "registration/service_certificate.rs"]
pub mod service_certificate;

#[path = "registration/sqlcipher_registration_repository.rs"]
pub mod sqlcipher_registration_repository;

#[path = "registration/client_deletion_service.rs"]
pub mod client_deletion_service;

#[path = "communication/comm_runtime.rs"]
pub mod comm_runtime;
#[path = "server/privileged_runtime.rs"]
pub mod privileged_runtime;
#[path = "server/production_scheduler.rs"]
pub mod production_scheduler;
#[path = "server/recovery_management.rs"]
pub mod recovery_management;
#[path = "server/runtime_context.rs"]
pub mod runtime_context;
#[path = "server/runtime_supervisor.rs"]
pub mod runtime_supervisor;
#[path = "server/server_application.rs"]
pub mod server_application;
#[path = "server/service_certificate_management.rs"]
pub mod service_certificate_management;

#[path = "token/jwe_token.rs"]
pub mod jwe_token;

#[path = "token/sqlcipher_token_repository.rs"]
pub mod sqlcipher_token_repository;

#[path = "token/issuance_service.rs"]
pub mod issuance_service;

#[path = "token/federated_session.rs"]
pub mod federated_session;
#[path = "token/runtime_protocol.rs"]
pub mod runtime_protocol;
#[path = "token/session_service.rs"]
pub mod session_service;
#[path = "token/token_inspection.rs"]
pub mod token_inspection;

#[path = "listener/connection_policy.rs"]
pub mod connection_policy;
#[path = "listener/runtime_connection.rs"]
pub mod runtime_connection;
#[path = "listener/unix_socket.rs"]
pub mod unix_socket;

#[path = "management/management_protocol.rs"]
pub mod management_protocol;

#[path = "management/curses_ui.rs"]
pub mod curses_ui;
#[path = "management/management_service.rs"]
pub mod management_service;
#[path = "management/registration_workflow.rs"]
pub mod registration_workflow;

#[path = "retention/log_drain.rs"]
pub mod log_drain;

#[path = "hsm/database_key_rotation.rs"]
pub mod database_key_rotation;
#[path = "storage/direct_database.rs"]
pub mod direct_database;
#[path = "hsm/helper_service.rs"]
pub mod helper_service;
#[path = "hsm/pkcs11_module.rs"]
pub mod pkcs11_module;
#[path = "security/recovery_authorization.rs"]
pub mod recovery_authorization;
#[path = "hsm/soft_hsm2.rs"]
pub mod soft_hsm2;

#[path = "installation/install_layout.rs"]
pub mod install_layout;
#[path = "installation/systemd_units.rs"]
pub mod systemd_units;

#[path = "installation/dependency_profile.rs"]
pub mod dependency_profile;

pub const VERSION: &str = env!("AUTOBRICKS_JWT_VERSION");
