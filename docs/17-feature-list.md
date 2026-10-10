# Feature List

`DONE` means the feature has an implementation and an executable test that
verifies its primary result. `PLAN` means the feature is specified but does not
yet have complete implementation and executable verification. Partially
implemented designs are divided into separate rows.

A completed component does not imply that the production server starts or
connects that component. Production composition, durable startup, management
workflow, packaging, and end-to-end restart behavior are tracked separately.

| F-CODE | Status | Feature | Document Reference |
| --- | --- | --- | --- |
| FTL-001 | `DONE` | `ab-jwtd` server executable and repository version integration | [Installation](../INSTALL.md#programs) |
| FTL-002 | `DONE` | `ab-jwt-cli` management executable and repository version integration | [Installation](../INSTALL.md#programs) |
| FTL-003 | `DONE` | Client-facing management Unix socket | [JWT Client Registration](01-jwt-client-registration.md#management-path) |
| FTL-004 | `DONE` | Separate `ab-jwtd` server-management Unix socket | [Architecture](../ARCHITECTURE.md#management-interface) |
| FTL-005 | `DONE` | Management socket parent mode `0750` and socket mode `0660` | [JWT Client Registration](01-jwt-client-registration.md#management-path) |
| FTL-006 | `DONE` | Unix peer UID retrieval and expected-UID comparison | [Architecture](../ARCHITECTURE.md#management-interface) |
| FTL-007 | `DONE` | Separate production broker and server operating-system identities | [Installation](../INSTALL.md#services) |
| FTL-008 | `DONE` | `autobricks-jwt.service` unit | [Installation](../INSTALL.md#services) |
| FTL-009 | `DONE` | `autobricks-jwt-cli.service` management-broker unit | [Installation](../INSTALL.md#services) |
| FTL-010 | `DONE` | Curses management interface | [Service Deletion](06-service-deletion.md#service-management-screen) |
| FTL-011 | `DONE` | Separate READ and WRITE client registrations | [JWT Client Registration](01-jwt-client-registration.md#operation-classes) |
| FTL-012 | `DONE` | Client-name uniqueness validation | [JWT Client Registration](01-jwt-client-registration.md#registration-input) |
| FTL-013 | `DONE` | Required source CIDR capture | [JWT Client Registration](01-jwt-client-registration.md#connection-settings) |
| FTL-014 | `DONE` | Multiple enabled transports per client | [JWT Client Registration](01-jwt-client-registration.md#client-credential-types) |
| FTL-015 | `DONE` | Per-client keep-alive timeout capture | [JWT Client Registration](01-jwt-client-registration.md#connection-settings) |
| FTL-016 | `DONE` | Unix peer UID and optional GID capture | [JWT Client Registration](01-jwt-client-registration.md#connection-settings) |
| FTL-017 | `DONE` | Client listing through both management sockets | [JWT Client Deletion](07-jwt-client-deletion.md#jwt-client-management-screen) |
| FTL-018 | `DONE` | Durable SQLCipher `clients` records | [JWT Client Registration](01-jwt-client-registration.md#stored-state) |
| FTL-019 | `DONE` | Active, inactive, and deleted client lifecycle | [JWT Client Deletion](07-jwt-client-deletion.md#state-and-history-rules) |
| FTL-020 | `DONE` | Client modification operation | [Architecture](../ARCHITECTURE.md#management-interface) |
| FTL-021 | `DONE` | Transport availability from the installed dependency profile | [Dependencies](../DEPENDENCIES.md#capability-matrix) |
| FTL-022 | `DONE` | Multiple services under one `client_id` | [Service Registration](02-service-registration.md#client-binding) |
| FTL-023 | `DONE` | One USER, DEVICE, or WORKLOAD subject type per service | [Service Registration](02-service-registration.md#subject-type) |
| FTL-024 | `DONE` | Independent APIKEY generation per service | [Architecture](../ARCHITECTURE.md#service-registry) |
| FTL-025 | `DONE` | Salted APIKEY verifier with constant-time comparison | [Architecture](../ARCHITECTURE.md#service-registry) |
| FTL-026 | `DONE` | APIKEY isolation between services | [Service Registration](02-service-registration.md#security-boundary) |
| FTL-027 | `DONE` | READ service field-allowlist registration | [Service Registration](02-service-registration.md#field-level-query-authorization) |
| FTL-028 | `DONE` | WRITE source type and encryption-profile registration | [Service Registration](02-service-registration.md#write-service-configuration) |
| FTL-029 | `DONE` | Service list scoped by selected `client_id` | [Service Deletion](06-service-deletion.md#jwt-client-selection) |
| FTL-030 | `DONE` | Durable SQLCipher `services` records and APIKEY verifier | [Service Registration](02-service-registration.md#security-boundary) |
| FTL-031 | `DONE` | CLIENT_JSON source validation and payload construction | [Service Registration](02-service-registration.md#client_json-source) |
| FTL-032 | `DONE` | DATABASE Connection, MAP, SELECT, and binding registration | [Service Registration](02-service-registration.md#database-source) |
| FTL-033 | `DONE` | Registered UPDATE statement and binding execution | [Service Registration](02-service-registration.md#update-query-and-binding-order) |
| FTL-034 | `DONE` | Configurable JWE profiles beyond the implemented profile | [Service Registration](02-service-registration.md#jwt-encryption-profile-selection) |
| FTL-035 | `DONE` | TLS server certificate and trust-chain loading | [Service Certificate](16-service-certificate.md#certificate-profile) |
| FTL-036 | `DONE` | Mutual TLS client-certificate requirement and chain verification | [Service Certificate](16-service-certificate.md#runtime-authentication) |
| FTL-037 | `DONE` | Encrypted data exchange after TLS and mutual TLS handshake | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-038 | `DONE` | `abpki-cli` certificate issuance during service registration | [Service Certificate](16-service-certificate.md#initial-certificate-provisioning) |
| FTL-039 | `DONE` | Certificate package download to the CLI invocation directory | [Service Certificate](16-service-certificate.md#service-registration-result) |
| FTL-040 | `DONE` | SQLCipher `service_certificates` records bound to `service_id` | [Service Certificate](16-service-certificate.md#sqlcipher-records) |
| FTL-041 | `DONE` | Registered certificate fingerprint verification | [Service Certificate](16-service-certificate.md#runtime-authentication) |
| FTL-042 | `DONE` | READ and WRITE URI SAN authorization | [Service Certificate](16-service-certificate.md#operation-uri-san) |
| FTL-043 | `DONE` | AIA OCSP lookup and fail-closed `GOOD` validation | [Service Certificate](16-service-certificate.md#runtime-authentication) |
| FTL-044 | `DONE` | Certificate purpose and validity-period enforcement | [Service Certificate](16-service-certificate.md#runtime-authentication) |
| FTL-045 | `DONE` | Service-certificate renewal and fingerprint handover | [Certificate Renewal](15-certificate-renewal.md#service-fingerprint-handover-procedure) |
| FTL-046 | `DONE` | Daily server-certificate renewal and listener restart | [Certificate Renewal](15-certificate-renewal.md#daily-server-renewal-check) |
| FTL-047 | `DONE` | Unix service socket creation and permissions | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-048 | `DONE` | TCP listener connection and data exchange | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-049 | `DONE` | TLS listener handshake and encrypted data exchange | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-050 | `DONE` | Mutual TLS listener handshake and data exchange | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-051 | `DONE` | Source CIDR enforcement for network transports | [JWT Client Registration](01-jwt-client-registration.md#runtime-enforcement) |
| FTL-052 | `DONE` | Persistent framed keep-alive processing | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-053 | `DONE` | Sliding per-client idle timeout | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-054 | `DONE` | Maximum connection and certificate deadline | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-055 | `DONE` | Certificate and OCSP revalidation on persistent connections | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-056 | `DONE` | JWE Compact serialization | [JWT Issuance](03-service-json-web-token-issuance.md#serialization-and-algorithms) |
| FTL-057 | `DONE` | Direct key management with A256GCM | [JWT Issuance](03-service-json-web-token-issuance.md#autobricks-jwt-profile) |
| FTL-058 | `DONE` | Independent content-encryption key and IV per token | [JWT Issuance](03-service-json-web-token-issuance.md#sqlcipher-token-state-and-optional-issuance-log) |
| FTL-059 | `DONE` | Shared UUID for `jti` and returned `token_id` | [JWT Issuance](03-service-json-web-token-issuance.md#required-claims) |
| FTL-060 | `DONE` | Registered JWT time, issuer, subject, and audience claims | [JWT Issuance](03-service-json-web-token-issuance.md#required-claims) |
| FTL-061 | `DONE` | Authenticated decryption and modified-token rejection | [JWT Issuance](03-service-json-web-token-issuance.md#later-token-validation) |
| FTL-062 | `DONE` | Audience and expiration validation | [JWT Issuance](03-service-json-web-token-issuance.md#later-token-validation) |
| FTL-063 | `DONE` | Authorized-field projection primitive | [JWT Query](04-service-json-web-token-query.md#authorized-field-query) |
| FTL-064 | `DONE` | Complete JWT_CREATE service request | [JWT Issuance](03-service-json-web-token-issuance.md#processing) |
| FTL-065 | `DONE` | Request idempotency by `client_id` and `request_id` | [JWT Issuance](03-service-json-web-token-issuance.md#sqlcipher-request-state-and-optional-request-log) |
| FTL-066 | `DONE` | SQLCipher token, key, IV, digest, and version persistence | [JWT Issuance](03-service-json-web-token-issuance.md#sqlcipher-token-state-and-optional-issuance-log) |
| FTL-067 | `DONE` | HSM-managed SQLCipher database key | [Architecture](../ARCHITECTURE.md#key-store) |
| FTL-068 | `DONE` | JWT_UPDATE claim upsert and token-version replacement | [Operation Definitions](10-operation-definitions.md#jwt_update) |
| FTL-069 | `DONE` | Dynamic Autobricks Cache C ABI loading | [Dependencies](../DEPENDENCIES.md#required-dependency-autobricks-cache) |
| FTL-070 | `DONE` | ON_DEMAND Cache initialization | [JWT Issuance](03-service-json-web-token-issuance.md#session-cache-and-map) |
| FTL-071 | `DONE` | Cache MAP lookup using `user_id` | [JWT Issuance](03-service-json-web-token-issuance.md#session-cache-and-map) |
| FTL-072 | `DONE` | Cache miss database load and resident lookup | [JWT Issuance](03-service-json-web-token-issuance.md#session-cache-and-map) |
| FTL-073 | `DONE` | Active encrypted session insertion into Cache | [JWT Issuance](03-service-json-web-token-issuance.md#session-cache-and-map) |
| FTL-074 | `DONE` | Automatic session Retention extension | [JWT Query](04-service-json-web-token-query.md#automatic-session-expiration-extension) |
| FTL-075 | `DONE` | Session removal from Cache during revocation | [JWT Revocation](05-service-json-web-token-revocation.md#processing) |
| FTL-076 | `DONE` | PostgreSQL, MariaDB, MySQL, SQLite, and SQLCipher adapters | [Supported Databases](../SUPPORT-DATABASE.md) |
| FTL-077 | `DONE` | Active-session status request | [JWT Query](04-service-json-web-token-query.md#active-session-status) |
| FTL-078 | `DONE` | Authorized-field query request over a service transport | [JWT Query](04-service-json-web-token-query.md#authorized-field-query) |
| FTL-079 | `DONE` | Required-token and token-optional runtime modes | [Installation](../INSTALL.md#runtime-token-submission) |
| FTL-080 | `DONE` | JWT_REVOKE processing and idempotency | [JWT Revocation](05-service-json-web-token-revocation.md#concurrency-and-idempotency) |
| FTL-081 | `DONE` | SSO session validation integration | [JWT Query](04-service-json-web-token-query.md#sso-session-validation) |
| FTL-082 | `DONE` | OAuth and OpenID Connect integration | [JWT Query](04-service-json-web-token-query.md#oauth-and-openid-connect-session-validation) |
| FTL-083 | `DONE` | Service deletion through `ab-jwt-cli` | [Service Deletion](06-service-deletion.md#processing) |
| FTL-084 | `DONE` | Client deletion with service and APIKEY cascade | [JWT Client Deletion](07-jwt-client-deletion.md#processing) |
| FTL-085 | `DONE` | Deleted service removed from the active list | [Service Deletion](06-service-deletion.md#state-and-history-rules) |
| FTL-086 | `DONE` | Durable logical deletion | [Service Deletion](06-service-deletion.md#state-and-history-rules) |
| FTL-087 | `DONE` | Active session revocation during WRITE client deletion | [JWT Client Deletion](07-jwt-client-deletion.md#cache-cleanup) |
| FTL-088 | `DONE` | Historical records retained after registration deletion | [JWT Client Deletion](07-jwt-client-deletion.md#historical-records-and-logs) |
| FTL-089 | `DONE` | Test-path `JWT_ISSUED` append through `ab-truelog-cli` | [Audit Logging](../LOGGING.md#successful-jwt-issuance) |
| FTL-090 | `DONE` | TrueLog append-receipt validation | [Audit Logging](../LOGGING.md#append-receipt) |
| FTL-091 | `DONE` | Current WORM metadata query using `info` | [Audit Log Query](09-audit-log-query.md#ab-truelog-cli-info) |
| FTL-092 | `DONE` | SQLCipher audit record and receipt persistence | [Audit Log Query](09-audit-log-query.md#path-2-query-the-local-audit-log-table) |
| FTL-093 | `DONE` | PENDING, STORED, and RECONCILE workflow | [Audit Logging](../LOGGING.md#local-receipt-state) |
| FTL-094 | `DONE` | Production issuance path TrueLog integration | [JWT Issuance](03-service-json-web-token-issuance.md#logging-and-audit) |
| FTL-095 | `DONE` | Common invalid-session TrueLog event | [Audit Logging](../LOGGING.md#invalid-jwt-session-request) |
| FTL-096 | `DONE` | Privileged decrypted-token inspection | [JWT Issuance](03-service-json-web-token-issuance.md#privileged-local-token-inspection) |
| FTL-097 | `DONE` | Structured classified-error syslog output | [Audit Logging](../LOGGING.md#syslog-service-error-logging) |
| FTL-098 | `DONE` | Mandatory connection-access logging | [Installation](../INSTALL.md#logging-selection) |
| FTL-099 | `DONE` | `journalctl` operational-log query | [Operational Log Query](08-operational-log-query.md) |
| FTL-100 | `DONE` | Local audit-log management query | [Audit Log Query](09-audit-log-query.md#path-2-query-the-local-audit-log-table) |
| FTL-101 | `DONE` | Registry for all 67 assigned error codes | [Error Contract](../ERROR.md) |
| FTL-102 | `DONE` | Duplicate and reserved error-code rejection | [Error Contract](../ERROR.md#change-control) |
| FTL-103 | `DONE` | Stable code, name, and exposure enumeration | [Error Contract](../ERROR.md#exposure-classes) |
| FTL-104 | `DONE` | Assigned codes in existing implemented failure paths | [Error Contract](../ERROR.md#implementation-coverage) |
| FTL-105 | `DONE` | Every error triggered through its owning boundary | [Error Contract](../ERROR.md#implementation-coverage) |
| FTL-106 | `DONE` | Complete public, generic, close, and internal mapping | [Error Contract](../ERROR.md#security-mapping-rules) |
| FTL-107 | `DONE` | Redacted syslog entry for every classified failure | [Error Contract](../ERROR.md#implementation-coverage) |
| FTL-108 | `DONE` | Keep-alive timeout configuration validation | [Installation](../INSTALL.md#programs) |
| FTL-109 | `DONE` | Secure default for complete token submission | [Installation](../INSTALL.md#runtime-token-submission) |
| FTL-110 | `DONE` | Certificate-renewal time parsing with `04:00` default | [Installation](../INSTALL.md#server-certificate-renewal-schedule) |
| FTL-111 | `DONE` | Backup directory and 7-to-30-day interval installation | [Data Backup](11-data-backup.md#installation-requirement) |
| FTL-112 | `DONE` | Initial and forced backup with key rotation | [Data Backup](11-data-backup.md#forced-backup) |
| FTL-113 | `DONE` | HSM CURRENT and PREVIOUS database-key chain | [Data Security-Key Rotation](12-data-security-key-rotation.md#hsm-key-slots) |
| FTL-114 | `DONE` | Forced security-key rotation and recovery backup | [Data Security-Key Rotation](12-data-security-key-rotation.md#forced-security-key-rotation) |
| FTL-115 | `DONE` | 256-bit recovery authorization key | [Recovery](14-recovery.md#recovery-authorization-key) |
| FTL-116 | `DONE` | Previous SQLCipher backup restoration | [Data Security-Key Rotation](12-data-security-key-rotation.md#recovery) |
| FTL-117 | `DONE` | Optional request, query, issuance, and audit logging | [Installation](../INSTALL.md#logging-selection) |
| FTL-118 | `DONE` | Automatic 90-day internal log drain | [Log Drain Cycle](13-log-drain-cycle.md#internal-record-retention) |
| FTL-119 | `PLAN` | Production runtime composition and shared service context | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-120 | `PLAN` | HSM-backed SQLCipher key acquisition during server startup | [Architecture](../ARCHITECTURE.md#key-store) |
| FTL-121 | `PLAN` | Production management registry opened from durable SQLCipher state | [Service Registration](02-service-registration.md#security-boundary) |
| FTL-122 | `PLAN` | Configuration-driven UNIX, TCP, TLS, and mTLS listener startup | [Architecture](../ARCHITECTURE.md#service-interface) |
| FTL-123 | `PLAN` | Listener-to-runtime-dispatcher request and response integration | [Operation Definitions](10-operation-definitions.md) |
| FTL-124 | `PLAN` | Production Autobricks Cache initialization and shutdown lifecycle | [Dependencies](../DEPENDENCIES.md#required-dependency-autobricks-cache) |
| FTL-125 | `PLAN` | Registered DATABASE source execution in the production issuance path | [Service Registration](02-service-registration.md#database-source) |
| FTL-126 | `PLAN` | Parameterized SELECT and UPDATE execution for every direct database adapter | [Supported Databases](../SUPPORT-DATABASE.md) |
| FTL-127 | `PLAN` | TLS and mTLS configuration for direct PostgreSQL, MariaDB, and MySQL connections | [Supported Databases](../SUPPORT-DATABASE.md) |
| FTL-128 | `PLAN` | Production syslog, TrueLog, and audit-receipt repository composition | [Audit Logging](../LOGGING.md) |
| FTL-129 | `PLAN` | Production backup, log-drain, and certificate-renewal scheduler execution | [Data Backup](11-data-backup.md), [Log Drain](13-log-drain-cycle.md), [Certificate Renewal](15-certificate-renewal.md) |
| FTL-130 | `PLAN` | Management broker caller authorization and operation filtering | [JWT Client Registration](01-jwt-client-registration.md#management-path) |
| FTL-131 | `PLAN` | Curses JWT client registration and modification workflow | [JWT Client Registration](01-jwt-client-registration.md) |
| FTL-132 | `PLAN` | Curses service registration workflow with independent READ or WRITE selection | [Service Registration](02-service-registration.md) |
| FTL-133 | `PLAN` | Curses DATABASE Connection, MAP, query-binding, and connection-test workflow | [Service Registration](02-service-registration.md#database-source) |
| FTL-134 | `PLAN` | Curses PKI certificate issuance, verification, download, and delivery workflow | [Service Certificate](16-service-certificate.md#initial-certificate-provisioning) |
| FTL-135 | `PLAN` | Authorized management commands for forced backup, key rotation, and restoration | [Recovery](14-recovery.md#operations-requiring-the-recovery-key) |
| FTL-136 | `PLAN` | Graceful shutdown, listener draining, and runtime admission transition | [Error Contract](../ERROR.md#80908100-runtime-and-reserved-expansion) |
| FTL-137 | `PLAN` | Installable binaries, configuration, systemd units, identities, directories, and dependency checks | [Installation](../INSTALL.md#services) |
| FTL-138 | `PLAN` | Restart recovery of clients, services, APIKEY verifiers, certificates, tokens, and audit state | [Architecture](../ARCHITECTURE.md#service-registry) |
| FTL-139 | `PLAN` | End-to-end create, status, query, update, and revoke over every enabled transport | [Operation Definitions](10-operation-definitions.md) |
| FTL-140 | `PLAN` | End-to-end reduced-capability startup without PKI or TrueLog clients | [Dependencies](../DEPENDENCIES.md#capability-matrix) |
| FTL-141 | `PLAN` | Recovery-point catalog with completed backup generation, creation time, and validation state | [Data Backup](11-data-backup.md#restoration-boundary) |
| FTL-142 | `PLAN` | Recovery preflight for authorization, HSM CURRENT and PREVIOUS availability, backup-chain completeness, and SQLCipher integrity | [Data Security-Key Rotation](12-data-security-key-rotation.md#recovery) |
| FTL-143 | `PLAN` | Atomic activation of a selected restored database with preservation of the pre-recovery database | [Data Security-Key Rotation](12-data-security-key-rotation.md#recovery-procedure) |
| FTL-144 | `PLAN` | Failed-recovery rollback that leaves the original active database and HSM slots usable | [Recovery](14-recovery.md#verification-failure) |
| FTL-145 | `PLAN` | Post-recovery registration reload, Cache rebuild, scheduler restoration, and listener restart | [Data Backup](11-data-backup.md#restoration-boundary) |
| FTL-146 | `PLAN` | Recovery operational logging, classified failure reporting, and successful recovery audit evidence | [Recovery](14-recovery.md) |
| FTL-147 | `PLAN` | READ-service registration of the exact WRITE services whose tokens it may access | [Service Registration](02-service-registration.md#security-boundary) |
| FTL-148 | `PLAN` | Durable SQLCipher storage and management validation of READ-to-WRITE service bindings | [Service Registration](02-service-registration.md#security-boundary) |
| FTL-149 | `PLAN` | Issuing-service authorization before status lookup, token decryption, field projection, or Retention extension | [JWT Query](04-service-json-web-token-query.md#authorized-field-query) |
| FTL-150 | `PLAN` | Cross-service query isolation tests for allowed and rejected issuers in complete-token and token-optional modes | [JWT Query](04-service-json-web-token-query.md#security-boundaries) |
| FTL-151 | `PLAN` | Authoritative durable session-state validation on every production Cache-backed query path | [Architecture](../ARCHITECTURE.md#cache-adapter) |
| FTL-152 | `PLAN` | Idempotent Cache-removal retry and reconciliation after durable JWT revocation | [JWT Revocation](05-service-json-web-token-revocation.md#concurrency-and-idempotency) |
| FTL-153 | `PLAN` | Stale-Cache denial tests proving that a durably revoked or missing session cannot become active | [JWT Revocation](05-service-json-web-token-revocation.md#processing) |
| FTL-154 | `PLAN` | Post-restoration invalidation of restored active sessions before service listeners reopen | [Data Backup](11-data-backup.md#restoration-boundary) |
| FTL-155 | `PLAN` | Post-restoration Cache rebuild that excludes invalidated, revoked, expired, and incomplete session records | [Data Security-Key Rotation](12-data-security-key-rotation.md#recovery-procedure) |
| FTL-156 | `PLAN` | End-to-end recovery tests proving that sessions revoked or issued after the selected restoration point cannot be reactivated | [Recovery](14-recovery.md) |
