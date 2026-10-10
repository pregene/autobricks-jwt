# Data Backup

## Scope

Defines the protected data included in an Autobricks JWT backup, the security
boundary for backup creation and storage, backup consistency, restoration, and
post-restoration validation.

## Backup Interval

Autobricks JWT performs a Database backup and security-key rotation as one
scheduled operation. The Database backup interval is configurable from 7
through 30 days, inclusive. The default is 30 days. Values below 7 days or
above 30 days are rejected.

The configured interval is measured from the completion time of the last
successful backup-and-rotation operation. A failed attempt does not reset the
interval or replace the last successful restoration point.

The most recent successful periodic backup can therefore represent Database
state from as much as the configured interval before a failure. Data committed
after that backup is not part of the restored snapshot.

## Installation Requirement

The installer requires the operator to provide a Database backup directory.
The value is not optional. The installer validates that the backup process can
write to the directory and that the directory is not accessible to
unauthorized users.

The installer accepts a backup interval from 7 through 30 days. An omitted
value selects the 30-day default. The validated value is stored in the service
configuration and controls scheduled backup-and-rotation operations.

Installation performs these steps in order:

1. Create the SQLCipher Database and its schema.
2. Validate the configured backup directory.
3. Create a complete backup of the initialized Database.
4. Validate that the backup can be opened as a SQLCipher Database through the
   configured HSM-managed Database-key path.
5. Perform the mandatory initial security-key rotation.
6. Store the key that opens the initial backup as the preceding-generation key
   inside the rekeyed active Database.
7. Validate the active Database, the initial backup, and their key-generation
   relationship.
8. Record the successful backup completion time as the start of the configured
   interval.
9. Complete installation.

The initial backup and its immediately following key rotation are mandatory.
Schema creation without a validated initial backup and recovery-key
relationship is not a successful installation.

## Forced Backup

An authorized local administrator can force a Database backup and its required
security-key rotation through the protected `ab-jwt-cli` management path
without waiting for the configured interval. The network JWT service
transports do not expose this operation.

The administrator must supply the installation recovery authorization key
before the forced operation can begin. The key requirement is defined in
[Recovery](14-recovery.md).

Autobricks JWT does not provide a backup-only management operation. Requesting
a forced Database backup always performs the corresponding security-key
rotation and creates a new key generation.

A forced backup is used to create an explicit restoration point after service
configuration changes, including client registration, service registration,
or another authorized management change that must be preserved together.

The forced-backup operation:

1. Authenticates and authorizes the local management caller.
2. Establishes a transactionally consistent SQLCipher backup boundary.
3. Writes a new backup artifact to the configured backup directory.
4. Validates the completed SQLCipher artifact.
5. Moves the key that opens the new backup to the preceding generation.
6. Creates a new current HSM key and rekeys the active SQLCipher Database.
7. Stores the preceding-generation key and backup relationship inside the
   rekeyed active Database.
8. Validates the active Database and the complete recovery chain.
9. Records the operation completion time and protected backup identity.
10. Returns the validated restoration-point information to the administrator.

A forced backup never replaces the last successful restoration point before
the new backup, key rotation, active Database, and recovery chain all pass
validation. A failed forced operation does not create a completed restoration
point and does not change the last successful operation time.

A successful forced backup-and-rotation operation creates a complete
restoration point and becomes the last successful backup. The next configured
interval begins at its completion time. Administrators can therefore finish a
related set of service configuration changes, force the operation, and restore
to that known configuration boundary when recovery is required.

## Backup Content

Each backup contains a transactionally consistent copy of the complete
Autobricks JWT SQLCipher Database. This includes the schema and the durable
records stored in that Database at the backup boundary, including client and
service registrations, enabled request and issuance logs still within their
retention period, encrypted tokens, token-key records, session state, and
locally retained audit receipts.

The backup does not contain a plaintext Database, decrypted JWT payloads, an
exported SQLCipher Database key, HSM credentials, certificate private keys, or
an in-memory Cache image. Autobricks Cache remains runtime state and is not a
substitute for the SQLCipher backup.

## Backup Completion

A backup is successful only when all Database content has been copied to a
complete backup artifact, that artifact passes SQLCipher validation, the
required key rotation completes, the active Database is valid under its new
current key, and the preceding-generation recovery relationship is stored and
validated. A partial artifact, an artifact that cannot be opened, or an
operation with an incomplete key transition is not a completed restoration
point and must not replace the last successful backup.

The service records the completion time and protected backup identity without
logging Database contents, token values, token keys, APIKEYs, HSM credentials,
or the SQLCipher Database key. Classified backup failures are written to
syslog using the applicable error from [ERROR.md](../ERROR.md).

## Restoration Boundary

Restoration selects a completed and validated backup from the configured
backup directory. The SQLCipher Database remains encrypted throughout backup
storage and restoration. Opening a restored Database still requires the
corresponding HSM-managed Database-key path.

The restored SQLCipher snapshot is authoritative only for the durable state
captured at its backup boundary. Cache state is rebuilt from the restored
durable state and configured data sources; stale pre-restoration Cache state
must not be reused.

After restoration, the operator validates the Database schema, SQLCipher
integrity, HSM key access, client and service relationships, token-key record
relationships, and audit-receipt records before starting JWT request
processing.

## Security Boundaries

- The backup directory is a protected service resource, not a public download
  location.
- Backup files retain the confidentiality provided by SQLCipher.
- Backup handling does not write an HSM key or a separate plaintext Database
  key file into the backup directory. Preceding-generation keys exist only
  inside the protected SQLCipher key chain defined in
  [Data Security-Key Rotation](12-data-security-key-rotation.md).
- Filesystem access to a backup does not authorize JWT operations or management
  operations.
- Restoring a snapshot does not recreate Database changes made after the
  selected backup boundary.
