# Data Security-Key Rotation

## Scope

Defines authorization, key lifecycle, protected-data transition, validation,
rollback boundaries, and audit requirements for rotating keys that protect
Autobricks JWT data.

## Forced Security-Key Rotation

An authorized local administrator can force rotation of the security key used
to protect Autobricks JWT data through the protected `ab-jwt-cli` management
path. Network JWT service transports do not expose this operation.

Forced rotation is an administrative operation. It requires management-caller
authentication and authorization before any backup or key change begins.
It also requires the installation recovery authorization key defined in
[Recovery](14-recovery.md).

Every Database backup includes this security-key rotation. Initial, scheduled,
and administrator-forced backups all create a new key generation and recovery
chain link. A Database backup is not complete until its key rotation and chain
validation have completed.

Autobricks JWT does not provide a rotation-only management operation. A forced
security-key rotation always creates and validates its pre-rotation Database
backup, and a forced Database backup always performs the corresponding key
rotation.

## Initial Key Rotation

Installation creates the initial SQLCipher schema with the initial key and
then creates the mandatory initial backup with that key. The installer
immediately performs a forced key rotation:

1. The initial key becomes HSM `PREVIOUS`.
2. A new key becomes HSM `CURRENT`.
3. The active Database is rekeyed with `CURRENT`.
4. The key that opens the initial backup is stored as the preceding-generation
   key inside the rekeyed active Database.
5. The initial backup, active Database, and key-generation relationship are
   validated before installation completes.

The service does not begin normal JWT request processing between the initial
backup and this rotation. This establishes the first recoverable link in the
Database key chain.

## HSM Key Slots

The HSM maintains two SQLCipher Database-key versions:

| Slot | Purpose |
| --- | --- |
| `CURRENT` | Opens the active Autobricks JWT SQLCipher Database. |
| `PREVIOUS` | Opens the most recent pre-rotation SQLCipher backup when the active Database is unavailable. |

The backup directory does not contain either key, a wrapped copy of either
key as a separate file, HSM recovery material, or HSM credentials. Backup
metadata identifies the generation and chain relationship without exposing key
material. Only the newest backup is opened directly with HSM `PREVIOUS`; older
keys are obtained from the protected Database chain.

## Database Key Chain

The active SQLCipher Database stores the key for the immediately preceding key
generation inside its protected Database content. It does not store its own
current key.

Each pre-rotation backup therefore contains the key required to open the backup
from the generation before it:

```text
HSM PREVIOUS K3
  -> opens Backup Generation 3
       -> contains K2
            -> opens Backup Generation 2
                 -> contains K1
                      -> opens Backup Generation 1
```

The initial backup is the chain's `GENESIS` generation. It has no preceding
generation key. Reaching and validating `GENESIS` terminates backward
traversal successfully.

The key chain is traversed only from the newest available generation toward an
older generation. An older backup key is obtained only after successfully
opening and validating the immediately newer backup Database.

Each Database generation records its generation identifier, its own backup
identity, and either the immediately preceding backup identity and key or the
`GENESIS` marker. The preceding key remains protected by the SQLCipher
encryption of the Database that contains it. Backup files and external backup
metadata do not contain a plaintext Database key.

## Recovery Backup

Before changing the security key, the forced-rotation operation creates a
protected SQLCipher Database backup using the `CURRENT` key. The backup
preserves a recovery point from before the key transition.

The key change does not begin unless the recovery backup completes and passes
validation. A backup failure leaves the current security key and protected
data unchanged and the rotation operation fails.

The recovery backup follows the storage and confidentiality boundaries defined
in [Data Backup](11-data-backup.md). It does not expose a plaintext Database,
decrypted JWT payload, token keys, the SQLCipher Database key, HSM credentials,
APIKEYs, or certificate private keys through the management result or logs.

## Rotation Sequence

After the recovery backup has completed and passed validation, the forced
rotation performs these state changes in order:

1. Confirm that the HSM `CURRENT` key opens the active SQLCipher Database.
2. Create and validate the new pre-rotation backup with the existing `CURRENT`
   key.
3. Confirm that the new backup contains the preceding generation relationship
   required to continue the older backup chain.
4. Assign the existing `CURRENT` key to the HSM `PREVIOUS` slot.
5. Create a new HSM key in the `CURRENT` slot.
6. Rekey the active SQLCipher Database from `PREVIOUS` to `CURRENT`.
7. Store the `PREVIOUS` key and the new pre-rotation backup relationship inside
   the rekeyed active Database.
8. Validate the Database and key-chain relationship with the new `CURRENT` key
   before resuming request processing.

The `CURRENT` key is used for normal Database operation. The HSM `PREVIOUS` key
opens the newest recovery backup without requiring the active Database. Keys
for older generations are recovered by traversing the validated Database chain.

## Recovery

The active Database is opened with `CURRENT`. The newest pre-rotation recovery
backup is opened with HSM `PREVIOUS`. To restore an older generation, the
operator opens the newest required backup, retrieves its protected preceding
generation key, and then opens the immediately preceding backup. This process
is repeated in generation order until the selected restoration point is
reached.

Every opened generation is validated before its preceding key is used. A
missing, corrupted, mismatched, or unverifiable intermediate backup breaks the
chain and prevents restoration of every older generation reachable only
through that backup.

### Recovery Preconditions

Recovery requires:

- An authenticated and authorized local administrator
- The HSM `CURRENT` and `PREVIOUS` key slots
- The newest valid recovery backup
- Every intermediate backup between the newest backup and the selected
  restoration point
- Matching generation identifiers, backup identities, and integrity metadata

The JWT service does not process issuance, query, update, or revocation
requests while recovery changes the active Database. Cache state from before
recovery is not reused.

### Recovery Procedure

1. Stop normal JWT request processing and close the active SQLCipher Database.
2. Preserve the active Database until recovery validation completes.
3. Open the newest recovery backup with HSM `PREVIOUS`.
4. Validate its SQLCipher integrity, backup identity, generation identifier,
   and preceding-generation relationship.
5. When the selected restoration point is older, obtain the preceding key from
   the opened Database and use it to open the immediately preceding backup.
6. Repeat validation and traversal one generation at a time until the selected
   backup is reached.
7. Restore the selected backup as the candidate active Database without
   modifying the retained backup artifact.
8. Rekey the candidate Database to HSM `CURRENT`.
9. Store the key that opens the selected backup as the active Database's
   preceding-generation key and associate it with the selected backup.
10. Assign that selected-backup key to HSM `PREVIOUS`.
11. Validate the restored Database and its remaining older recovery chain.
12. Rebuild runtime Cache state from the restored durable state and configured
    data sources.
13. Resume normal JWT request processing only after all validation succeeds.

The selected restoration point becomes the head of the retained older recovery
chain. Database changes and newer restoration points created after that
selected backup are not part of the restored active state.

### Recovery Failure

Recovery does not report success from an opened file alone. A candidate is
accepted only after SQLCipher integrity, generation linkage, key transition,
active Database validation, and Cache rebuilding have completed.

If an intermediate generation cannot be opened or validated, traversal stops
and no older generation beyond that point is accepted. If the selected
Database cannot be rekeyed or validated, normal JWT request processing remains
stopped and the preserved pre-recovery active Database is not overwritten as a
successful recovery result.

Temporary plaintext key material obtained while traversing a Database
generation is restricted to the recovery process and removed from process
memory when that generation no longer requires it. Keys, decrypted Database
content, JWT payloads, and HSM credentials are not written to syslog, TrueLog,
command output, or temporary files.

Recovery requires authorized access to both the protected backup and the HSM.
It also requires the installation recovery authorization key. Possession of
the backup or recovery authorization key alone does not provide the Database
key.
