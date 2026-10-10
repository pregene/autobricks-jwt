# Recovery

## Scope

Defines the recovery authorization key, operations that require it, protected
input handling, verification failure behavior, and its boundary from HSM and
SQLCipher encryption keys.

## Recovery Authorization Key

Installation generates one cryptographically secure 256-bit random recovery
authorization key. It is represented to the administrator as 64 lowercase
hexadecimal characters. The key is independent of the HSM `CURRENT` and
`PREVIOUS` keys, SQLCipher Database keys, JWT token keys, APIKEYs, and client
certificates.

The key is generated directly from 32 bytes of cryptographically secure random
data; it is not derived by applying SHA-256 to a password or another
low-entropy input. Autobricks JWT authenticates a supplied key against its
protected SHA-256 verifier without storing the plaintext recovery key.

The recovery authorization key does not decrypt a Database or replace HSM
authorization. It adds a separate authorization factor for destructive or
recovery-sensitive local management operations.

The installer displays the recovery authorization key once through its
protected interactive output. The plaintext key is not written to the
SQLCipher Database, configuration, syslog, TrueLog, shell history, command-line
arguments, installation log, or package output. Autobricks JWT retains only
the protected verifier required to authenticate a supplied key.

The administrator is responsible for transferring the key to an approved
recovery-key store. Installation does not complete until the administrator
confirms that the key has been recorded.

## Operations Requiring the Recovery Key

The following operations require the complete recovery authorization key:

- Forced Database backup
- Forced security-key rotation
- Restoration of a previous SQLCipher Database backup

The key is required in addition to local management-socket access, operating
system caller authorization, and any required HSM authorization. Possession of
the recovery key alone does not grant access to a backup, Database, HSM key, or
JWT management operation.

The key is entered through protected, non-echoing `ab-jwt-cli` input. It is not
accepted as a command-line argument. `ab-jwt-cli` sends it only through the
protected local management path for verification and removes the plaintext
input from process memory after the operation no longer requires it.

## Verification Failure

A missing, malformed, or incorrect recovery authorization key rejects the
operation before a backup, HSM key transition, SQLCipher rekey, or restoration
state change begins. The response does not distinguish an unknown key from an
incorrect key.

The failed attempt writes a redacted classified entry to the operating
server's syslog. The entry does not contain the supplied key, its verifier, a
Database path, an HSM identifier, or backup contents. Connection access logging
remains mandatory for the management connection.

Loss of the recovery authorization key prevents forced backup, forced key
rotation, and previous-Database restoration through the management interface.
Normal JWT runtime operations do not use this key.
