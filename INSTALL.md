# Installation

## Programs

| Program | Role |
| --- | --- |
| `ab-jwtd` | Autobricks JWT server program |
| `ab-jwt-cli` | Management client for JWT client registration, modification, and deletion |

The interactive `ab-jwt-cli` process connects to the local socket owned by
`autobricks-jwt-cli.service`. The client service authenticates the local caller,
validates and filters the management request, and forwards an authorized
request to `ab-jwtd` through the server's separate local management socket.

JWT client registration, modification, and deletion are available only through
this management path. Network JWT service transports do not expose these
operations. Neither management socket is world-accessible; filesystem
permissions and Unix peer credentials restrict both connections.

When `ab-jwt-cli` provisions a client certificate, it downloads the certificate
package into the directory from which `ab-jwt-cli` was invoked.

## Database Backup Directory

The installer requires a Database backup directory. Installation cannot omit
this value.

```text
Database backup directory: [/var/backups/autobricks-jwt]
```

The selected directory must be writable by the backup process and protected
from access by identities that are not authorized to operate or recover
Autobricks JWT. The installer writes the validated path to the service
configuration.

The installer also requires the Database backup interval in days. Accepted
values are 7 through 30, inclusive. The default is 30 days. Values outside this
range are rejected.

```text
Database backup interval in days [30]:
```

Pressing Enter without a value selects 30 days.

After creating the SQLCipher schema, the installer creates and validates the
initial Database backup, performs the mandatory initial security-key rotation,
and verifies that the rekeyed active Database contains the key relationship
required to open that backup. Installation does not complete successfully
unless the backup and initial rotation both complete. The configured backup
interval starts from the successful initial backup. The complete contracts are
defined in [Data Backup](docs/11-data-backup.md) and
[Data Security-Key Rotation](docs/12-data-security-key-rotation.md).

## Recovery Authorization Key

The installer generates a cryptographically secure 256-bit recovery
authorization key and displays it once as 64 lowercase hexadecimal characters.
The administrator must preserve this key in an approved recovery-key store and
confirm that it has been recorded before installation completes.

The recovery authorization key is required for forced Database backup, forced
security-key rotation, and restoration of a previous SQLCipher Database. It is
not a Database encryption key and does not replace HSM or local administrator
authorization. The handling and failure contract is defined in
[Recovery](docs/14-recovery.md).

## Logging Selection

The installer requires an explicit enabled or disabled selection for each
optional log category:

```text
Write request logs?  [Enable/Disable]
Write query logs?    [Enable/Disable]
Write issuance logs? [Enable/Disable]
Write audit logs?    [Enable/Disable]
```

| Category | Installation choice | Effect when disabled |
| --- | --- | --- |
| Request log | Optional | No request-history record or request-activity syslog entry is created. |
| Query log | Optional | No JWT query-history record or query-activity syslog entry is created. |
| Issuance log | Optional | No JWT issuance-history record or issuance-activity syslog entry is created. |
| Audit log | Optional | No local audit log, TrueLog audit event, or TrueLog receipt is created; privileged complete-token inspection is unavailable. |
| Connection access log | Always enabled | Cannot be disabled by the installer or service configuration. |

The installer does not complete until all four optional categories have an
explicit selection. Disabling a category applies to records created after that
installation profile becomes active. Because no local history record or
operational activity entry is created, the omitted historical activity cannot
later be queried, restored from a Database backup, or reconstructed.

Connection access logging is mandatory and independent of these selections.
Every accepted or rejected connection writes its permitted access metadata to
the operating server's syslog. Access logs never contain an APIKEY, JWT,
decrypted field, token key, Database key, HSM credential, certificate private
key, or unrestricted error text.

Classified service failures continue to follow [ERROR.md](ERROR.md) and
[LOGGING.md](LOGGING.md); an optional activity-log selection does not suppress
the required syslog error classification.

## Runtime Token Submission

The `ab-jwtd` installation selects whether query and revocation requests must
send the complete encrypted token with `token_id`:

```yaml
require_token_for_query_and_revoke: true
```

| Value | Request behavior | Security and network effect |
| --- | --- | --- |
| `true` | `JWT_QUERY` and `JWT_REVOKE` require both `token_id` and `token`. | Confirms that the caller submitted the exact issued token, with the additional network cost of sending the complete JWE. |
| `false` | `token_id` is required and `token` is optional for `JWT_QUERY` and `JWT_REVOKE`. | Reduces request size, but does not prove that the caller possesses the complete JWE. |

The secure default is `true`. The installer must present this selection and
write the chosen value to the `ab-jwtd` configuration. Changing the value
requires configuration authorization and a service restart; a runtime request
cannot override it.

```text
Require the complete token for JWT query and revocation? [Y/n]
```

`Y` writes `true`; `n` writes `false`. An omitted configuration value is
interpreted as `true` so a missing setting cannot silently enable the weaker
token-optional mode.

When the value is `false` and `token` is omitted, `ab-jwtd` resolves the stored
encrypted token from `token_id` and performs the same JWE, key, IV, claim,
audience, expiration, service-binding, session-state, and field-authorization
checks internally. When a caller supplies `token` in either mode, it must match
the stored token; the service never ignores a mismatched submitted token.

Token-optional mode relies more heavily on the connection credential,
`client_id`, APIKEY, service binding, field allowlist, and source CIDR boundary.
`token_id` is an identifier, not a secret. Deployments that require proof that
the caller possesses the issued JWE must keep the secure default.

The Web Server remains responsible for authenticating its end user and
confirming that the incoming application request is entitled to query or revoke
the selected JWT session. `ab-jwtd` validates the registered service and token
state; it cannot validate the Web Server's user-to-session association. The Web
Server performs this check while treating the JWT as opaque and never receives
the JWT decryption key.

## Server Certificate Renewal Schedule

When TLS or mutual TLS is enabled, the installer requires a daily server
certificate renewal-check time. The value uses the server's configured local
time zone and 24-hour `HH:MM` format. The default is `04:00`.

```text
Daily server certificate renewal check time [04:00]:
```

Pressing Enter without a value selects `04:00`. The installer rejects an
invalid time. The configured scheduler runs exactly once each day at the
selected time and uses `abpki-cli` to check the currently installed server
certificate for renewal.

The scheduler does not restart a listener when no replacement certificate is
issued. When renewal returns a replacement, Autobricks JWT downloads and
validates the replacement certificate, private key, and trust chain, installs
them as one protected update, and restarts the TLS and mutual TLS listeners.
New secure connections then use the replacement certificate. Unix domain
socket and plain TCP listeners are not restarted by this certificate update.

The complete server and client certificate renewal contract is defined in
[Certificate Renewal](docs/15-certificate-renewal.md).

## Services

| Service | Role |
| --- | --- |
| `autobricks-jwt.service` | Autobricks JWT server service |
| `autobricks-jwt-cli.service` | Local management broker that authenticates and filters `ab-jwt-cli` requests before forwarding them to `ab-jwtd` |
