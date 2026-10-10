# Audit Log Query

## Purpose

Autobricks JWT audit information has two authorized query paths:

1. Sign in to the Autobricks TrueLog server and read the immutable audit
   records from its WORM storage.
2. Query the local SQLCipher audit-log table maintained by Autobricks JWT.

These paths contain records only for events created while audit logging was
enabled. Activity that occurred while audit logging was disabled has no local
audit record, TrueLog event, or receipt to query later.

The two paths have different responsibilities. Autobricks TrueLog is the
authoritative immutable evidence store. The local table is the JWT Service's
searchable index of audit events, relationships, receipt state, and the exact
append receipt returned by TrueLog.

The operating server's syslog copy is not a third audit query path. It is an
operational log and does not contain a durable append receipt.

## Audit Records

When audit logging is enabled, the local audit-log table contains records for
the audit categories defined in [LOGGING.md](../LOGGING.md):

- Successful JWT issuance
- An expired or nonexistent session request
- Privileged local inspection of a complete decrypted token

Each local record contains the event metadata permitted for its category, its
local record relationship, and its receipt state. A receipt in `STORED` state
contains:

- `hostname`
- `service`
- `before.file`, `before.filesize`, and `before.checksum`
- `after.file`, `after.filesize`, and `after.checksum`

The local table never contains an APIKEY, JWT value, token key, decrypted
payload, requested or returned field value, Database credential, HSM
credential, certificate private key, or unrestricted error text.

## Path 1: Read Audit Records on the Autobricks TrueLog Server

This path requires an authorized operator to sign in directly to the
Autobricks TrueLog server.

The client-side `ab-truelog-cli info` operation is not an audit-record query.

The receipt's `service` and `after.file` values identify the WORM file that
contains the appended record. For example:

```text
service:     autobricks-jwt
after.file:  truelog-2026-10-10.log
```

On the TrueLog server, the corresponding WORM path is:

```text
/mnt/worm-storage/autobricks-jwt/truelog-2026-10-10.log
```

An authorized operator signs in to the TrueLog server and opens that file
through the mounted WORM namespace. For example:

```sh
sudo less /mnt/worm-storage/autobricks-jwt/truelog-2026-10-10.log
```

Each stored line includes the TrueLog timestamp, source hostname, service name,
and the JSON audit event submitted by Autobricks JWT. The operator locates the
event using non-secret correlation values retained in the local audit table,
such as the event category, service identifier, result, error code, and event
time.

The available daily file can be checked with the server-side TrueLog integrity
operation:

```sh
sudo ab-truelog checksum \
  --service autobricks-jwt \
  --date 2026-10-10
```

This operation verifies the retained daily file using TrueLog's recorded chain
state and append boundaries. It verifies the file; it does not select or return
one JWT audit event.

The operator confirms:

- The path uses the receipt's exact `service` and file name.
- The selected line is an Autobricks JWT audit record with the expected event
  category and non-secret correlation values.
- The stored receipt's before and after sizes are valid and ordered.
- The stored receipt checksums are valid SHA-256 values.
- The daily file passes the server-side TrueLog checksum verification while
  its retained content remains available.

A file can contain later appends after the selected event. Current file size or
checksum metadata is therefore not assumed to equal an older receipt's
`after.filesize` or `after.checksum`. Verification uses the selected receipt as
the event's append boundary rather than replacing it with metadata from a later
write.

### `ab-truelog-cli info`

`ab-truelog-cli info --file PATH` returns the current stored WORM metadata for
the specified file, including its latest size and checksum. It does not read or
search audit records, and it does not prove that a selected historical record
is the last append in that file.

Because more records may have been appended after a JWT event, the current
metadata can differ from that event's stored `after.filesize` and
`after.checksum`. The `info` result must not be presented as the result of an
audit-record query.

## Path 2: Query the Local Audit-Log Table

The curses-based `ab-jwt-cli` provides an `Audit Logs` management screen through
the protected local management broker. Runtime JWT clients cannot query this
table.

```text
Autobricks JWT 0.1.N

Audit Logs

  Event: ALL    Receipt: ALL    From: 2026-10-10    To: 2026-10-10

  Event Time            Event                  Service          Result   Receipt
> 2026-10-10 10:01:14   JWT_ISSUED             login-issuer     SUCCESS  STORED
  2026-10-10 10:08:42   JWT_SESSION_INVALID    login-query      ERROR    STORED
  2026-10-10 10:15:03   JWT_ISSUED             login-issuer     SUCCESS  RECONCILE

  [ View ]    [ Filter ]    [ Refresh ]    [ Back ]

  Up/Down: Select record    Tab: Select action    Enter: Continue
```

The list can filter by:

- Event category
- Receipt state: `PENDING`, `STORED`, or `RECONCILE`
- Event time range
- Registered service
- Result or assigned error code when the category contains one

Filters do not grant access to a record that the management caller is not
authorized to inspect. APIKEYs, token values, token keys, decrypted fields, and
certificate secrets never appear as filter values or result columns.

## Local Audit Detail

Selecting a row displays the local event and complete receipt separately:

```text
Audit Log Detail

  Event:          JWT_SESSION_INVALID
  Event time:     2026-10-10T01:08:42Z
  Service ID:     c02c370f-5081-47d4-b2e5-d4ae4cd441e3
  Result:         ERROR
  Error code:     8060
  Error:          SESSION_NOT_FOUND_OR_EXPIRED
  Receipt state:  STORED

  TrueLog receipt
    Hostname:       autobricks-jwt
    Service:        autobricks-jwt
    Before file:    truelog-2026-10-10.log
    Before size:    104
    Before checksum: <sha256>
    After file:     truelog-2026-10-10.log
    After size:     293
    After checksum:  <sha256>

  [ Show TrueLog Location ]    [ Back ]
```

`Show TrueLog Location` displays the TrueLog service, file name, and server-side
WORM location derived from the stored receipt. It does not connect to the
TrueLog server, execute a command, or accept an arbitrary path. The service and
file name must pass the receipt path validation defined in `LOGGING.md`.

## Local Query Result

When an operator exports one authorized local record, `ab-jwt-cli` separates
the local audit event from its TrueLog receipt:

```json
{
  "audit_record": {
    "event": "JWT_SESSION_INVALID",
    "event_at": "2026-10-10T01:08:42Z",
    "service_id": "c02c370f-5081-47d4-b2e5-d4ae4cd441e3",
    "result": "ERROR",
    "error_code": 8060,
    "error": "SESSION_NOT_FOUND_OR_EXPIRED",
    "receipt_state": "STORED"
  },
  "truelog_receipt": {
    "hostname": "autobricks-jwt",
    "service": "autobricks-jwt",
    "before": {
      "file": "truelog-2026-10-10.log",
      "filesize": 104,
      "checksum": "<sha256>"
    },
    "after": {
      "file": "truelog-2026-10-10.log",
      "filesize": 293,
      "checksum": "<sha256>"
    }
  }
}
```

The local record and receipt are read-only query results. Querying them does not
change receipt state, event time, service relationships, or the TrueLog file.

## Receipt-State Handling

| State | Query behavior |
| --- | --- |
| `PENDING` | Display the local event and state. No TrueLog WORM location is presented because no valid receipt is stored. |
| `STORED` | Display the complete validated receipt and its corresponding TrueLog server-side WORM location. |
| `RECONCILE` | Display the local event and available receipt context as incomplete. Do not claim verification and do not append a duplicate event. |

The local table must not manufacture a receipt for `PENDING` or `RECONCILE`.
Only a receipt returned by the completed TrueLog append and validated by
Autobricks JWT can enter `STORED` state.

## Cross-Verification Procedure

1. Select the local audit record through `ab-jwt-cli`.
2. Confirm its event category, service, event time, result, and receipt state.
3. Require `receipt_state: STORED` before claiming completed audit evidence.
4. Display the TrueLog service and WORM file name stored in the receipt.
5. Sign in directly to the Autobricks TrueLog server with an authorized
   operator identity.
6. Open the identified WORM file and locate the actual audit record using its
   non-secret correlation values.
7. Run the server-side TrueLog checksum operation for the retained daily file
   when integrity verification is required.
8. Match the actual record and its WORM file to the local record and receipt.
9. Report the local record and immutable evidence relationship without
   exposing prohibited token or subject content.

Failure to query TrueLog does not delete or alter the local record. A local
`STORED` receipt remains preserved, but current immutable evidence verification
cannot be claimed until the TrueLog query succeeds.

## Deletion and Retention

Deleting a JWT service or client does not delete its local audit-log records,
stored receipts, or TrueLog evidence. Historical rows retain their original
service and client relationships until the local 90-day audit retention period
expires.

Autobricks JWT automatically drains an internal SQLCipher audit record and its
locally stored receipt after 90 days. Older audit evidence is checked by
signing in directly to the Autobricks TrueLog server. The local SQLCipher
retention policy and the Autobricks TrueLog WORM retention policy are separate.
Local table availability does not shorten or rewrite TrueLog retention, and
TrueLog does not use the local table as its authoritative WORM record. The
local Drain contract is defined in [Log Drain Cycle](13-log-drain-cycle.md).

## Logging of Audit Queries

Reading the local audit table, reading a WORM file on the TrueLog server, or
running a TrueLog integrity check does not create a JWT TrueLog event. Query
failures write their assigned error code and error name to the appropriate
operational log with redacted context.

An audit query never logs or returns an APIKEY, JWT, token key, decrypted
payload, requested field value, Database credential, HSM credential,
certificate private key, or unrestricted internal error.

## Errors

The local audit query and receipt verification paths use the assigned errors
from [ERROR.md](../ERROR.md), including:

| Code | Name | Audit query use |
| ---: | --- | --- |
| 8001 | `INVALID_REQUEST` | The query filter, selected record, or receipt path is invalid |
| 8006 | `REQUEST_TIMEOUT` | Local query exceeds its deadline |
| 8070 | `AUDIT_WRITE_FAILED` | The record shows that its configured TrueLog append failed |
| 8071 | `AUDIT_RECEIPT_INVALID` | Stored or returned receipt data fails validation |
| 8072 | `AUDIT_RECEIPT_STORE_FAILED` | Receipt persistence did not complete |
| 8073 | `AUDIT_RECONCILIATION_REQUIRED` | TrueLog may contain the event but local receipt state requires reconciliation |
| 8080 | `DATABASE_UNAVAILABLE` | The SQLCipher audit-log table cannot be opened |
| 8081 | `DATABASE_OPERATION_FAILED` | The local audit query cannot be completed |

TrueLog server access and TrueLog integrity operations report their own failures
independently of the JWT error registry. Such a failure must not be relabeled as
proof that the local event or receipt never existed.

## Security Boundaries

- Autobricks TrueLog is the authoritative immutable evidence store.
- An authorized operator reads TrueLog audit-record content by signing in
  directly to the TrueLog server.
- The local SQLCipher audit table is a searchable index and receipt store, not
  a replacement for TrueLog WORM evidence.
- Syslog is operational visibility and is not authoritative audit evidence.
- Audit queries are available only to authorized local management operators.
- Local records and TrueLog audit records never expose JWT protected content or
  cryptographic secrets.
- Querying evidence does not modify, delete, or append evidence.
