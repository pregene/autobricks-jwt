# Autobricks JWT Audit Logging

## Scope

Autobricks JWT writes security audit events to Autobricks TrueLog and stores the returned append receipt in its local database. The TrueLog event and the local receipt record have separate formats and responsibilities.

Only these event categories are produced:

1. Successful JWT issuance
2. A request using an expired or nonexistent JWT session

No other JWT operation creates a TrueLog event.

Each `JWT_ISSUED` and `JWT_SESSION_INVALID` event is also written to the operating server's syslog for local operational visibility. The syslog copy is not audit evidence; the TrueLog record is authoritative.

## Common TrueLog Rules

- Encode each event as one UTF-8 JSON object.
- Use the configured TrueLog service name `autobricks-jwt`.
- Use lowercase JSON field names with underscores.
- Use an RFC 3339 UTC timestamp ending in `Z` for `event_at`.
- Use the fixed uppercase event, result, subject-type, and error values defined below.
- Include only the fields defined for the selected event category.
- Reject an event locally if a required field is absent, has the wrong type, or contains an unsupported value.
- Do not place a TrueLog append receipt inside the event payload.
- Do not add the TrueLog append receipt to the syslog copy of the event.

## Successful JWT Issuance

Event name: `JWT_ISSUED`

Required payload:

```json
{
  "event": "JWT_ISSUED",
  "service_id": "example-service",
  "subject_type": "USER",
  "result": "SUCCESS",
  "event_at": "2026-01-01T00:00:00Z"
}
```

Rules:

- `service_id` identifies the registered service that requested issuance.
- `subject_type` is exactly one of `USER`, `DEVICE`, or `WORKLOAD`.
- `result` is always `SUCCESS`.
- Write this event only after JWT issuance has succeeded.
- A rejected or internally failed issuance does not produce this event.

## Invalid JWT Session Request

Event name: `JWT_SESSION_INVALID`

Required payload:

```json
{
  "event": "JWT_SESSION_INVALID",
  "service_id": "example-service",
  "result": "ERROR",
  "error_code": 8060,
  "error": "SESSION_NOT_FOUND_OR_EXPIRED",
  "event_at": "2026-01-01T00:00:00Z"
}
```

Rules:

- `service_id` identifies the registered service that submitted the request.
- `result` is always `ERROR`.
- `error_code` is always `8060`.
- `error` is always `SESSION_NOT_FOUND_OR_EXPIRED`.
- The event never reveals whether the session expired or never existed.
- Repeated invalid requests produce separate events.

## Events Not Written

Autobricks JWT does not write TrueLog events for:

- Successful session-status queries
- Successful authorized-field queries
- Field-authorization decisions
- Cache lookup, mutation, persistence, or Retention extension
- Client-side policy decisions
- Service registration
- Certificate or APIKEY authentication failures
- Rejected or internally failed JWT issuance
- Internal maintenance operations

Changing this list requires an explicit architecture decision. Implementations must not introduce additional event categories implicitly.

## Syslog Service Error Logging

Every classified service failure writes a structured entry to the operating server's syslog, including failures that close a connection or map to a generic client response. Syslog is an operational service log for failure diagnosis. It is not an audit-evidence log, is not stored in TrueLog, and does not receive a TrueLog append receipt.

Required fields:

```json
{
  "level": "ERROR",
  "error_code": 8081,
  "error_name": "DATABASE_OPERATION_FAILED",
  "event_at": "2026-01-01T00:00:00Z"
}
```

Rules:

- `error_code` and `error_name` must match one assigned entry in `ERROR.md`.
- Send the entry through the platform syslog interface; do not implement it as a TrueLog write.
- Log the classified internal code even when the client receives a generic mapped code.
- A failure that closes a connection still writes its classified syslog error when logging is available.
- One failure is not relabeled with multiple root-cause codes. Boundary layers may record the client-visible mapped code separately from the root classification.
- Syslog service errors must not create an additional TrueLog event category or local audit-receipt record.
- Apply the prohibited-content rules to syslog as well as TrueLog events.
- Syslog failure must not cause recursive error logging.

## Prohibited Content

A TrueLog event must not contain:

- An APIKEY or its hash
- A JWT value
- A JWT `jti`
- A complete or partial decrypted JWT payload
- A requested or returned field value
- A subject identifier or source record
- A client certificate, private key, or issuance download token
- A database, HSM, or service credential
- A JWT cryptographic key or SQLCipher database key
- A TrueLog pairing code
- A TrueLog append receipt
- A stack trace or unrestricted error text

## Append Receipt

After a successful append, TrueLog returns the durable storage receipt:

```json
{
  "hostname": "autobricks-jwt",
  "service": "autobricks-jwt",
  "before": {
    "file": "truelog-YYYY-MM-DD.log",
    "filesize": 0,
    "checksum": "<sha256>"
  },
  "after": {
    "file": "truelog-YYYY-MM-DD.log",
    "filesize": 0,
    "checksum": "<sha256>"
  }
}
```

The receipt is not another TrueLog event. Autobricks JWT validates it and stores it in the corresponding local database record for the issuance or invalid-session event.

Receipt validation requires:

- `hostname` matches the configured TrueLog client hostname.
- `service` is `autobricks-jwt`.
- `before.file` and `after.file` are identical.
- File names contain no directory traversal.
- File sizes are nonnegative integers.
- `after.filesize` is greater than `before.filesize`.
- Both checksums are 64 lowercase hexadecimal SHA-256 values.

The local database record stores all receipt fields without modification. The service and file form the relative metadata path used for later verification:

```text
autobricks-jwt/truelog-YYYY-MM-DD.log
```

Example verification command:

```sh
ab-truelog-cli info --file autobricks-jwt/truelog-YYYY-MM-DD.log
```

## Local Receipt State

The local event record distinguishes these receipt states:

| State | Meaning |
| --- | --- |
| `PENDING` | The local event exists but no valid TrueLog receipt has been stored. |
| `STORED` | A valid TrueLog append receipt has been stored in the local event record. |
| `RECONCILE` | TrueLog may have committed the event, but local receipt persistence did not complete. |

A `RECONCILE` event must not be blindly appended again because that can create a duplicate immutable audit event.

## Ordering and Concurrency

- Preserve the receipt returned for the exact append operation; never infer it from a later write.
- Do not share one receipt between multiple local event records.
- Concurrent writers may change the file between separate appends. The before/after checksum boundary applies only to the append that returned it.
- Database queries and audit tools must treat the complete receipt as one atomic value.

## Open Decisions

The following behavior requires a separate architecture decision:

- Whether JWT issuance is returned to the caller when TrueLog is unavailable
- Whether an invalid-session response waits for TrueLog completion
- Retry limits, retry delay, and reconciliation workflow
- Local receipt-table layout and retention period
- Maximum audit-event size
