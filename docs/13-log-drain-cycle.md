# Log Drain Cycle

## Scope

Defines creation, retention, Drain eligibility, and removal boundaries for
Autobricks JWT request, issuance, query, audit, connection-access, and
classified service-error logs.

## Internal Record Retention

Autobricks JWT does not accumulate internal activity records indefinitely. The
following SQLCipher records are retained for a maximum of 90 days:

- Request logs
- JWT issuance logs
- JWT query logs
- Audit logs and their locally stored TrueLog receipts

Each category is retained only when it was enabled during installation. A
disabled category does not create a local log record or its optional
operational activity syslog entry. Audit logging disabled at event time also
does not create a TrueLog event or receipt.

Historical activity omitted while a category was disabled cannot later be
queried, recovered from a Database backup, or reconstructed.

The retention age is calculated from the UTC time at which each internal record
was stored. When a record becomes older than 90 days, the service deletes it
automatically through internal data Drain processing.

Viewing, filtering, exporting, or correlating a record does not extend its
90-day retention period. Restarting the JWT service also does not reset the
retention age.

The 90-day rule applies to internal logs and history records. It does not
delete an active JWT session, a key required by an active token, an active
client or service registration, or current configuration merely because a
related log record reached its retention limit.

Minimal current state required to process an active JWT operation is not a log
record. Disabling an optional log category does not remove the state required
for active-session validation, request idempotency, authorization, or
cryptographic processing; it removes the corresponding historical log view.

## Mandatory Connection Access Logs

Connection access logs are always enabled and are not part of the optional
90-day internal log categories. The installer and runtime configuration cannot
disable them.

Every accepted or rejected connection writes a redacted access entry to the
operating server's syslog. Optional request, issuance, query, or audit logging
settings do not suppress connection access logs or classified service-error
logs.

## Local Audit-Log Retention

Autobricks JWT retains its internal SQLCipher audit-log records for a maximum
of 90 days. The retention age is calculated from the UTC time at which the
local audit record was stored.

When a local audit record becomes older than 90 days, the service automatically
deletes that record during its internal data Drain processing. The deletion
includes the TrueLog append receipt stored with that local audit record. It
does not delete or modify the corresponding immutable record in Autobricks
TrueLog.

## Audit Records Older Than 90 Days

Autobricks JWT does not return an internal SQLCipher audit-log record after its
90-day retention period has expired and the record has been drained. An
authorized operator checks older audit evidence by signing in directly to the
Autobricks TrueLog server and reading the retained WORM record.

Autobricks JWT does not use local Drain processing to shorten, extend, or
otherwise change Autobricks TrueLog retention. TrueLog evidence remains subject
to the retention policy configured for the TrueLog service.

When TrueLog integration was not enabled when the event occurred, no TrueLog
evidence or receipt exists for that event; the syslog copy is operational data
and is not a replacement for audit evidence.

Drained request, issuance, and query logs are not reconstructed from TrueLog.
Only the audit events defined in [LOGGING.md](../LOGGING.md) are stored as
TrueLog evidence and can be checked there after their local copies are drained.

## Audit Drain Boundaries

- Drain removes expired request logs, issuance logs, query logs, audit logs,
  and locally stored TrueLog receipts from SQLCipher.
- Drain does not delete encrypted token state or token-key records required by
  an active session, client records, service records, active sessions, current
  configuration, or source Database records merely because a related log
  record reached 90 days.
- Drain does not send a deletion request to Autobricks TrueLog.
- A drained local record cannot be reconstructed from its former local receipt.
- TrueLog audit content is checked through the server-local query process
  defined in [Audit Log Query](09-audit-log-query.md).
