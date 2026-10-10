# Operational Log Query

## Purpose

Autobricks JWT writes operational events and classified service failures to the
Linux operating server's syslog. A systemd deployment queries those records
with `journalctl` using the `autobricks-jwt.service` unit.

Operational logs support service monitoring and failure investigation. They are
not immutable audit evidence and do not contain a TrueLog append receipt.

## Access

Run log queries with an operating-system account authorized to read the system
journal. Depending on the Linux configuration, this normally requires root or
membership in the administrator-approved journal-reading group.

Do not make the journal world-readable and do not copy unrestricted journal
output into an application response. Log access can reveal service timing,
client activity patterns, request identifiers permitted by the logging
contract, and internal failure classifications.

## Service Log

Show all retained records for the JWT server unit:

```sh
journalctl --unit=autobricks-jwt.service
```

Show records for the current boot only:

```sh
journalctl --unit=autobricks-jwt.service --boot
```

Show the most recent 100 records without opening a pager:

```sh
journalctl --unit=autobricks-jwt.service --lines=100 --no-pager
```

The unit filter is required when the operator intends to inspect only JWT
Server records. Omitting it mixes entries from unrelated operating-system
services.

## Live Monitoring

Follow new JWT Server records as they are written:

```sh
journalctl --unit=autobricks-jwt.service --follow
```

Start with the most recent 50 records and continue following:

```sh
journalctl --unit=autobricks-jwt.service --lines=50 --follow
```

Use live monitoring for operational diagnosis. It does not replace an alerting
or log-retention system.

## Time-Range Query

Query from an explicit time:

```sh
journalctl --unit=autobricks-jwt.service \
  --since="2026-10-10 09:00:00"
```

Query a bounded incident window:

```sh
journalctl --unit=autobricks-jwt.service \
  --since="2026-10-10 09:00:00" \
  --until="2026-10-10 09:30:00"
```

The timestamps are interpreted using the operating server's configured time
zone. JWT event payload timestamps remain RFC 3339 UTC values ending in `Z`.

## Priority Query

Show warning through emergency priorities:

```sh
journalctl --unit=autobricks-jwt.service \
  --priority=warning..emerg
```

Priority filtering is supplementary. The authoritative JWT failure
classification is the `error_code` and `error_name` assigned by
[ERROR.md](../ERROR.md).

## Error Query

Find a specific JWT error code:

```sh
journalctl --unit=autobricks-jwt.service \
  --grep='error_code.*8060' \
  --no-pager
```

Find Cache availability failures by symbolic name:

```sh
journalctl --unit=autobricks-jwt.service \
  --grep='error_name.*CACHE_UNAVAILABLE' \
  --no-pager
```

`8060 SESSION_NOT_FOUND_OR_EXPIRED` deliberately does not reveal whether the
session expired, never existed, or was already inactive. Journal queries must
not attempt to reconstruct a distinction that the service intentionally does
not log.

## Operational Event Query

Find successful issuance records written to the local journal:

```sh
journalctl --unit=autobricks-jwt.service \
  --grep='event.*JWT_ISSUED' \
  --no-pager
```

Find invalid-session event copies:

```sh
journalctl --unit=autobricks-jwt.service \
  --grep='event.*JWT_SESSION_INVALID' \
  --no-pager
```

The local `JWT_ISSUED` record can contain `request_id` and `token_id` for
authorized administrative correlation. It does not contain the JWT, subject
values, decrypted payload, APIKEY, token key, IV, or TrueLog receipt.

Successful session-status checks, successful authorized-field queries, Cache
Retention extension, and client-side policy decisions do not create JWT
operational event records.

## Structured Output

Display the journal entry and its systemd metadata as formatted JSON:

```sh
journalctl --unit=autobricks-jwt.service \
  --lines=20 \
  --output=json-pretty \
  --no-pager
```

The JSON produced by `journalctl --output=json-pretty` is the journal export
format. The service-generated JSON record is normally contained in its
`MESSAGE` field. Systemd metadata must not be confused with fields in the JWT
logging contract.

## Management Broker Log

The local management broker uses a separate systemd unit. Query its operational
records independently when diagnosing `ab-jwt-cli` management access:

```sh
journalctl --unit=autobricks-jwt-cli.service \
  --lines=100 \
  --no-pager
```

The broker log does not replace the JWT Server log. A management request can
produce relevant entries in both units, depending on where it is rejected or
fails.

## Retention and Export Boundary

`journalctl` can display only records retained by the operating system's
systemd journal configuration. Autobricks JWT client or service deletion does
not delete previously written journal records.

Exporting or forwarding operational logs is an operating-system administration
function. Any destination must preserve the prohibited-content rules in
[LOGGING.md](../LOGGING.md) and restrict access to authorized operators.

## Audit Boundary

The syslog copy of an issuance or invalid-session event is operational
visibility only. It is not the immutable TrueLog record and cannot prove that
TrueLog durably appended an event.

TrueLog audit evidence and locally stored append receipts are queried through
the audit procedure in [Audit Log Query](09-audit-log-query.md), not through
`journalctl` alone.
