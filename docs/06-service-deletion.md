# Service Deletion

## Purpose

Service deletion is a local management operation provided by the curses-based
`ab-jwt-cli`. The operator first selects a registered JWT client, opens the
services bound to that `client_id`, selects one service, reviews its identity
and deletion impact, and confirms deletion.

The operation is not available through UNIX, TCP, TLS, or mTLS JWT runtime
interfaces. The interactive client reaches `ab-jwtd` only through the protected
`autobricks-jwt-cli.service` management broker and server management socket.

## JWT Client Selection

`ab-jwt-cli` opens the registered-client list before showing services:

```text
Autobricks JWT 0.1.N

JWT Client Management

  Filter: ACTIVE

  Client Name          Operation  Transports       Services  Status
> token-server         WRITE      UNIX, mTLS       2         ACTIVE
  business-web         READ       mTLS             2         ACTIVE
  device-policy        READ       UNIX             1         ACTIVE

  [ Services ]    [ Delete Client ]    [ Filter ]    [ Refresh ]    [ Back ]

  Up/Down: Select client    Tab: Select action    Enter: Continue
```

The highlighted row carries its authoritative `client_id`; the operator does
not type or edit that identifier. Selecting `Services` or pressing Enter on the
highlighted client loads only the service registrations bound to that
`client_id`.

The client screen does not delete the client. Client deletion belongs to
[JWT Client Deletion](07-jwt-client-deletion.md) and begins from the `Delete
Client` action on this shared screen.

## Service Management Screen

After the client selection, `ab-jwt-cli` opens that client's service list:

```text
Autobricks JWT 0.1.N

Service Management

  Client: token-server
  Client ID: 53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a
  Operation: WRITE
  Filter: ACTIVE

  Service Name          Subject   Active Sessions  Status
> login-issuer          USER      24               ACTIVE
  admin-login-issuer    USER      3                ACTIVE

  [ View ]    [ Delete ]    [ Filter ]    [ Refresh ]    [ Back ]

  Up/Down: Select service    Tab: Select action    Enter: Continue
```

The client and service lists are loaded from `ab-jwtd`; they are not local
configuration-file lists. Every service row is bound to the selected
`client_id` and inherits that client's READ or WRITE operation class. A service
belonging to another client cannot appear in this scoped list.

The screen displays only the fields needed to distinguish registrations:

- Service name
- Subject type
- Active-session count when the selected client is WRITE
- Active or deleted state

APIKEY values, certificate private keys, Database credentials, JWT values, and
decrypted fields never appear in the list.

## Keyboard Behavior

- Up and Down move the highlighted client or service row.
- Page Up and Page Down move through a list larger than the terminal.
- Tab and Shift+Tab move between actions.
- Enter activates the highlighted action or advances to the next screen.
- Escape or the `Back` action returns without changing service state. From the
  service list, `Back` returns to the client list.
- `Filter` selects `ACTIVE`, `DELETED`, or `ALL` without changing a record.
- `Refresh` reloads the authoritative list from `ab-jwtd`.
- `Delete` is disabled when no active service is selected or the caller lacks
  service-deletion permission.

Terminal resizing preserves the selected `client_id` and `service_id` when
those rows remain in the refreshed results. It never changes the client scope
or deletion target to another row based only on its screen position.

## Service Detail and Deletion Impact

Selecting `View` or `Delete` first displays the authoritative service detail:

```text
Service Details

  Service name:           login-issuer
  Service ID:             b16e32ae-85f2-4b03-9c73-c1455350b220
  Operation class:        WRITE
  Subject type:           USER
  Client name:            token-server
  Client ID:              53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a
  Status:                 ACTIVE
  Active APIKEYs:         1
  Active sessions:        24

  Deletion impact:
    - Disable this service registration
    - Revoke its APIKEY
    - Revoke 24 active sessions issued by this WRITE service
    - Preserve service, request, token, key, and audit history
    - Keep the registered JWT client unchanged

  [ Delete ]    [ Back ]
```

For a READ registration, the impact shows that its APIKEY and field-query
permission are removed. A READ registration does not own issued JWT sessions,
so deleting it does not revoke sessions issued by a WRITE service.

For a WRITE registration, deletion revokes every active session issued by that
service. This prevents a deleted issuer from leaving active JWT sessions that
can continue to be queried. The preview obtains the active-session count from
the same authoritative state used by the deletion operation; it is informative
and can change before confirmation.

Deleting a service does not delete its bound JWT client or revoke the client
certificate. Client deletion is the separate process defined in
[JWT Client Deletion](07-jwt-client-deletion.md).

## Confirmation Screen

Deletion requires a separate confirmation screen. `Cancel` is selected by
default so an accidental Enter on the detail screen cannot complete deletion.

```text
Delete Service

  Service:    login-issuer
  Operation:  WRITE
  Client:     token-server

  This action revokes the service APIKEY and all active sessions issued by
  this service. Historical records are retained.

  [ Cancel ]    [ Delete Service ]
```

Left, Right, Tab, and Shift+Tab change the selected action. Enter activates the
selected action. Escape cancels. The operator does not retype `service_id`, the
service name, or an arbitrary confirmation string.

Immediately before deletion, `ab-jwtd` resolves the selected `service_id`
again and verifies that its service name, operation class, client binding, and
active state still match the preview. A changed, missing, or already deleted
record is not deleted under stale screen data.

## Deletion Parameters

After confirmation, `ab-jwt-cli` displays the accepted management parameters
separately from the result:

```json
{
  "operation": "SERVICE_DELETE",
  "request_id": "<management-request-uuid>",
  "client_id": "53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a",
  "service_id": "b16e32ae-85f2-4b03-9c73-c1455350b220"
}
```

The request does not contain an APIKEY. Local management authorization comes
from the protected management socket, filesystem access, Unix peer credentials,
broker authorization, and the `ab-jwtd` management permission check.

## Processing

`ab-jwtd` processes a confirmed deletion in this order:

1. Authenticate the local management connection and authorized operator.
2. Validate `request_id`, selected `client_id`, and selected `service_id`.
3. Load the active client and require the service to remain bound to that exact
   client.
4. Load the operation class, APIKEY record, and dependent active-session count.
5. Reject stale, missing, already deleted, incorrectly bound, or unauthorized
   selections.
6. Mark the service registration `DELETED` and record `deleted_at`.
7. Revoke every APIKEY belonging to that service registration.
8. For a WRITE service, mark its active sessions `REVOKED`, record their
   revocation time, and remove their active Cache and `token_id` MAP entries.
9. For a READ service, remove its field-query authorization without modifying
   JWT sessions issued by a WRITE service.
10. Remove the service's authorization, APIKEY, field allowlist,
    subject-source, active-session, `token_id` MAP, token-key, validation, and
    Retention entries from every applicable runtime Cache. Shared Cache
    resources and entries owned by other active services remain unchanged.
11. Preserve service, request, issuance, token-version, key, revocation, error,
   and audit-receipt history.
12. Return the completed deletion result and refresh the selected client's
    service list.

The state transition is fail-closed. A service is not reported as deleted while
its APIKEY remains usable. A WRITE service is not reported as deleted while any
session assigned to its deletion set remains active or while an owned Cache
entry can authorize, locate, or reactivate the deleted service or session.

## Deletion Result

The result is displayed as a separate JSON object:

```json
{
  "request_id": "<management-request-uuid>",
  "client_id": "53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a",
  "service_id": "b16e32ae-85f2-4b03-9c73-c1455350b220",
  "service_name": "login-issuer",
  "operation_class": "WRITE",
  "status": "DELETED",
  "revoked_apikey_count": 1,
  "revoked_session_count": 24,
  "deleted_at": "2026-01-01T00:00:00Z"
}
```

The service list then shows the record as `DELETED` when deleted records are
included by the active list filter. It disappears from the default active-only
view.

## State and History Rules

- Deletion is a logical state transition, not a physical removal of the
  SQLCipher service record.
- A deleted `service_id` cannot be reused for a new registration.
- A revoked APIKEY cannot be restored by recreating a service with the same
  name.
- Service names do not replace `service_id` as the deletion target.
- Historical tokens and token keys remain unavailable to runtime clients.
- All runtime Cache entries owned by the deleted service are removed. Durable
  SQLCipher history is not treated as a source for restoring deleted Cache
  state.
- Existing TrueLog receipt references remain attached to their historical
  local records.
- JWT request, issuance, token-version, key, session-state, revocation, and
  error history created before service deletion remains in SQLCipher.
- Previously written operating server syslog records remain unchanged and are
  not part of the service-deletion transaction.
- Deletion does not remove or rewrite immutable TrueLog evidence.
- Re-registering an equivalent service creates a new `service_id` and APIKEY.

## Logging and Audit

Service deletion does not create a JWT TrueLog event or append receipt. The
operation does not modify existing TrueLog records or their locally stored
receipts.

Every classified deletion failure writes its assigned `error_code` and
`error_name` to the operating server's syslog with redacted context. APIKEYs,
JWT values, keys, decrypted fields, Database credentials, and certificate
private keys are never logged.

## Errors

The deletion path uses the assigned errors from [ERROR.md](../ERROR.md),
including:

| Code | Name | Deletion use |
| ---: | --- | --- |
| 8001 | `INVALID_REQUEST` | The management request or selected identifier is invalid |
| 8006 | `REQUEST_TIMEOUT` | Deletion does not complete within its management deadline |
| 8040 | `SERVICE_NOT_REGISTERED` | The selected service does not exist |
| 8041 | `SERVICE_REGISTRATION_INACTIVE` | The service is already inactive or deleted |
| 8081 | `DATABASE_OPERATION_FAILED` | The durable deletion state cannot be completed |
| 8082 | `CACHE_UNAVAILABLE` | Active WRITE sessions cannot be invalidated safely |

An unauthorized local caller is rejected by the management socket and broker
authorization boundary. Internal failures map to the safe response defined by
`ERROR.md`; partial success is never reported as completed deletion.

## Security Boundaries

- Only the local `ab-jwt-cli` management path can request service deletion.
- Runtime JWT clients cannot list or delete service registrations.
- The operator selects `client_id` before a service list is loaded.
- The service list contains only registrations bound to the selected client.
- List and detail screens never reveal APIKEY values or protected secrets.
- The deletion target is the selected authoritative `service_id`, not editable
  text.
- A second confirmation is required before state changes begin.
- READ service deletion removes only that READ authorization.
- WRITE service deletion removes its authority and revokes its active sessions.
- JWT client identity and certificate lifecycle remain separate from service
  deletion.
