# JWT Client Deletion

## Purpose

JWT client deletion is a local `ab-jwt-cli` management operation that removes
one registered `client_id` and every service authorization below it. The
operator selects the client from the same JWT Client Management screen used to
enter process 06, then chooses `Delete Client` instead of opening its services.

Client deletion cascades through the selected client's complete authorization
scope. It deletes all bound READ or WRITE service registrations, revokes their
APIKEYs, terminates the client's active connections, and revokes active
sessions issued by its WRITE services. Historical records remain available for
authorized administrative and audit verification.

This operation is available only through the protected local management path.
Runtime JWT transports cannot list or delete clients.

## JWT Client Management Screen

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

The highlighted row contains the authoritative `client_id`. The operator does
not type or edit it. `Services` enters the service-management process described
in [Service Deletion](06-service-deletion.md). `Delete Client` opens the client
deletion impact screen.

The client list never displays certificate private keys, APIKEY values,
Database credentials, JWT values, token keys, or decrypted fields.

## Client Detail and Cascade Impact

Before confirmation, `ab-jwt-cli` loads the current client, all bound services,
APIKEY counts, active connections, and active sessions from `ab-jwtd`:

```text
Delete JWT Client

  Client name:            token-server
  Client ID:              53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a
  Operation class:        WRITE
  Transports:             UNIX, mTLS
  Status:                 ACTIVE
  Bound services:         2
  Active APIKEYs:         2
  Active connections:     3
  Active sessions:        27

  Services to delete:
    - login-issuer
    - admin-login-issuer

  Deletion impact:
    - Disable this client identity and fingerprint authorization
    - Close 3 active client connections
    - Delete 2 bound service registrations
    - Revoke 2 service APIKEYs
    - Revoke 27 active sessions issued by the WRITE services
    - Preserve client, service, token, key, and audit history

  [ Continue ]    [ Back ]
```

For a READ client, deletion removes all bound field-query services and APIKEYs
but does not revoke JWT sessions issued by a different WRITE client. For a
WRITE client, every active session issued by every bound WRITE service is
included in the cascade deletion set.

The displayed counts are a preview. `ab-jwtd` recalculates them after final
confirmation so a connection, service, or session change cannot escape the
deletion set by occurring between screens.

## Confirmation Screen

The confirmation screen shows the selected client and the cascade totals.
`Cancel` is selected by default.

```text
Confirm JWT Client Deletion

  Client:            token-server
  Operation:         WRITE
  Services:          2
  APIKEYs:           2
  Active sessions:   27

  The client and every bound service will be deleted. All service APIKEYs and
  active sessions issued by this WRITE client will be revoked.

  [ Cancel ]    [ Delete Client ]
```

Left, Right, Tab, and Shift+Tab change the selected action. Enter activates the
selected action. Escape cancels. The operator does not retype the client name,
`client_id`, or a confirmation phrase.

Immediately before state changes begin, `ab-jwtd` resolves the selected
`client_id` again and requires the client name, operation class, registration
state, and management selection to match the preview.

## Deletion Parameters

After confirmation, `ab-jwt-cli` displays the accepted request separately from
the result:

```json
{
  "operation": "JWT_CLIENT_DELETE",
  "request_id": "<management-request-uuid>",
  "client_id": "53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a"
}
```

The management request does not contain an APIKEY. The protected management
socket, filesystem permission, Unix peer credentials, broker authorization,
and `ab-jwtd` management permission authorize the operation.

## Processing

`ab-jwtd` processes confirmed client deletion in this order:

1. Authenticate the local management connection and authorized operator.
2. Validate `request_id` and the selected `client_id`.
3. Load the active client, transport identities, bound services, service
   certificate fingerprints, APIKEYs, active connections, and dependent active
   sessions.
4. Reject a missing, already deleted, stale, or unauthorized client selection.
5. Block new connections and management or runtime operations for that
   `client_id`.
6. Mark every bound service registration `DELETED` and revoke every APIKEY
   issued for those registrations.
7. For a WRITE client, mark every active session issued by its bound services
   `REVOKED`, record the revocation time, and remove the active Cache and
   `token_id` MAP entries.
8. For a READ client, remove all field-query authorizations without changing
   sessions issued by another WRITE client.
9. Retire every active or pending service certificate under the client, mark
   the client registration `DELETED`, record `deleted_at`, and prevent its Unix
   peer identity, source CIDR, or service certificate from authenticating
   again.
10. Close every active connection bound to that client so keep-alive cannot
    continue after deletion.
11. Remove every runtime Cache entry owned by the client and its deleted
    services, including client identity, service-certificate fingerprints,
    service, APIKEY, field allowlist, subject-source, active-session, `token_id`
    MAP, token-key, and token-validation Cache entries.
12. Release service-owned Cache Definitions and Database Connection resources
    after their pending work has reached the deletion-safe state. A shared
    Cache or Connection remains active for other registered owners, but every
    entry and reference belonging to the deleted client is removed.
13. Preserve client, service, request, issuance, token-version, key,
    revocation, error, and audit-receipt history.
14. Return the deletion result and refresh the JWT Client Management list.

The cascade is fail-closed. Completion is not reported while a bound service or
APIKEY remains active, an issued session in the deletion set remains active, or
an existing connection can continue using the deleted client identity. It is
also not reported while a Cache entry or service-owned Cache resource can still
authorize, locate, or reactivate the deleted client, service, APIKEY, or session.

## Cache Cleanup

Client deletion clears every Cache layer associated with the selected
`client_id` and its cascade deletion set:

- Client registration, transport identity, service-certificate fingerprint,
  and source CIDR lookup entries
- Bound service and APIKEY authorization entries
- READ field-allowlist entries
- WRITE subject-source Cache and MAP entries owned by deleted services
- Active session and `token_id` MAP entries issued by deleted WRITE services
- In-memory token-key and token-validation entries for revoked sessions
- Retention timers and pending reload paths that could restore deleted state

Cache cleanup does not physically delete SQLCipher history, token versions,
keys, revocation records, or stored audit receipts. Those records remain
durable historical evidence and cannot be used to repopulate an active Cache
entry for a deleted client. Enabled request, issuance, query, and audit
logs remain only until their normal 90-day Drain applies.

When a Cache Definition or Database Connection is shared, deletion removes only
the deleted client's ownership references and entries. The shared resource is
released only when no active registered owner remains. Client deletion must not
remove or invalidate Cache data owned by another active client.

## Historical Records and Logs

Client deletion does not immediately delete records that were created before
the deletion:

- Enabled JWT request and issuance logs still within their retention period
- Issued token and token-version history
- Token-key, IV, session-state, and revocation history
- Previously stored TrueLog append receipts
- Operating server syslog records
- Immutable Autobricks TrueLog audit evidence

The deletion timestamp and deleted state are added to the retained management
history. Existing records are not rewritten to hide the former client, service,
APIKEY authorization, issuance, query error, or revocation relationship.

Cache cleanup removes only active runtime copies and lookup paths. It does not
apply a deletion request to the operating system's log retention facility or
to Autobricks TrueLog. Log retention and authorized log retrieval remain
governed by their respective operational systems. Internal SQLCipher logs are
automatically removed by the 90-day Drain contract.

## Deletion Result

```json
{
  "request_id": "<management-request-uuid>",
  "client_id": "53f6bd4c-fe3d-494b-ae27-4ba66fdfb87a",
  "client_name": "token-server",
  "operation_class": "WRITE",
  "status": "DELETED",
  "deleted_service_count": 2,
  "revoked_apikey_count": 2,
  "closed_connection_count": 3,
  "revoked_session_count": 27,
  "deleted_at": "2026-01-01T00:00:00Z"
}
```

The result does not contain APIKEY values, certificate contents, fingerprints,
JWTs, token keys, decrypted fields, or audit receipts. The deleted client is
removed from the default active-only list and remains visible through the
`DELETED` or `ALL` filter.

## State and History Rules

- Client deletion is a logical state transition, not physical removal of the
  SQLCipher client record.
- Every service bound to the deleted client is logically deleted in the same
  cascade.
- The deleted `client_id` cannot be reused.
- Deleted service IDs and revoked APIKEYs cannot be restored.
- Re-registering an equivalent client creates a new `client_id`, service IDs,
  APIKEYs, and certificate identity when certificates are used.
- Retired service certificate fingerprints are retained only as protected
  historical evidence and can never authenticate an active service.
- Existing token, key, and revocation records remain connected to their
  historical client and service IDs. Enabled issuance and TrueLog
  receipt logs retain those relationships until their 90-day Drain.
- Previously written operational syslog records remain unchanged.
- Client deletion does not delete or rewrite immutable TrueLog evidence.

## Logging and Audit

JWT client deletion does not create a JWT TrueLog event or append receipt. It
does not modify existing TrueLog records or their locally stored receipts.

Every classified failure writes its assigned `error_code` and `error_name` to
the operating server's syslog with redacted context. The client certificate,
fingerprint, APIKEYs, JWT values, keys, decrypted fields, Database credentials,
and connection secrets are never logged.

## Errors

The deletion path uses the assigned errors from [ERROR.md](../ERROR.md),
including:

| Code | Name | Client deletion use |
| ---: | --- | --- |
| 8001 | `INVALID_REQUEST` | The management request or selected client identifier is invalid |
| 8006 | `REQUEST_TIMEOUT` | Cascade deletion does not complete within its management deadline |
| 8020 | `CLIENT_REGISTRATION_INACTIVE` | The selected client is already inactive or deleted |
| 8081 | `DATABASE_OPERATION_FAILED` | The durable cascade state cannot be completed |
| 8082 | `CACHE_UNAVAILABLE` | Active WRITE sessions cannot be invalidated safely |

An unauthorized local caller is rejected at the management socket and broker
authorization boundary. Internal causes map to the safe response defined by
`ERROR.md`; partial deletion is never reported as successful completion.

## Security Boundaries

- Only the local `ab-jwt-cli` management path can delete a JWT client.
- Runtime clients cannot list or delete client registrations.
- The selected `client_id` scopes the complete cascade deletion set.
- Every service and APIKEY below that client is removed from active use.
- WRITE client deletion revokes the active sessions issued by all of its bound
  services.
- READ client deletion removes query permissions without revoking sessions
  issued by a different WRITE client.
- Existing keep-alive connections are closed after the client is disabled.
- All client-owned authorization, subject-source, session, MAP, token-key,
  validation, and Retention Cache state is removed.
- Historical records remain non-runnable evidence and cannot restore access.
