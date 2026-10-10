# Runtime Operation Definitions

## Purpose

Every runtime request declares one fixed `operation`. Autobricks JWT resolves
that value through its internal SQLCipher `operations` definition table before
request-specific processing. Unknown or inactive names are rejected with `8002
UNSUPPORTED_OPERATION`.

The operation name does not grant permission. Effective authorization remains
the intersection of the connection credential, active `client_id`, service
binding, APIKEY, and the operation class recorded for the operation.

## SQLCipher Definition Table

The built-in table contains the fixed protocol registry:

| Field | Required | Meaning |
| --- | --- | --- |
| `operation` | Yes | Unique protocol operation name |
| `operation_class` | Yes | Required `READ` or `WRITE` permission |

The registry contains these definitions:

| Operation | Class | Purpose |
| --- | --- | --- |
| `JWT_CREATE` | `WRITE` | Create and persist a new encrypted JWT session |
| `JWT_UPDATE` | `WRITE` | Modify the permitted state of an active JWT session |
| `JWT_REVOKE` | `WRITE` | Revoke an active JWT session |
| `JWT_QUERY` | `READ` | Check an active session and return only authorized requested fields |

These definitions are product protocol data. Service registration cannot add,
rename, or change their permission class. A request-history row stores the
resolved operation name so its purpose and required permission remain explicit.

## Common Request Fields

Every operation request contains:

| Field | Meaning |
| --- | --- |
| `operation` | One name from the operation registry |
| `client_id` | Registered client authorized for the required operation class |
| `apikey` | APIKEY bound to the same client, service, and operation class |
| `request_id` | Client-generated identifier unique within that client |

The remaining fields depend on the selected operation.

## JWT_CREATE

DATABASE source example:

```json
{
  "operation": "JWT_CREATE",
  "client_id": "<write-client-id>",
  "apikey": "<write-apikey>",
  "request_id": "<client-request-id>",
  "conditions": [
    {
      "field": "user_id",
      "value": "user-1001"
    }
  ]
}
```

CLIENT_JSON source example:

```json
{
  "operation": "JWT_CREATE",
  "client_id": "<write-client-id>",
  "apikey": "<write-apikey>",
  "request_id": "<client-request-id>",
  "data": {
    "user_id": "user-1001",
    "role": "member"
  }
}
```

The registered source type determines whether `conditions` or `data` is
accepted. Details are defined in
[Service JSON Web Token Issuance](03-service-json-web-token-issuance.md).

Successful creation returns both the lookup UUID and the complete encrypted
token:

```json
{
  "token_id": "73475423-3470-4da3-b702-0d234b3632cd",
  "token": "<base64url-jwe-compact-token>"
}
```

The two values have a one-to-one relationship. The client retains both and
supplies both for later query, update, and revoke operations.

`token` is a JWE Compact Serialization string using the JWT encryption profile
selected during WRITE service registration. The profile uses `alg: dir` with
`A128GCM`, `A192GCM`, or `A256GCM`. Its protected header, initialization vector,
ciphertext, and authentication tag are individually Base64URL encoded without
`=` padding. The Encrypted Key component is empty, and all five component
positions are joined with four `.` separators. The whole compact token is not
wrapped in another Base64 layer. A runtime operation cannot override the
registered profile.

## JWT_UPDATE

```json
{
  "operation": "JWT_UPDATE",
  "client_id": "<write-client-id>",
  "apikey": "<write-apikey>",
  "request_id": "<client-request-id>",
  "token_id": "<token-uuid>",
  "token": "<base64url-jwe-compact-token>",
  "updates": [
    {
      "field": "authentication_context",
      "value": "passkey"
    }
  ]
}
```

`JWT_UPDATE` uses upsert behavior inside the encrypted `claims` object. If the
field already exists, its value is replaced. If it does not exist, the field is
added. The field does not need to be a Database column.

The internal `claims` value is a dynamic JSON object rather than a fixed mirror
of the source Database schema. `JWT_UPDATE` can therefore add a new application
field that was not returned by the original SELECT and does not exist as a
Database column. This capability does not require a separate field declaration
during service registration.

Reserved JWT metadata such as `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, and
`token_id` is outside `claims` and cannot be added or replaced through
`updates`. Field names, JSON value types, nesting depth, field count, and payload
size remain subject to JWT update validation and configured safety limits.

Autobricks JWT decrypts the submitted token internally, applies the validated
claim upserts, creates a replacement encrypted token with a new token-specific key,
and keeps the same `token_id` and `jti` for the session. The previous encrypted
token version becomes invalid. SQLCipher retains the version history, and the
Session Cache atomically replaces the active token digest and key reference.

Successful update returns the same lookup UUID and the replacement token:

```json
{
  "token_id": "<token-uuid>",
  "token": "<replacement-base64url-jwe-compact-token>"
}
```

A WRITE client does not receive the existing decrypted values as part of this
operation.

## JWT_REVOKE

```json
{
  "operation": "JWT_REVOKE",
  "client_id": "<write-client-id>",
  "apikey": "<write-apikey>",
  "request_id": "<client-request-id>",
  "token_id": "<token-uuid>",
  "token": "<base64url-jwe-compact-token>"
}
```

Revocation invalidates the active session identified by the token. Details are
defined in
[Service JSON Web Token Revocation](05-service-json-web-token-revocation.md).

## JWT_QUERY

Active-session status example:

```json
{
  "operation": "JWT_QUERY",
  "client_id": "<read-client-id>",
  "apikey": "<read-apikey>",
  "request_id": "<client-request-id>",
  "token_id": "<token-uuid>",
  "token": "<base64url-jwe-compact-token>"
}
```

Authorized-field query example:

```json
{
  "operation": "JWT_QUERY",
  "client_id": "<read-client-id>",
  "apikey": "<read-apikey>",
  "request_id": "<client-request-id>",
  "token_id": "<token-uuid>",
  "token": "<base64url-jwe-compact-token>",
  "fields": ["user_id", "role"]
}
```

When `fields` is absent, the operation checks only whether the session is
active. When `fields` is present, it must be a nonempty list and the response
contains only fields present in the READ service registration's allowlist. The
interface never returns the complete decrypted payload. Active session checking
and field-query behavior are defined in
[Service JSON Web Token Query](04-service-json-web-token-query.md).

## Security Rules

- `operation` selects processing behavior but never supplies authorization.
- Query, update, and revoke requests require both `token_id` and the complete
  encrypted `token`; `token_id` is only a lookup accelerator.
- READ credentials cannot execute WRITE operations.
- WRITE credentials cannot execute `JWT_QUERY`.
- APIKEYs, tokens, token keys, and subject values are never stored in the
  operation definition table or written to logs.
- Request-specific validation occurs only after the operation and its required
  permission class have been resolved.
