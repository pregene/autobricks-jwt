# Service Registration

## Purpose

Service registration binds exactly one registered JWT `client_id` to one
service and one subject type. The client permission determines the service
credential and configuration accepted by the registration.

| Client permission | Service credential | Service capability |
| --- | --- | --- |
| `WRITE` | APIKEY scoped by the WRITE registration | Create, modify, and revoke JWT sessions |
| `READ` | APIKEY scoped by the READ registration | Check sessions and query authorized JWT fields |

READ and WRITE clients are never combined in one service registration. A Web
Server requiring both capabilities creates separate WRITE and READ service
registrations so their credentials and deployment security areas remain
independent.

## Client Binding

The request supplies one `client_id`. `ab-jwtd` loads the active client record
and uses its registered operation class; the caller cannot change or override
that permission during service registration. An inactive, deleted, unknown, or
already incompatibly bound client is rejected.

One `client_id` can be bound to multiple service registrations. When mutual
TLS is enabled, each service registration receives its own certificate. The
certificate is bound one-to-one to `service_id`, not one-to-one to `client_id`.
Services sharing the same READ or WRITE client therefore retain independent
certificate fingerprints and APIKEYs. See
[Service Certificate](16-service-certificate.md).

## Subject Type

Each service registration selects exactly one subject type: `USER`, `DEVICE`,
or `WORKLOAD`. A client application requiring another subject type creates a
separate service registration.

## WRITE Service Configuration

A WRITE registration defines exactly one subject source. The source is either
`CLIENT_JSON` or `DATABASE`. DATABASE sources use the Autobricks Cache
Connection and Cache Definition contracts without a JWT-specific alternative
schema.

### JWT Encryption Profile Selection

Every WRITE service registration selects exactly one JWT encryption profile.
The registration client makes this selection; `ab-jwtd` does not silently
choose an algorithm for the service.

`ab-jwt-cli` obtains the profiles enabled by `ab-jwtd` and displays only those
profiles as selectable values. The operator selects one profile before the
APIKEY is created. The registration request carries the selected profile name,
not caller-defined `alg`, `enc`, key-size, IV-size, or tag-size strings.

The supported profiles are:

| Profile | Serialization | `alg` | `enc` | Content-encryption key | IV | Authentication tag |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `JWE_DIR_A128GCM` | JWE Compact | `dir` | `A128GCM` | 128 bits | 96 bits | 128 bits |
| `JWE_DIR_A192GCM` | JWE Compact | `dir` | `A192GCM` | 192 bits | 96 bits | 128 bits |
| `JWE_DIR_A256GCM` | JWE Compact | `dir` | `A256GCM` | 256 bits | 96 bits | 128 bits |

These profiles use the JWE and JWA definitions in RFC 7516 and RFC 7518. Each
uses direct symmetric key management and AES-GCM authenticated encryption. The
JWE Encrypted Key component is empty for `alg: dir`.

Logical profile selection:

```json
{
  "jwt_encryption_profile": "JWE_DIR_A256GCM"
}
```

Registration rejects an omitted profile, an unknown profile, a disabled
profile, or an attempt to submit raw JOSE algorithm parameters. READ service
registration does not select an encryption profile because it does not issue
tokens.

The selected profile is stored with `service_id` and bound to the WRITE APIKEY.
Every JWT issued through that APIKEY uses the stored profile. A runtime
`JWT_CREATE` request cannot supply or override `jwt_encryption_profile`, `alg`,
`enc`, `typ`, key size, IV size, or authentication-tag size.

The service-registration result returns the selected profile and resolved JOSE
parameters with the APIKEY:

```json
{
  "service_id": "<service-uuid>",
  "client_id": "<write-client-uuid>",
  "operation_class": "WRITE",
  "apikey": "<write-apikey>",
  "jwt_encryption_profile": {
    "name": "JWE_DIR_A256GCM",
    "serialization": "JWE_COMPACT",
    "alg": "dir",
    "enc": "A256GCM",
    "typ": "autobricks+jwt",
    "key_bits": 256,
    "iv_bits": 96,
    "tag_bits": 128
  }
}
```

The returned object allows the registering client to verify that the stored
profile matches its selection. The APIKEY remains an authorization credential;
it is not an encryption key and does not reveal the token-specific
content-encryption key.

### CLIENT_JSON Source

`CLIENT_JSON` allows the WRITE client to supply the subject data in the JWT
issuance request. Autobricks JWT does not load the subject from a Database when
this source type is registered.

Service registration defines which JSON fields the WRITE client may supply,
which fields are required, and the expected value type for each field. An
issuance request is rejected when it contains an unregistered field, omits a
required field, supplies an invalid value type, or does not match the registered
subject type. The supplied JSON is treated as subject source data; it does not
grant permission or replace the WRITE client credential, `client_id`, or
APIKEY.

The WRITE client is responsible for the correctness and integrity of the
subject data it submits. Autobricks JWT validates the request against the
registered field contract, creates the encrypted JWT, and stores the session.
It does not independently verify submitted values against a user, device, or
workload Database unless the service is registered with a `DATABASE` source.

A `CLIENT_JSON` registration does not create a Database Connection or Cache
Definition and therefore does not accept Connection, MAP, SELECT, UPDATE, TLS,
or mTLS Database settings.

### DATABASE Source

`connection_id` is generated by Autobricks JWT when it creates the internal
Database Connection. It is not accepted as an operator-supplied registration
field and is returned in the successful creation result.

For a network Database Connection, transport protection can be disabled or set
to TLS or mTLS. TLS accepts only the trust chain used to authenticate the
Database Server. mTLS additionally accepts a Client certificate and private
key. Fields that do not apply to the selected mode are omitted. SQLite does not
use network TLS fields.

The Cache Definition provides Primary Key and MAP lookup fields, SELECT loading,
optional UPDATE behavior, and Retention. JWT does not perform INSERT or DELETE;
those fixed Cache Definition entries contain empty query strings and empty field
arrays.

### Field List Input

Fields entered through `ab-jwt-cli` use a comma-separated list. Whitespace
before or after a comma is ignored. Field names must not be empty or repeated.

```text
user_id, display_name, status
```

The value above is converted to the following JSON array in the registration
request:

```json
["user_id", "display_name", "status"]
```

This input rule applies to Primary Key fields, SELECT fields, UPDATE fields,
CLIENT_JSON field declarations, and allowed JWT query fields. A single field is
entered without a comma:

```text
user_id
```

### SELECT Query and Binding Order

`select.fields` defines the parameter-binding order for the single SELECT Query.
The first field supplies `$1`, the second supplies `$2`, and so on. The number
of SQL placeholders must equal the number of fields.

For example:

```text
SELECT query:
SELECT * FROM users WHERE tenant_id = $1 AND user_id = $2

SELECT fields:
tenant_id, user_id
```

This produces:

```json
{
  "select": {
    "query": "SELECT * FROM users WHERE tenant_id = $1 AND user_id = $2",
    "fields": ["tenant_id", "user_id"]
  }
}
```

An ON_DEMAND Cache requires at least one SELECT field. A PRELOAD Cache uses a
parameterless SELECT and therefore has an empty SELECT field list. SELECT result
columns must include the Primary Key and every column required by the configured
MAPs and JWT source fields.

### SELECT Result Column Mapping

`select.fields` describes input values bound to SQL placeholders; it does not
list the columns returned by the SELECT. Returned columns are discovered from
the result metadata supplied by the Database Driver. Their column labels become
the internal subject-field names. This is equivalent to mapping the column
names visible in the Database schema, but Autobricks JWT does not need to issue
a separate `DESC` statement for every lookup.

For a table whose columns are:

```text
id
user_id
password
last_ip
created_at
role
```

the following parameterless query returns all of those columns:

```sql
SELECT * FROM users;
```

The loaded Database record is mapped by column name:

```json
{
  "id": "...",
  "user_id": "...",
  "password": "...",
  "last_ip": "...",
  "created_at": "...",
  "role": "..."
}
```

When a JWT is issued, the mapped subject fields become fields in the JWT's
encrypted internal payload together with JWT session metadata. The complete
decrypted payload is retained inside Autobricks JWT and is never returned to a
Web Service or READ client.

Conceptually, Autobricks JWT constructs an internal value before encryption:

```json
{
  "iss": "autobricks-jwt",
  "sub": "<subject-identifier>",
  "aud": "<registered-service-id>",
  "iat": 0,
  "nbf": 0,
  "exp": 0,
  "jti": "...",
  "subject_type": "USER",
  "claims": {
    "id": "...",
    "user_id": "...",
    "last_ip": "...",
    "created_at": "...",
    "role": "..."
  }
}
```

The returned encrypted token is produced from this internal value. `token` is
an issuance-response field and is not inserted into its own JWT payload. The
WRITE client receives an opaque result such as `{ "token": "..." }`; it does
not receive `id`, `user_id`, or the other decrypted subject fields alongside
the token. An authorized READ client can later request only the individual
fields allowed by its service registration.

### Issued Token and Subsequent Operations

Successful JWT creation returns an opaque encrypted `token`. That token
identifies the stored JWT session and is subsequently supplied when a client
requests a session-status check, an authorized field query, a WRITE
modification, or revocation. The client does not decode the token to perform
these operations; Autobricks JWT decrypts and validates it internally.

Possession of the token alone does not authorize an operation. Each subsequent
request must also pass the registered connection credential, active
`client_id`, matching APIKEY, operation-class, service-binding, session-state,
and field-authorization checks. A READ registration can use the token only for
status and permitted field queries. A WRITE registration can use it only for
the defined modification and revocation operations; WRITE does not gain field
query permission.

The runtime contracts are described in greater detail in:

- [03 - Service JSON Web Token Issuance](03-service-json-web-token-issuance.md),
  including token creation and WRITE-side session handling
- [04 - Service JSON Web Token Query](04-service-json-web-token-query.md),
  including status checks and field-authorized READ access
- [05 - Service JSON Web Token Revocation](05-service-json-web-token-revocation.md),
  including explicit session invalidation

Column aliases determine the mapped field name. For example,
`SELECT user_id, created_at AS joined_at FROM users WHERE user_id = $1` maps
the returned values to `user_id` and `joined_at`. Duplicate result-column names
are invalid unless aliases make them unique.

`SELECT *` also loads columns that should not normally become JWT fields, such
as a password hash or recovery secret. Service registration should therefore
use an explicit SELECT column list containing only the subject fields required
by the JWT. Field-query authorization limits what READ clients can retrieve,
but it is not a reason to place unnecessary secrets in the encrypted payload.

For example:

```text
SELECT query:
SELECT id, user_id, last_ip, created_at, role
FROM users
WHERE user_id = $1

SELECT fields:
user_id
```

Here `user_id` in `SELECT fields` supplies the value for `$1`; it does not
restrict the SELECT result to the `user_id` column. The SQL projection controls
which columns are loaded and mapped into the internal JWT payload.

### UPDATE Query and Binding Order

`update.fields` also defines SQL parameter-binding order. Each field must occupy
the same position as its placeholder in the UPDATE statement. For example:

```text
UPDATE query:
UPDATE users SET last_ip = $1 WHERE user_id = $2

UPDATE fields:
last_ip, user_id
```

The registration request contains:

```json
{
  "update": {
    "query": "UPDATE users SET last_ip = $1 WHERE user_id = $2",
    "fields": ["last_ip", "user_id"]
  }
}
```

In this example, `last_ip` is bound to `$1` and `user_id` is bound to `$2`.
Reversing the field list would bind the values to the wrong SQL parameters and
must be rejected during registration or Database statement preparation.

UPDATE is optional. When no UPDATE behavior is required, both the UPDATE Query
and UPDATE fields remain empty. INSERT and DELETE are never entered for an
Autobricks JWT subject source; their fixed Cache Definition entries remain
empty.

A successful WRITE registration returns one `apikey` bound to the service,
WRITE `client_id`, subject type, and selected JWT encryption profile.

## READ Service Configuration

A READ registration defines the JWT fields that the service may query. These
are JWT response-field permissions, not Database columns, MAP definitions, or
SQL parameters. READ registration does not configure subject sources or grant
JWT state-changing permission.

The allowed JWT fields are entered as a comma-separated list. For example,
`user_id, role, tenant_id` registers the JSON array `["user_id", "role",
"tenant_id"]` as the service's field allowlist.

A successful READ registration returns one `apikey` bound to the service, READ
`client_id`, subject type, and field authorization.

### Field-Level Query Authorization

A READ `client_id` does not receive permission to query every field stored in a
JWT session. Service registration records an explicit allowlist of fields that
the service may request. Different services can therefore use the same JWT
session while receiving only the values required for their own function.

Every field-query request must satisfy all of the following conditions:

- The connection credential is valid for the registered client.
- The `client_id` is active and has READ permission.
- The APIKEY is active and bound to the same service and `client_id`.
- The requested subject type is authorized by the service registration.
- Every requested field appears in that service's field allowlist.

Autobricks JWT rejects the complete request with `8064
FIELD_NOT_AUTHORIZED` when any requested field is not registered. It does not
silently omit unauthorized fields because a partial response could conceal a
client authorization error. The service never provides an operation that
returns the complete decrypted JWT payload.

The field allowlist is bound to the READ service registration. Possession of an
APIKEY does not permit its holder to use another `client_id`, query another
service's fields, create a JWT session, or expand the registered field scope.
Changing the allowlist is a management operation and does not occur through the
runtime field-query interface.

## Security Boundary

The APIKEY authenticates the registered service request but does not replace
the client credential or client permission. Runtime authorization requires the
connection credential, active `client_id`, matching service binding, matching
APIKEY, and registered subject or field permissions to agree.
