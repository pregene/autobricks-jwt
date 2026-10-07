# Autobricks JWT Architecture

Design status: initial architecture.

## Purpose

Autobricks JWT separates JWT cryptographic keys and complete payload processing from registered client services. It issues encrypted session tokens and returns only authorized fields from an active token. A Web Service can be an issuance and query client. Autobricks Policy is one optional query client and is not a required component.

## System Context

```mermaid
flowchart LR
    Issuer[Registered Issuance Client<br/>Web Service]
    Client[Registered Query Client<br/>Web Service, Policy, or Other Service]
    JWT[Autobricks JWT]
    PKI[Autobricks PKI]
    Cache[Autobricks Cache]
    DB[(Database)]
    HSM[HSM]
    Log[Autobricks TrueLog]

    Issuer -->|Issuance APIKEY\nissue JWT| JWT
    Client -->|Query APIKEY\ncheck session or query fields| JWT
    PKI -->|server and client certificates| JWT
    JWT -->|session and source Cache operations| Cache
    JWT -->|direct DB connections| DB
    Cache -->|independent Cache DB connections| DB
    JWT -->|SQLCipher DB key operations| HSM
    JWT -->|issuance or invalid-session event| Log
```

## Functional Design

### 1. Service Registration

A client service is registered before it can issue a JWT or query a JWT session. Registration defines the service identity, allowed operations, allowed subject types, and field-query authorization.

Autobricks PKI issues the JWT Service server certificate and a client certificate for the registered service. The client certificate is delivered to that service during registration. Autobricks JWT stores the issued client certificate fingerprint in the SQLCipher `clients` table. When the service connects, Autobricks JWT validates the presented certificate and matches its fingerprint to the active client record. Only a registered and currently valid certificate identity can reach JWT issuance or query operations.

Connection authentication requires all of the following checks:

1. The client certificate chains to the configured trust chain.
2. The certificate is within its validity interval and is valid for client authentication.
3. The certificate contains an OCSP responder URL in its Authority Information Access extension.
4. The certificate status obtained from that AIA OCSP URL is `GOOD`.
5. The certificate SHA-256 fingerprint matches an active record in the SQLCipher `clients` table.
6. The certificate URI SAN declares the JWT operation class assigned to that client registration.

A missing or invalid AIA OCSP URL, an unavailable or unverifiable OCSP response, and any status other than `GOOD` fail closed. APIKEY authorization begins only after certificate validation succeeds.

Client certificate usage is encoded in an exact URI SAN value:

| URI SAN | Certificate usage | Allowed JWT operation class |
| --- | --- | --- |
| `urn:autobricks:jwt:read` | Read-only | Session-status and authorized-field queries |
| `urn:autobricks:jwt:write` | Write-only | JWT issuance |

The URI SAN is a signed certificate claim, but it does not authorize access by itself. The certificate fingerprint must be actively registered, the `clients` record must contain the same operation class, and the request must use the corresponding APIKEY. A certificate issued by the PKI but not registered in `clients` remains unauthorized.

Registration produces two credentials with separate permissions:

| Credential | Permission | Consumer |
| --- | --- | --- |
| Issuance APIKEY | Issue JWT sessions for authorized subject types | Registered issuance client, such as a Web Service |
| Query APIKEY | Check an active session and query authorized JWT fields | Registered query client; Autobricks Policy is one example |

An Issuance APIKEY cannot query fields. A Query APIKEY cannot issue a JWT. Both APIKEYs are bound to the registered service.

Logical registration result:

```json
{
  "service_id": "example-service",
  "issuance_apikey": "<secret>",
  "query_apikey": "<secret>"
}
```

The APIKEY values are returned as credentials and never appear in TrueLog events, normal logs, error details, or token payloads. Certificate identity verification and APIKEY authorization are separate checks; passing either check does not bypass the other.

### 2. JWT Issuance by Subject

Every JWT session belongs to one subject. Autobricks JWT supports these subject types:

| Subject type | Meaning |
| --- | --- |
| `USER` | A human user identity |
| `DEVICE` | A device identity |
| `WORKLOAD` | An application, process, service, or workload identity |

The issuance request identifies the registered service, subject type, subject identifier, and configured source. Source data is supplied as client JSON, loaded through a configured direct database query, or created from service-defined data.

Logical issuance input:

```json
{
  "subject": {
    "type": "USER",
    "id": "user-1234"
  },
  "source": {
    "type": "DATABASE",
    "id": "user_by_id"
  }
}
```

Issuance processing:

1. Authenticates the registered service with the Issuance APIKEY.
2. Verifies that the service can issue a JWT for the requested subject type.
3. Resolves the configured source data.
4. Constructs the complete JWT payload inside Autobricks JWT.
5. Encrypts the complete payload.
6. Inserts the active session into Autobricks Cache and persists it through the configured session path.
7. Writes the successful issuance event to Autobricks TrueLog.
8. Returns only the encrypted JWT.

The caller knows data that it supplies itself but cannot obtain additional source fields or the complete constructed payload.

### 3. JWT Internal Structure

The externally visible token is a JWE compact value:

```text
BASE64URL(protected-header)
.
BASE64URL(encrypted-key)
.
BASE64URL(initialization-vector)
.
BASE64URL(ciphertext)
.
BASE64URL(authentication-tag)
```

The protected header contains only the information required to process the encrypted token. The cryptographic algorithm profile remains a deployment-independent implementation decision.

Logical protected header:

```json
{
  "typ": "JWT",
  "alg": "<key-management-algorithm>",
  "enc": "<content-encryption-algorithm>",
  "kid": "<key-identifier>"
}
```

The ciphertext contains an encrypted logical payload:

```json
{
  "iss": "autobricks-jwt",
  "sub": "user-1234",
  "subject_type": "USER",
  "aud": "example-service",
  "iat": 0,
  "exp": 0,
  "jti": "<session-identifier>",
  "claims": {
    "<field>": "<value>"
  }
}
```

The payload shown above is a logical internal structure, not a plaintext service response. Only Autobricks JWT decrypts it as a complete object. Registered client services cannot obtain this object.

### 4. JWT Expiration Status Query

The expiration-status operation accepts an encrypted JWT and a Query APIKEY. It does not return payload fields.

Processing:

1. Authenticates the registered service with the Query APIKEY.
2. Looks up the active session in Autobricks Cache.
3. Validates token integrity, audience, absolute `exp`, and session state inside Autobricks JWT.
4. Returns an active status only when the token and Cache session are both active.
5. Returns the common invalid-session error when the session is expired or does not exist.

Logical active response:

```json
{
  "status": "ACTIVE"
}
```

Logical invalid response:

```json
{
  "status": "ERROR",
  "error": "SESSION_NOT_FOUND_OR_EXPIRED"
}
```

The invalid response never distinguishes an expired session from a session that never existed.

### 5. JWT Field Query

The field-query operation accepts an encrypted JWT, a Query APIKEY, and an explicit field list.

Logical request:

```json
{
  "jwt": "<encrypted-jwt>",
  "fields": ["department", "role"]
}
```

Processing:

1. Authenticates the registered service with the Query APIKEY.
2. Confirms that the session is active.
3. Validates and decrypts the complete JWT only inside Autobricks JWT.
4. Authorizes each requested field for the registered service.
5. Projects only the authorized requested values.
6. Extends the Cache idle Retention for the active session.
7. Returns the field projection without returning the complete payload.

Logical response:

```json
{
  "fields": {
    "department": "engineering",
    "role": "reviewer"
  }
}
```

The interface provides no wildcard, root-object, or complete-payload query.

### 6. JWT Expiration

JWT session validity has two independent limits:

| Limit | Behavior |
| --- | --- |
| Absolute expiration | The encrypted payload's `exp` value defines the maximum token lifetime and is not changed by a field query. |
| Idle expiration | Autobricks Cache Retention removes a session that has no authorized activity within the configured interval. An authorized active-session query extends this interval. |

A session is active only while both limits remain valid. When either limit expires:

- The session is rejected with `SESSION_NOT_FOUND_OR_EXPIRED`.
- The database record does not reactivate the expired Cache session.
- The JWT is not reissued automatically.
- Autobricks JWT writes the common invalid-session event when the expired token is requested.

### 7. JWT Service Log Examples

Autobricks JWT writes exactly two TrueLog event categories. The examples define the allowed security content; the transport envelope used by Autobricks TrueLog remains separate.

The normative event, prohibited-content, receipt-validation, and local receipt-state rules are defined in [LOGGING.md](LOGGING.md).

Successful issuance:

```json
{
  "event": "JWT_ISSUED",
  "service_id": "example-service",
  "subject_type": "USER",
  "result": "SUCCESS",
  "event_at": "2026-01-01T00:00:00Z"
}
```

Expired or nonexistent session request:

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

The two events do not contain an APIKEY, JWT, `jti`, complete payload, decrypted field value, database credential, HSM credential, or cryptographic key. The invalid-session event always carries error code `8060`. Successful expiration-status queries, successful field queries, client-side decisions, Retention extension, and Cache activity do not create JWT TrueLog events.

After TrueLog durably appends an event, it returns an append receipt containing `hostname`, `service`, and the before/after file name, file size, and checksum. Autobricks JWT stores that complete receipt in the corresponding local database record for the issuance or invalid-session event. The receipt is database evidence and is not added to the TrueLog event payload.

Logical receipt record:

```json
{
  "event": "JWT_ISSUED",
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

The stored receipt provides the WORM file location and checksum-chain boundary needed for later audit verification. A TrueLog append is not reported as complete until a valid receipt is received. If the append succeeds but local receipt persistence fails, the event enters a reconciliation state rather than being written to TrueLog a second time without proof that duplication is safe.

## Responsibility Boundaries

| Component | Responsibility | Excluded responsibility |
| --- | --- | --- |
| Autobricks JWT | Service registration, SQLCipher client records, certificate-chain and validity verification, AIA-based OCSP validation, registered fingerprint and URI SAN usage verification, APIKEY authorization, token construction, encryption, validation, internal decryption, field authorization, session handling, two TrueLog events, and receipt persistence | Correctness of compromised external source records |
| Registered issuance client | JWT issuance requests and token transport; a Web Service is one example | JWT keys and complete decrypted payload access |
| Registered query client | Active-session checks and authorized field queries; Autobricks Policy is one example | JWT keys, direct token decryption, and complete payload access |
| Autobricks PKI | Server and client certificate issuance and trust material for TLS and mutual TLS identity | JWT issuance, payload processing, service authorization, and session state |
| Autobricks Cache | MAP-based lookup, mutation, persistence queue, and Retention according to Cache Definitions | JWT cryptography and field authorization |
| Database owner | Source-record integrity, access control, change authorization, backup security, and compromise detection | JWT cryptographic processing |
| Autobricks TrueLog | Durable storage for the two JWT event categories | Token payload inspection and client-side decisions |
| HSM | Protection and use of the SQLCipher database key | Protection from every operation performed by an authorized compromised host |

## Internal Components

```text
Service Interface
├── Unix Domain Socket
├── TCP
├── TLS
└── Mutual TLS
        │
        ▼
Request Authentication
├── Service Registry
├── Certificate chain, validity, and purpose verification
├── AIA OCSP status verification
├── SQLCipher client fingerprint verification
├── Certificate URI SAN operation verification
├── Issuance APIKEY authorization
└── Query APIKEY authorization
        │
        ├──► Issuance Service
        │     ├── Source Resolver
        │     ├── Payload Builder
        │     ├── Token Cryptography
        │     ├── Session Store
        │     └── TrueLog Writer
        │
        └──► Field Query Service
              ├── Session Lookup
              ├── Token Validation
              ├── Field Authorization
              ├── Internal Payload Decryption
              ├── Field Projection
              └── Retention Extension

Shared Infrastructure
├── Direct Database Layer
├── Autobricks Cache Adapter
├── SQLCipher Key Store
├── HSM Adapter
├── PKI/TLS Configuration
└── Error Mapper
```

### Service Interface

The service supports Unix domain socket, TCP, TLS, and mutual TLS transports according to the active dependency profile. Secure network access uses Autobricks PKI-issued identity certificates. The JWT Service presents its server certificate and validates the connecting service's client certificate chain, validity, client-authentication purpose, AIA OCSP `GOOD` status, and registered fingerprint before allowing JWT issuance or query operations. Transport selection does not change APIKEY, token, field authorization, session, database, Cache, or logging semantics.

TLS and mutual TLS are enabled only when the Autobricks PKI client is installed, configured, and the required certificate material validates successfully. Without that dependency, the service exposes only Unix domain socket and TCP. The dependency and secure installation profiles are defined in [DEPENDENCIES.md](DEPENDENCIES.md).

TLS and mutual TLS transports support persistent keep-alive connections. A client can send multiple framed requests over one authenticated connection, reusing the established TLS channel instead of performing a new handshake for every JWT operation. Each request carries its own operation credentials and correlation identifier; keep-alive does not reuse or broaden an APIKEY authorization decision.

The authenticated certificate identity is bound to the connection. Its absolute connection deadline is the earlier of the configured maximum connection lifetime and the client certificate's `notAfter` time. The service closes the connection no later than that deadline and never accepts a request over a connection after the certificate expires. It also closes the connection on framing errors, protocol violations, idle timeout, failed certificate-status refresh, inactive client registration, or transport failure. Certificate and OCSP validation must be refreshed according to the configured security interval; a persistent connection cannot remain authorized after required revalidation fails.

Keep-alive uses a sliding idle timeout measured in seconds. The service configuration supplies the default value:

```yaml
timeout: 3600
```

`3600` is an example configuration value, not a protocol constant. Each registered client can have its own keep-alive timeout in the SQLCipher `clients` record. A client-specific value overrides the configuration default; otherwise, the configured `timeout` applies. After each successfully authenticated and processed request, the connection's idle deadline is renewed to `now + effective_timeout`, capped by the absolute connection deadline. Unauthenticated bytes, malformed frames, and rejected requests do not renew it. When the idle deadline is reached, the server closes the connection so the client reconnects and authenticates again.

### Service Registry

Every client service is registered before using JWT operations. Registration records the Autobricks PKI-issued client certificate fingerprint and its URI SAN operation class in the SQLCipher `clients` table and delivers the client certificate to the registered service. The client record must remain active for the certificate to authenticate. Registration also produces two credentials:

| Credential | Allowed operation | Consumer |
| --- | --- | --- |
| Issuance APIKEY | Create an encrypted JWT session | Registered issuance client, such as a Web Service |
| Query APIKEY | Query authorized fields from an active JWT session | Registered query client; Autobricks Policy is one example |

An APIKEY is bound to its registered service and operation class. Possession of one APIKEY does not grant the permissions of the other. Authorization is the intersection of the certificate URI SAN operation, the active `clients` registration operation, and the APIKEY operation. A mismatch is rejected.

### Source Resolver

The Source Resolver supplies token input from one of the configured sources:

- Client-supplied JSON
- A direct database query
- Service-defined data

A caller necessarily knows values that it supplies itself. It does not gain access to additional database-derived fields or to the complete payload constructed inside Autobricks JWT.

### Token Cryptography

Token encryption and complete payload decryption occur only inside Autobricks JWT. Registered client services receive neither JWT cryptographic keys nor a complete decrypted payload.

The cryptographic component returns an encrypted token during issuance. During field query, it decrypts the complete payload only within the JWT Service process and passes only the authorized field projection to the response layer.

### Field Authorization

Field authorization evaluates the registered service, Query APIKEY, token context, and requested field names. The response contains only authorized requested fields. The interface does not provide a complete-payload operation.

### Direct Database Layer

Autobricks JWT directly supports PostgreSQL, MariaDB, MySQL, SQLite, and SQLCipher. Direct JWT database connections are independent of Autobricks Cache Connections and database adapters.

Direct database access handles configured JWT service data, registration data, token source data, and session records.

The SQLCipher `clients` table is the authoritative certificate registration store. It associates a registered service with its client certificate SHA-256 fingerprint, URI SAN operation class, and active registration state. A valid certificate that has no active matching record is not authorized to use JWT operations.

The client record can also define that client's keep-alive timeout in seconds. Absence of the client-specific value selects the service configuration's `timeout` default.

### Cache Adapter

Autobricks JWT uses the public Autobricks Cache interface without JWT-specific changes to the Cache implementation.

Session Cache behavior follows these rules:

- JWT issuance inserts the active session into the Cache.
- Authorized field lookup of an active session extends Retention.
- A missing session Cache record is an invalid session.
- A missing or expired session is not restored from the session database record.
- Database persistence does not make an expired Cache session active again.

Separate Caches can serve user, account, device, or other source records. Their SELECT, MAP, mutation, and Retention configuration is independent of the session Cache.

### TrueLog Writer

Autobricks JWT writes exactly two event categories:

1. Successful JWT issuance
2. Expired or nonexistent session request

An expired session and a nonexistent session use the same service error and TrueLog event category. Normal field queries, client-side decisions, Retention extension, and Cache activity do not create JWT TrueLog events.

TrueLog records exclude APIKEYs, JWT values, complete payloads, decrypted field values, and cryptographic secrets.

After a successful append, the TrueLog Writer validates the returned hostname, service, before/after file names, byte sizes, and checksums and updates the corresponding JWT issuance or invalid-session database record with those receipt fields. These fields are local database evidence for later WORM metadata and checksum-chain verification; they are not written into the TrueLog event and do not create an additional TrueLog event category.

## Operational and Audit Log Separation

Autobricks JWT stores operational service logs and audit-evidence logs separately. They have different purposes, destinations, and retention responsibilities.

| Log class | Destination | Purpose | Content | TrueLog receipt |
| --- | --- | --- | --- | --- |
| Operational service log | Operating server syslog | Diagnose failures and provide local operational visibility for audit events | Assigned `error_code`, `error_name`, timestamp, redacted diagnostic context, and a copy of each `JWT_ISSUED` or `JWT_SESSION_INVALID` event | No |
| Audit-evidence log | Autobricks TrueLog | Preserve evidence of successful JWT issuance and expired-or-nonexistent session requests | Only `JWT_ISSUED` and `JWT_SESSION_INVALID` events defined by `LOGGING.md` | Yes; stored in the corresponding JWT database record |

Every `JWT_ISSUED` and `JWT_SESSION_INVALID` event is written to syslog as well as submitted to TrueLog. The syslog copy provides local operational visibility but is not audit evidence. TrueLog remains the authoritative audit-evidence destination.

TrueLog submission and receipt persistence are enabled only when the Autobricks TrueLog client is installed and configured. Without it, the two audit events remain in syslog only and no TrueLog evidence or receipt exists. A runtime delivery failure after TrueLog has been enabled follows the audit failure and reconciliation rules; it is not treated as an intentional syslog-only profile change.

Other operational syslog entries are not submitted to TrueLog merely because they contain an error code. Syslog entries do not create TrueLog append receipts or audit-receipt database records, and the TrueLog receipt is not added to the syslog copy.

Audit events are not used as a replacement for service diagnostics. A TrueLog delivery or receipt-persistence failure is classified and written to syslog, while a successfully returned TrueLog receipt is stored only with the corresponding local audit record.

The two log paths must use separate writers and failure handling. A failure in one path must not silently redirect its record into the other path.

### Key Store

JWT key data is stored in a SQLCipher-encrypted database. The SQLCipher database key is managed through an HSM. JWT cryptographic keys and the SQLCipher database key are not returned through service interfaces.

This boundary minimizes key exposure but does not treat root access to the JWT Service host as safe. A privileged host attacker may inspect runtime plaintext, obtain material available to the process, or invoke cryptographic operations available to the service.

## Issuance Flow

```mermaid
sequenceDiagram
    participant W as Web Service
    participant J as Autobricks JWT
    participant D as Direct Database
    participant C as Autobricks Cache
    participant T as Autobricks TrueLog

    W->>J: Issue request + Issuance APIKEY
    J->>J: Authenticate registered service and APIKEY
    alt Database source is configured
        J->>D: Execute configured source query
        D-->>J: Source records
    else JSON or service source is configured
        J->>J: Resolve configured source data
    end
    J->>J: Build and encrypt complete payload
    J->>C: Insert active session
    C->>D: Persist session through Cache WRITE Queue
    J->>T: Write successful issuance event
    J-->>W: Encrypted JWT
```

The issuance response never contains the complete plaintext payload or JWT cryptographic keys.

## Field Query Flow

```mermaid
sequenceDiagram
    participant X as Registered Query Client
    participant J as Autobricks JWT
    participant C as Autobricks Cache
    participant T as Autobricks TrueLog

    X->>J: JWT + requested fields + Query APIKEY
    J->>J: Authenticate registered service and APIKEY
    J->>C: Look up active session
    alt Session is missing or expired
        J->>T: Write common invalid-session event
        J-->>X: Common invalid-session error
    else Session is active
        J->>J: Validate and decrypt JWT internally
        J->>J: Authorize and project requested fields
        J->>C: Extend session Retention
        J-->>X: Authorized field values only
    end
```

## Data Trust Boundary

Autobricks JWT treats records returned by a correctly configured source query as input data. It cannot determine whether a valid-looking source record was maliciously inserted, altered, or substituted before query execution.

A compromised user table can therefore produce a cryptographically valid token containing false data. Responsibility for that source compromise remains with the database owner. Autobricks JWT remains responsible for correct APIKEY enforcement, configured query execution, token construction, encryption, field authorization, and session handling.

## Error Disclosure Boundary

The external error model does not distinguish an expired session from a session that never existed. This prevents callers from using the response or TrueLog category to determine prior session existence.

Errors and logs do not expose payloads, decrypted field values, APIKEYs, database credentials, HSM credentials, or cryptographic keys.

Every classified service failure writes its assigned `error_code` and `error_name` to the operating server's syslog, including connection-closing and internal failures. Syslog is for service failure diagnosis and is not audit evidence. It does not create a TrueLog receipt or an additional TrueLog category. Only `JWT_SESSION_INVALID` is an error audit event in TrueLog, and it carries code `8060`.

The authoritative `8000` through `8100` error registry, response envelope, exposure classes, and security mappings are defined in [ERROR.md](ERROR.md).

## Fixed Architecture Decisions

- Public repository artifacts are written in English.
- Complete payload access is internal to Autobricks JWT.
- Service registration is required before JWT operations.
- Autobricks PKI issues the JWT Service server certificate and registered-service client certificates.
- Service registration stores the client certificate fingerprint in the SQLCipher `clients` table.
- Network access requires a valid certificate chain, validity interval, client-authentication purpose, `GOOD` status from the AIA OCSP URL, and an active matching client fingerprint before JWT issuance or query authorization.
- Client certificate URI SAN `urn:autobricks:jwt:read` authorizes only query operations, and `urn:autobricks:jwt:write` authorizes only issuance operations.
- Effective permission is the intersection of the certificate URI SAN, active `clients` registration, and request APIKEY operation class.
- TLS and mutual TLS connections support multiple framed requests so the established secure session can be reused.
- Keep-alive uses the registered client's timeout or the configuration `timeout` default, renews its idle deadline after each valid processed request, and closes the idle connection to require reconnection.
- Idle renewal cannot extend the connection beyond the configured maximum lifetime or the certificate's `notAfter` time. Keep-alive also remains subject to OCSP refresh and active client registration.
- Issuance and Query use separate APIKEY permissions.
- Registered client services cannot obtain the complete decrypted payload.
- Direct database support is independent of Autobricks Cache.
- Autobricks Cache is consumed through its existing public behavior.
- JWT issuance and common invalid-session failure are the only JWT TrueLog event categories.
- SQLCipher protects JWT key data at rest, and an HSM manages the SQLCipher database key.
- Root compromise of the JWT Service host remains outside the protected trust boundary.

## Open Design Decisions

The following implementation details are not fixed by this architecture:

- Wire message framing and operation names
- JWT and JWE algorithm profiles
- APIKEY format, hashing, rotation, revocation, and recovery
- Service-registration authority and administrative workflow
- Field-authorization configuration format
- Database schema and query configuration format beyond the required SQLCipher `clients` registration table
- Session identifier and database record format
- Cache Definition identifiers and field layout
- HSM provider, PKCS #11 profile, and recovery procedure
- Concurrency, request-size, and rate limits
- Keep-alive maximum connection lifetime, request limit, certificate-status refresh interval, and allowed bounds for the default and per-client idle timeout
- Error codes and response schema
