# Autobricks JWT

Autobricks JWT issues encrypted session tokens and provides authorized access to individual token fields without exposing the complete token payload.

## Service Registration

A service must be registered before it can use Autobricks JWT. Registration issues two APIKEYs with separate permissions.

| APIKEY | Permission | Consumers |
| --- | --- | --- |
| Issuance APIKEY | Create encrypted JWT sessions | Web Service |
| Query APIKEY | Query authorized fields from an active JWT session | Web Service, Autobricks Policy |

An APIKEY is valid only for its assigned operation and registered service.

## Token Issuance

- Accepts token source data as client-supplied JSON, database records, or service-defined data.
- Creates the token payload inside Autobricks JWT.
- Encrypts the payload before returning the JWT.
- Prevents the requesting service from reading the complete token payload.
- Authenticates issuance requests with the Issuance APIKEY.
- Persists JWT session records in the configured database.
- Writes a successful issuance event to Autobricks TrueLog.

## Field Query

- Authenticates field-query requests with the Query APIKEY.
- Validates the registered service, token integrity, intended audience, expiration, and session state.
- Decrypts the token only inside Autobricks JWT.
- Authorizes every requested field for the calling service.
- Returns only the authorized field values requested by the caller.
- Never returns the complete decrypted payload to a Web Service or Autobricks Policy.
- Extends session retention when an authorized query accesses an active session.

## Session Errors

- Returns the same error for an expired session and a nonexistent session.
- Does not reveal whether an invalid session previously existed.
- Writes the common expired-or-nonexistent session error to Autobricks TrueLog.

## Cache and Database

- Uses [Autobricks Cache](https://github.com/pregene/autobricks-cache) for MAP-based in-memory session lookup and configurable retention.
- Applies Cache mutations before asynchronous database persistence through the Connection-owned WRITE Queue.
- Provides configurable Cache Definitions for each deployment.
- Supports independent Caches for optional source data such as users, accounts, and devices.
- Keeps source-data Cache loading and retention separate from JWT session retention.

## Service Interfaces

The same registration, authentication, token, authorization, session, and Cache functions are available through:

- Unix domain socket
- TCP
- TLS
- Mutual TLS

## Related Service Responsibilities

| Service | Responsibility |
| --- | --- |
| Autobricks JWT | Service registration, APIKEY authorization, encrypted JWT issuance, token validation, payload decryption, field authorization, and session handling |
| [Autobricks PKI](https://github.com/pregene/autobricks-pki) | Certificates and trust material for TLS and mutual TLS service connections |
| Autobricks Policy | JWT field queries and policy evaluation without access to the complete decrypted payload |
| [Autobricks Cache](https://github.com/pregene/autobricks-cache) | In-memory lookup, mutation, database persistence, and retention |
| [Autobricks TrueLog](https://github.com/pregene/autobricks-log) | Durable storage for JWT issuance and invalid-session events |

## True Log Events

Autobricks JWT writes exactly two event categories to Autobricks TrueLog:

1. Successful JWT issuance
2. Expired or nonexistent session request

Successful field queries, policy evaluation, session retention extension, and Cache activity do not create JWT TrueLog events.

## Security Boundaries

- Token payload encryption and decryption occur only inside Autobricks JWT.
- Complete payload decryption exists only as an internal JWT Service operation.
- Web Services and Autobricks Policy cannot obtain a complete decrypted payload.
- Web Services and Autobricks Policy do not receive decryption keys.
- Issuance and Query APIKEYs have separate permissions.
- Audit records do not contain APIKEYs, JWTs, complete payloads, decrypted field values, or cryptographic secrets.
- Logs and error details do not expose protected token content.

## License

Autobricks JWT is governed by the terms in [LICENSE](LICENSE).
