# Autobricks JWT

Autobricks JWT is a security service for issuing encrypted session tokens and providing controlled access to individual token fields without exposing the complete token payload.

## Core Functions

- Issue encrypted JWT session tokens whose payload cannot be read by the requesting client.
- Build token payloads from client-supplied JSON, database records, or service-defined data sources.
- Keep payload encryption and decryption inside the JWT service.
- Allow an authorized policy service to request only the token fields required for a policy decision.
- Prevent clients and policy services from receiving the complete decrypted payload.
- Apply service and field-level authorization to token-field requests.
- Validate token integrity, intended audience, expiration, and session state before returning a field value.
- Revoke sessions and reject expired, invalid, or unauthorized tokens.

## Session Storage and Cache

JWT sessions can be persisted in a database and managed through Autobricks Cache. Cache definitions remain configurable so each deployment can select the required database and retention behavior.

Autobricks Cache provides MAP-based in-memory lookup, immediate in-memory mutation, asynchronous database persistence through a connection-owned write queue, and configurable retention. These capabilities allow the JWT service to use cached records for low-latency session validation and to extend retention when an authorized lookup accesses an active session.

Additional caches can be configured independently for data such as users, accounts, devices, or other token source records. Their loading, lookup, mutation, and retention policies are separate from the session cache.

## Related Service Responsibilities

| Service | Responsibility |
| --- | --- |
| Autobricks JWT | Owns encrypted token issuance, token validation, payload decryption, field-level authorization, session handling, and the JWT service interfaces. |
| [Autobricks PKI](https://github.com/pregene/autobricks-pki) | Provides the certificates and trust material used by TLS and mutual TLS deployments. It does not issue JWTs or access token payloads. |
| Autobricks Policy | Sends a token to Autobricks JWT, requests only the fields required for a policy decision, and performs the policy evaluation. It does not decrypt the token or receive the complete payload. |
| [Autobricks Cache](https://github.com/pregene/autobricks-cache) | Provides configurable MAP-based lookup, mutation, database persistence, and retention for JWT sessions and optional source-data caches. Cache behavior is selected by JWT service configuration. |
| [Autobricks TrueLog](https://github.com/pregene/autobricks-log) | Provides True Log storage for the two JWT audit events defined below. It does not receive token payloads or decrypted field values. |

## True Log Events

Autobricks JWT writes only the following two event categories to Autobricks TrueLog:

1. A JWT was issued successfully.
2. A request used a session that is expired or does not exist.

An expired session and a nonexistent session produce the same service error and the same True Log event category. The response and audit record do not reveal whether the session previously existed.

Successful field lookup, policy evaluation, session retention extension, and Cache activity do not create JWT True Log events. Audit records never contain the JWT, the complete payload, decrypted field values, or cryptographic secrets.

## Service Interfaces

The service provides the same JWT operations through configurable transports:

- Unix domain socket
- TCP
- TLS
- Mutual TLS

Transport configuration does not change the token, authorization, field-access, session, or cache behavior.

## Security Boundary

- Token payloads are encrypted before they leave the JWT service.
- Decryption keys are owned by the JWT service and are never returned through a service interface.
- Complete decrypted payloads are not returned to clients or policy services.
- Field requests return only explicitly authorized values.
- Decrypted payloads and cryptographic secrets are excluded from logs, error details, and audit messages.
- Cache and database records do not provide an interface for retrieving a complete plaintext payload.

## License

Autobricks JWT is governed by the terms in [LICENSE](LICENSE).
