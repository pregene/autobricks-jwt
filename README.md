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

