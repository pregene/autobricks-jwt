# Autobricks JWT Process Documentation

Each lifecycle process is defined in one document. Process documents use the same structure so that inputs, authorization, state changes, errors, logging, and security boundaries remain independently reviewable.

| Order | Process | Document |
| ---: | --- | --- |
| 1 | JWT client registration | [JWT Client Registration](01-jwt-client-registration.md) |
| 2 | Service registration | [Service Registration](02-service-registration.md) |
| 3 | Service JSON Web Token issuance | [Service JSON Web Token Issuance](03-service-json-web-token-issuance.md) |
| 4 | Service JSON Web Token query | [Service JSON Web Token Query](04-service-json-web-token-query.md) |
| 5 | Service JSON Web Token revocation | [Service JSON Web Token Revocation](05-service-json-web-token-revocation.md) |
| 6 | Service deletion | [Service Deletion](06-service-deletion.md) |
| 7 | JWT client deletion | [JWT Client Deletion](07-jwt-client-deletion.md) |
| 8 | Operational log query | [Operational Log Query](08-operational-log-query.md) |
| 9 | Audit log query | [Audit Log Query](09-audit-log-query.md) |
| 10 | Runtime operation definitions | [Operation Definitions](10-operation-definitions.md) |

## Document Structure

Every process document contains these sections:

1. Scope
2. Preconditions
3. Request
4. Authentication and authorization
5. Validation
6. Processing
7. Response
8. State changes
9. Errors
10. Logging and audit
11. Security boundaries
12. Verification

Shared architecture, operation, error, logging, dependency, and database rules
remain authoritative in the repository root documents. Runtime operation names,
permission classes, and common examples are defined in
[Operation Definitions](10-operation-definitions.md). A process document narrows those rules for
one lifecycle operation and does not redefine them globally.

JWT and JOSE standards are listed in [JWT Standards References](../REFERENCES.md).
