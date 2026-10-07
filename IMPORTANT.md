# Important Security Boundaries

## Why JWT Keys Do Not Belong in a Web Service

A Web Service that directly manages JWT encryption and decryption keys becomes both an application endpoint and a cryptographic trust boundary. A compromise of that service can expose the keys through source code, configuration, environment variables, deployment artifacts, process memory, logs, crash data, or unauthorized runtime operations. The same compromise can then permit bulk token decryption or unauthorized token creation.

Moving keys to a general-purpose secret manager, including an open-source service, improves storage and distribution but does not eliminate this risk. The Web Service still needs an authorized path to retrieve a key or request a cryptographic operation. An attacker who controls the Web Service process, its credentials, or a privileged host account can attempt to use that same path. OWASP therefore treats storage, distribution, memory lifetime, rotation, revocation, and compromise response as separate parts of secrets management rather than assuming that a secret store makes runtime use safe. [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

Cryptographic protection remains dependent on the protection of its keys. NIST key-management guidance covers key generation, storage, use, cryptoperiods, compromise handling, and destruction as lifecycle responsibilities. [NIST Key Management Guidelines](https://csrc.nist.gov/projects/key-management/key-management-guidelines)

## Autobricks JWT Isolation

Autobricks JWT removes JWT encryption and decryption keys from Web Services and Autobricks Policy.

- Web Services hold an Issuance APIKEY and a Query APIKEY, not JWT cryptographic keys.
- Autobricks Policy holds a Query APIKEY, not JWT cryptographic keys.
- Token encryption and complete payload decryption occur only inside Autobricks JWT.
- Web Services and Autobricks Policy cannot request or receive a complete decrypted payload.
- A Query APIKEY returns only fields authorized for the registered service.
- Issuance and Query APIKEYs have separate permissions, which limits the operations available after one credential is compromised.
- TLS and mutual TLS protect supported network service connections; Unix domain sockets provide a local service boundary.
- JWT issuance and invalid-session requests produce the two defined Autobricks TrueLog event categories without recording keys, tokens, payloads, or decrypted field values.

Encrypted JWT payloads use the confidentiality boundary defined by JSON Web Encryption. JWE defines content encryption and key-management modes; it does not remove the need to protect the decryption keys. [RFC 7516: JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516.html)

## Key Storage

JWT key data is stored in a SQLCipher-encrypted database. SQLCipher encrypts database pages and journal data at rest, authenticates encrypted pages, and supports application-supplied raw key material. [SQLCipher security design](https://www.zetetic.net/sqlcipher/design/)

The SQLCipher database key is managed through an HSM. HSM-backed key management reduces exposure of the database key in files, configuration, and ordinary application storage. PKCS #11 distinguishes sensitive and non-extractable key attributes, but the effective protection depends on HSM configuration and the operations permitted to authenticated callers. [PKCS #11 Specification 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)

SQLCipher does not permanently store its own database key. The integrating service remains responsible for supplying and protecting that key. SQLCipher explicitly notes that protection strength is bounded by where and how key material is held and that hardware-backed storage still depends on configured access controls. [SQLCipher database key material guidance](https://www.zetetic.net/sqlcipher/database-key-material/)

## Security Impact Reduction

| Compromise | Direct key management in a Web Service | Autobricks JWT boundary |
| --- | --- | --- |
| Web Service process or host | JWT keys and complete token payloads may become available; the attacker may decrypt or create tokens directly. | JWT keys and complete decrypted payloads remain outside the Web Service. Stolen APIKEYs still permit operations within their assigned permissions. |
| Autobricks Policy process or host | A shared JWT key can expose every token available to the Policy service. | The Policy service can request only authorized fields with its Query APIKEY and cannot obtain the complete payload or JWT keys. |
| Source repository, image, or deployment artifact | Embedded keys can expose every environment that reuses them. | JWT keys are not distributed with Web Service or Policy artifacts. |
| Database file theft | Plaintext key records or an unencrypted database can expose stored key material. | SQLCipher protects JWT key data at rest; opening the database still requires the HSM-managed SQLCipher key. |
| One APIKEY | A shared unrestricted credential can expose issuance and lookup together. | Issuance and Query permissions are separated. Compromise remains effective within the stolen APIKEY's scope. |
| JWT Service process or root account | Not applicable when the Web Service owns the keys. | This is a high-impact compromise. A privileged attacker may inspect runtime plaintext, invoke authorized cryptographic operations, or obtain key material available to the service. |

The architecture reduces the number of systems that can access JWT keys, removes complete-payload access from Web Services and Autobricks Policy, and limits credential permissions. It does not make compromise impossible.

## Source Data Trust Boundary

Autobricks JWT can create a token from records returned by a configured user database or another configured data source. It validates and protects the token created from those records, but it cannot determine whether an otherwise valid source record was maliciously inserted, altered, or substituted before the query result reached the JWT Service.

- The owner of the user database is responsible for database access control, record integrity, change authorization, backup security, and compromise detection.
- A compromised user table can cause Autobricks JWT to issue a cryptographically valid token containing false or unauthorized source data.
- Token encryption does not prove that the source database record was correct; it protects the payload created from that record.
- A successful issuance event in Autobricks TrueLog proves that Autobricks JWT performed an issuance operation. It does not prove that the source record was legitimate.
- Autobricks JWT is not responsible for an incorrect issuance caused solely by compromised or falsified source records returned through a correctly configured database query.
- Autobricks JWT remains responsible for enforcing service registration, APIKEY permissions, configured field authorization, token construction, encryption, session handling, and its own database-query behavior.

## Residual Risks

- A compromised Web Service can misuse its Issuance APIKEY to issue tokens within that registered service's permission.
- A compromised Web Service or Policy service can misuse its Query APIKEY to retrieve fields authorized for that registered service.
- A compromised source database can provide false records that result in cryptographically valid but incorrectly issued tokens.
- Information already supplied by or returned to a compromised client is not protected from that client.
- A compromised JWT Service can access complete payloads while processing requests.
- A root user on the JWT Service host can inspect the running system and may obtain plaintext or key material available during runtime.
- An HSM reduces key extraction risk but does not prevent an authorized compromised process from requesting permitted HSM operations.
- SQLCipher protects database files at rest; it does not protect values after the JWT Service has opened and decrypted them for processing.
- APIKEY theft, HSM credential theft, incorrect field authorization, excessive service permissions, insecure transport configuration, and vulnerable host software remain security risks.
- Centralizing cryptographic operations makes the JWT Service a high-value target that requires host hardening, least privilege, credential rotation, monitoring, and tested compromise recovery.

## Security Claim

Autobricks JWT minimizes JWT key exposure and reduces the impact of a Web Service or Policy service compromise. It does not guarantee that keys, tokens, or plaintext remain protected after compromise of the JWT Service host, its root account, the HSM authorization path, or another component inside the JWT Service trust boundary.
