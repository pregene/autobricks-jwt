# Installation

## Programs

| Program | Role |
| --- | --- |
| `ab-jwtd` | Autobricks JWT server program |
| `ab-jwt-cli` | Management client for JWT client registration, modification, and deletion |

The interactive `ab-jwt-cli` process connects to the local socket owned by
`autobricks-jwt-cli.service`. The client service authenticates the local caller,
validates and filters the management request, and forwards an authorized
request to `ab-jwtd` through the server's separate local management socket.

JWT client registration, modification, and deletion are available only through
this management path. Network JWT service transports do not expose these
operations. Neither management socket is world-accessible; filesystem
permissions and Unix peer credentials restrict both connections.

When `ab-jwt-cli` provisions a client certificate, it downloads the certificate
package into the directory from which `ab-jwt-cli` was invoked.

## Runtime Token Submission

The `ab-jwtd` installation selects whether query and revocation requests must
send the complete encrypted token with `token_id`:

```yaml
require_token_for_query_and_revoke: true
```

| Value | Request behavior | Security and network effect |
| --- | --- | --- |
| `true` | `JWT_QUERY` and `JWT_REVOKE` require both `token_id` and `token`. | Confirms that the caller submitted the exact issued token, with the additional network cost of sending the complete JWE. |
| `false` | `token_id` is required and `token` is optional for `JWT_QUERY` and `JWT_REVOKE`. | Reduces request size, but does not prove that the caller possesses the complete JWE. |

The secure default is `true`. The installer must present this selection and
write the chosen value to the `ab-jwtd` configuration. Changing the value
requires configuration authorization and a service restart; a runtime request
cannot override it.

```text
Require the complete token for JWT query and revocation? [Y/n]
```

`Y` writes `true`; `n` writes `false`. An omitted configuration value is
interpreted as `true` so a missing setting cannot silently enable the weaker
token-optional mode.

When the value is `false` and `token` is omitted, `ab-jwtd` resolves the stored
encrypted token from `token_id` and performs the same JWE, key, IV, claim,
audience, expiration, service-binding, session-state, and field-authorization
checks internally. When a caller supplies `token` in either mode, it must match
the stored token; the service never ignores a mismatched submitted token.

Token-optional mode relies more heavily on the connection credential,
`client_id`, APIKEY, service binding, field allowlist, and source CIDR boundary.
`token_id` is an identifier, not a secret. Deployments that require proof that
the caller possesses the issued JWE must keep the secure default.

The Web Server remains responsible for authenticating its end user and
confirming that the incoming application request is entitled to query or revoke
the selected JWT session. `ab-jwtd` validates the registered service and token
state; it cannot validate the Web Server's user-to-session association. The Web
Server performs this check while treating the JWT as opaque and never receives
the JWT decryption key.

## Services

| Service | Role |
| --- | --- |
| `autobricks-jwt.service` | Autobricks JWT server service |
| `autobricks-jwt-cli.service` | Local management broker that authenticates and filters `ab-jwt-cli` requests before forwarding them to `ab-jwtd` |
