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

## Services

| Service | Role |
| --- | --- |
| `autobricks-jwt.service` | Autobricks JWT server service |
| `autobricks-jwt-cli.service` | Local management broker that authenticates and filters `ab-jwt-cli` requests before forwarding them to `ab-jwtd` |

Installation and configuration procedures are defined separately as the
packaging and deployment design is completed.
