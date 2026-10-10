# Autobricks JWT Service Dependencies

## Purpose

Autobricks JWT can run with reduced capabilities when optional Autobricks security services are unavailable. The active interfaces and audit guarantees depend on which client packages are installed and configured on the JWT Service host.

For a security-focused deployment, install and configure the Autobricks PKI client and Autobricks TrueLog client before installing Autobricks JWT.

## Required Dependency: Autobricks Cache

The Autobricks Cache shared library is a mandatory runtime dependency. Autobricks JWT requires `libautobricks_cache.so` for session lookup, mutation, persistence, and Retention behavior. There is no Cache-free or reduced-cache operating mode.

The Autobricks JWT installation package installs the currently validated Autobricks Cache shared-library version by default. This provides a compatible library during a normal JWT installation without requiring a separate Cache installation step.

For a separate installation or update, download and install the latest compatible release from the official [Autobricks Cache repository](https://github.com/pregene/autobricks-cache). Verify the release checksum and platform architecture before installation.

Required behavior:

- Verify that the shared library is present, loadable, and exposes the required ABI before starting Autobricks JWT.
- Refuse service startup if the library is missing, incompatible, or fails initialization.
- Do not silently replace a packaged compatible version with an unverified local file.
- Record the loaded Autobricks Cache version in startup syslog without logging Cache data or database credentials.
- Validate compatibility before upgrading the shared library independently of Autobricks JWT.

## Capability Matrix

The matrix below assumes that the required Autobricks Cache shared library is installed and valid.

| Autobricks PKI client | Autobricks TrueLog client | Available transports | Audit behavior |
| --- | --- | --- | --- |
| Installed and configured | Installed and configured | Unix domain socket, TCP, TLS, and mutual TLS | Audit events are written to syslog and TrueLog; TrueLog receipts are stored in the JWT database. |
| Installed and configured | Not installed or not configured | Unix domain socket, TCP, TLS, and mutual TLS | Audit events are written only to syslog. No TrueLog evidence or receipt is available. |
| Not installed or not configured | Installed and configured | Unix domain socket and TCP only | Audit events are written to syslog and TrueLog; TrueLog receipts are stored in the JWT database. |
| Not installed or not configured | Not installed or not configured | Unix domain socket and TCP only | Audit events are written only to syslog. No TrueLog evidence or receipt is available. |

An installed package is considered available only after its required configuration and connectivity checks succeed.

## Autobricks PKI Client

The Autobricks PKI client provides the certificate operations required for TLS and mutual TLS service identities.

When it is installed and configured, Autobricks JWT can:

- Install and use its server certificate, private key, and trust chain.
- Issue and deliver separate registered-client certificates for JWT read and write operations.
- Verify certificate chains, validity, client-authentication purpose, AIA OCSP status, registered fingerprints, and JWT URI SAN usage.
- Expose TLS and mutual TLS interfaces.

When it is absent or not configured:

- TLS and mutual TLS interfaces are disabled.
- Certificate provisioning, fingerprint authentication, AIA OCSP validation, and URI SAN authorization are unavailable.
- Only the Unix domain socket and TCP interfaces are available.
- APIKEY and application authorization rules still apply to supported interfaces.

Plain TCP does not provide transport encryption or certificate identity. Restrict it to a separately protected trusted network, or disable it when the deployment requires cryptographic client identity and confidentiality.

Project and packages: [Autobricks PKI](https://github.com/pregene/autobricks-pki).

## Autobricks TrueLog Client

The Autobricks TrueLog client provides durable WORM audit evidence and append receipts.

When it is installed and configured, Autobricks JWT:

- Writes JWT audit events to syslog and Autobricks TrueLog, including privileged
  complete-token inspection.
- Validates the returned append receipt.
- Stores the receipt in the corresponding local JWT database record.

When it is absent or not configured:

- JWT audit events are written to syslog only.
- No event is stored as TrueLog audit evidence.
- No TrueLog append receipt is created or stored in the JWT database.
- Ordinary service failures continue to use syslog.

Syslog records are operational records and are not a replacement for TrueLog audit evidence.

Project and packages: [Autobricks TrueLog](https://github.com/pregene/autobricks-log).

## Recommended Secure Installation Order

Use this order for a deployment that requires encrypted authenticated transport and durable audit evidence:

1. Install and configure the Autobricks PKI client.
2. Verify PKI server connectivity and certificate operations.
3. Install and configure the Autobricks TrueLog client.
4. Verify an mTLS TrueLog write and receipt from the JWT Service host.
5. Install Autobricks JWT and its packaged Autobricks Cache shared library.
6. Verify the Autobricks Cache library version and ABI.
7. Provision the JWT server certificate and the separate read/write client certificates.
8. Start Autobricks JWT and verify Cache initialization, enabled transports, and the audit destination.

Installing only the package files is insufficient. Each client must complete its enrollment or setup and pass its connectivity check before Autobricks JWT treats the capability as available.

## Startup Capability Detection

At startup, Autobricks JWT determines the active capability set and records it in syslog without exposing credentials or certificate contents.

Required behavior:

- Refuse startup when the required Autobricks Cache shared library is absent, incompatible, or cannot initialize.
- Do not advertise or bind TLS or mutual TLS when the PKI client configuration or required certificate material is unavailable.
- Do not claim TrueLog audit completion when the TrueLog client is unavailable.
- Continue writing operational errors and audit-event copies to syslog.
- Make reduced capability explicit in startup status and health information.
- Do not silently enable a newly installed dependency without completing configuration validation and applying the service's reload or restart procedure.

## Security Profiles

| Profile | Requirements | Intended use |
| --- | --- | --- |
| Secure | Required Cache library plus PKI client and TrueLog client installed, configured, and verified before JWT installation | Production deployments requiring mTLS identity and durable audit evidence |
| Transport-reduced | Required Cache library installed; PKI client unavailable | Controlled environments using only Unix domain socket or protected TCP |
| Audit-reduced | Required Cache library installed; TrueLog client unavailable | Environments that accept syslog-only records without WORM audit evidence |

The reduced profiles are explicit operational choices. They must not be described as providing the certificate authentication or immutable audit guarantees of the Secure profile.
