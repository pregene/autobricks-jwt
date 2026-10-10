# Autobricks JWT Error Contract

## Scope

Autobricks JWT uses error codes from `8000` through `8100`, inclusive. Codes outside this range are not JWT Service errors.

The contract separates client-visible errors from internal diagnostic classifications. A failure that occurs before a secure application channel exists may close the connection without returning an error object.

## Error Response

When a response can be returned safely, it uses this logical structure:

```json
{
  "status": "ERROR",
  "error": {
    "code": 8001,
    "name": "INVALID_REQUEST",
    "message": "The request is invalid."
  }
}
```

Rules:

- `code` is the stable numeric identifier.
- `name` is the stable uppercase symbolic identifier.
- `message` is a safe English description and is not intended for programmatic matching.
- Clients must branch on `code`, not on `message`.
- Responses must not include stack traces, SQL, file paths, credentials, JWT contents, decrypted fields, cryptographic details, certificate contents, OCSP response contents, or the existence of a protected record.
- Every classified service failure writes its assigned `error_code` and `error_name` to the operating server's syslog, including failures that close a connection or map to a generic client response.
- Syslog entries may contain a separate safe diagnostic cause but must still follow the secret-redaction rules. They are service diagnostics, not TrueLog audit evidence.

## Exposure Classes

| Class | Behavior |
| --- | --- |
| Public | Return the documented error object to an authenticated client. |
| Generic | Return the documented generic error without disclosing the underlying cause. |
| Close | Terminate the connection; an application error response is not guaranteed. |
| Internal | Do not return this classification directly; map it to a documented generic error. |

## 8000–8009: Request and Protocol

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8000 | `INTERNAL_ERROR` | Generic | The request could not be completed because of an undisclosed service failure. |
| 8001 | `INVALID_REQUEST` | Public | The request structure or value is invalid. |
| 8002 | `UNSUPPORTED_OPERATION` | Public | The requested operation is not supported. |
| 8003 | `UNSUPPORTED_PROTOCOL_VERSION` | Public | The requested protocol version is not supported. |
| 8004 | `REQUEST_TOO_LARGE` | Public | The request or frame exceeds the configured limit. |
| 8005 | `MALFORMED_FRAME` | Close | The transport frame cannot be decoded safely. |
| 8006 | `REQUEST_TIMEOUT` | Public | Request processing exceeded the configured deadline. |
| 8007 | `RATE_LIMITED` | Public | The client exceeded an applicable rate limit. |
| 8008 | `TOO_MANY_REQUESTS` | Public | The connection exceeded its configured in-flight request limit. |
| 8009 | `SERVICE_UNAVAILABLE` | Generic | The service cannot accept the request temporarily. |

## 8010–8029: Certificate and Connection Identity

These failures occur before APIKEY authorization. The service normally closes the TLS or mutual TLS connection without an application response.

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8010 | `CLIENT_CERTIFICATE_REQUIRED` | Close | A required client certificate was not presented. |
| 8011 | `CERTIFICATE_CHAIN_INVALID` | Close | The certificate chain is not trusted or cannot be verified. |
| 8012 | `CERTIFICATE_TIME_INVALID` | Close | The certificate is not yet valid or has expired. |
| 8013 | `CERTIFICATE_PURPOSE_INVALID` | Close | The certificate is not valid for client authentication. |
| 8014 | `CERTIFICATE_AIA_OCSP_MISSING` | Close | The certificate does not contain a usable AIA OCSP URL. |
| 8015 | `OCSP_UNAVAILABLE` | Close | A current OCSP result cannot be obtained. |
| 8016 | `OCSP_RESPONSE_INVALID` | Close | The OCSP response is malformed, stale, mismatched, or cryptographically invalid. |
| 8017 | `CERTIFICATE_REVOKED` | Close | OCSP reports the certificate as revoked. |
| 8018 | `CERTIFICATE_STATUS_UNKNOWN` | Close | OCSP does not report `GOOD`. |
| 8019 | `CERTIFICATE_NOT_REGISTERED` | Close | The certificate fingerprint has no active matching registration. |
| 8020 | `CLIENT_REGISTRATION_INACTIVE` | Close | The matching client registration is inactive. |
| 8021 | `CERTIFICATE_USAGE_INVALID` | Close | The JWT URI SAN is missing, unknown, duplicated, or conflicting. |
| 8022 | `CERTIFICATE_USAGE_MISMATCH` | Close | The certificate URI SAN does not match the registered operation class. |
| 8023 | `CONNECTION_IDENTITY_CHANGED` | Close | A request attempts to use an identity other than the one bound to the connection. |
| 8024 | `CONNECTION_IDLE_TIMEOUT` | Close | The configured sliding idle timeout expired. |
| 8025 | `CONNECTION_LIFETIME_EXCEEDED` | Close | The configured maximum connection lifetime expired. |
| 8026 | `CERTIFICATE_CONNECTION_EXPIRED` | Close | The connection reached the certificate `notAfter` time. |
| 8027 | `CERTIFICATE_REGISTRATION_KEY_INVALID` | Close | The temporary certificate registration key is missing, expired, consumed, mismatched, or invalid. |
| 8028 | `SERVICE_CERTIFICATE_BINDING_MISMATCH` | Close | The certificate fingerprint, `service_id`, `client_id`, APIKEY, or operation URI SAN does not resolve to one service binding. |
| 8029 | `CERTIFICATE_HANDOVER_FAILED` | Internal | The verified pending-to-active certificate transition could not complete atomically. |

## 8030–8039: APIKEY Authorization

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8030 | `APIKEY_AUTHENTICATION_FAILED` | Generic | The required APIKEY is missing, invalid, revoked, or not bound to the authenticated client. |
| 8031 | `APIKEY_OPERATION_FORBIDDEN` | Public | The APIKEY does not permit the requested operation class. |
| 8032 | `OPERATION_CLASS_MISMATCH` | Public | Certificate usage, client registration, and APIKEY operation classes do not agree. |
| 8033–8039 | Reserved | Internal | Reserved for APIKEY authorization errors. |

## 8040–8049: Service Registration

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8040 | `SERVICE_NOT_REGISTERED` | Generic | No active registered service can authorize the request. |
| 8041 | `SERVICE_REGISTRATION_INACTIVE` | Generic | The service registration is inactive. |
| 8042 | `SUBJECT_TYPE_FORBIDDEN` | Public | The service cannot issue for the requested subject type. |
| 8043 | `FIELD_QUERY_FORBIDDEN` | Public | The service cannot query one or more requested fields. |
| 8044 | `SERVICE_CERTIFICATE_PROVISIONING_FAILED` | Internal | Service certificate issuance, download, verification, persistence, delivery, or activation preparation failed. |
| 8045–8049 | Reserved | Internal | Reserved for service-registration errors. |

## 8050–8059: JWT Issuance

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8050 | `JWT_ISSUANCE_FAILED` | Generic | JWT issuance did not complete. |
| 8051 | `INVALID_SUBJECT` | Public | The subject type or identifier is invalid. |
| 8052 | `SOURCE_NOT_CONFIGURED` | Public | The requested token source is not configured for the service. |
| 8053 | `SOURCE_DATA_UNAVAILABLE` | Generic | Required source data could not be obtained. |
| 8054 | `SOURCE_DATA_INVALID` | Generic | Source data cannot produce a valid configured payload. |
| 8055 | `JWT_ENCRYPTION_FAILED` | Internal | Token encryption failed. |
| 8056 | `SESSION_CREATE_FAILED` | Internal | The active session could not be created or persisted. |
| 8057–8059 | Reserved | Internal | Reserved for JWT issuance errors. |

## 8060–8069: JWT Session and Field Query

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8060 | `SESSION_NOT_FOUND_OR_EXPIRED` | Generic | The session does not exist or is no longer active. The two conditions are never distinguished. |
| 8061 | `JWT_INVALID` | Generic | The encrypted JWT is malformed, fails integrity validation, or cannot be processed. |
| 8062 | `JWT_AUDIENCE_INVALID` | Generic | The JWT is not valid for the authenticated registered service. |
| 8063 | `FIELD_LIST_INVALID` | Public | The requested field list is empty, malformed, duplicated, or exceeds configured limits. |
| 8064 | `FIELD_NOT_AUTHORIZED` | Public | At least one requested field is not authorized for the service. |
| 8065 | `FIELD_VALUE_UNAVAILABLE` | Generic | An authorized requested value cannot be returned. |
| 8066 | `SESSION_RETENTION_FAILED` | Internal | The active session idle Retention could not be extended. |
| 8067–8069 | Reserved | Internal | Reserved for session and field-query errors. |

## 8070–8079: TrueLog Audit

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8070 | `AUDIT_WRITE_FAILED` | Internal | The required TrueLog event could not be appended. |
| 8071 | `AUDIT_RECEIPT_INVALID` | Internal | The returned append receipt failed validation. |
| 8072 | `AUDIT_RECEIPT_STORE_FAILED` | Internal | The receipt could not be stored in the corresponding local database record. |
| 8073 | `AUDIT_RECONCILIATION_REQUIRED` | Internal | TrueLog may have committed the event, but local receipt persistence is incomplete. |
| 8074–8079 | Reserved | Internal | Reserved for audit and receipt errors. |

## 8080–8089: Storage and Cryptography

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8080 | `DATABASE_UNAVAILABLE` | Internal | A required direct database is unavailable. |
| 8081 | `DATABASE_OPERATION_FAILED` | Internal | A required database operation failed. |
| 8082 | `CACHE_UNAVAILABLE` | Internal | Autobricks Cache is unavailable. |
| 8083 | `CACHE_OPERATION_FAILED` | Internal | A required Cache operation failed. |
| 8084 | `KEY_STORE_UNAVAILABLE` | Internal | The SQLCipher key store cannot be opened safely. |
| 8085 | `HSM_UNAVAILABLE` | Internal | A required HSM operation is unavailable. |
| 8086 | `KEY_OPERATION_FAILED` | Internal | A cryptographic key operation failed. |
| 8087–8089 | Reserved | Internal | Reserved for storage and cryptographic errors. |

## 8090–8100: Runtime and Reserved Expansion

| Code | Name | Exposure | Meaning |
| ---: | --- | --- | --- |
| 8090 | `CONFIGURATION_INVALID` | Internal | Service configuration is missing or invalid. |
| 8091 | `DEPENDENCY_UNAVAILABLE` | Internal | A required external service is unavailable. |
| 8092 | `SHUTTING_DOWN` | Generic | The service is shutting down and cannot accept the request. |
| 8093 | `CAPACITY_EXCEEDED` | Generic | A configured runtime capacity limit was reached. |
| 8094–8099 | Reserved | Internal | Reserved for runtime errors. |
| 8100 | Reserved | Internal | Reserved as the upper boundary of the JWT error range. |

## Security Mapping Rules

- Map codes `8010`–`8026` to connection closure when the application channel is not authenticated.
- Return `8030` for all missing, unknown, malformed, revoked, or mismatched APIKEY authentication failures; do not reveal which condition occurred.
- Return `8060` for both expired and nonexistent sessions. When audit logging
  is enabled, write the same `JWT_SESSION_INVALID` audit event for both cases.
- Include `error_code: 8060` in every emitted `JWT_SESSION_INVALID` event.
- Map internal codes to `8000` or `8009` when a safe client response is required.
- Never use a database, Cache, HSM, OCSP, or TrueLog error string as a client message.
- Reserved codes must not be emitted until this document assigns them a stable name and meaning.

## Implementation Coverage

- Every non-reserved registry entry must have an explicit construction path in the implementation.
- Every failure path must select one classified root error before response mapping or connection closure.
- Every classified root error must emit its code and name to the operating server's syslog when logging is available.
- Tests must trigger every non-reserved error or its owning boundary condition and verify the returned response, generic mapping, or connection closure defined by its exposure class.
- Tests must also verify that syslog receives the classified code and does not contain prohibited data.

## Change Control

- Existing numeric meanings are immutable after release.
- A new error receives an unused code in the appropriate reserved range.
- Renaming, reusing, or changing the security disclosure behavior of an existing code requires a protocol-version change.
- All implementations, SDKs, tests, and public documentation use this file as the authoritative error registry.
