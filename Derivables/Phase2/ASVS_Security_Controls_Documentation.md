# Kryptos — ASVS 5.0 Security Controls Documentation

**Version**: 1.0
**Date**: 2026-06-14
**Scope**: Vault, Credential, Auth, and cross-cutting security modules

---

## V8.1.1 — Authorization Rules

### Function-Level Access Control

All API endpoints enforce role-based access via `@PreAuthorize` annotations at the controller level, with `@EnableMethodSecurity` enabled globally in `SecurityConfig.java`.

| Endpoint | Method | Required Role | Controller |
|---|---|---|---|
| `/api/vaults` | POST | USER | VaultController |
| `/api/vaults` | GET | USER | VaultController |
| `/api/vaults/{id}` | GET | USER | VaultController |
| `/api/vaults/{id}` | PUT | USER | VaultController |
| `/api/vaults/{id}` | DELETE | USER | VaultController |
| `/api/credentials` | POST | USER | CredentialController |
| `/api/credentials/{id}` | GET | USER | CredentialController |
| `/api/credentials/vault/{vaultId}` | GET | USER | CredentialController |
| `/api/credentials/{id}` | DELETE | USER | CredentialController |
| `/api/auth/login` | POST | Public | AuthController |
| `/api/auth/register` | POST | Public | AuthController |
| `/api/users` | GET | ADMIN | UserController |
| `/api/audit` | GET | ADMIN, AUDITOR | AuditController |

### Data-Level Access Control (IDOR Prevention)

Every data access operation is scoped by the authenticated user's ID (ownerId). The pattern used across all services:

- **Vaults**: `VaultRepository.findByIdAndOwnerId(vaultId, ownerId)` — a user can only access vaults they own.
- **Credentials**: `CredentialRepository.findByIdAndVaultOwnerId(credentialId, ownerId)` — credential access is verified through the parent vault's owner.
- **Trusted Devices**: `TrustedDeviceRepository` methods include `userId` parameter.

If the ownership check fails, a `ForbiddenException` (HTTP 403) is returned and the attempt is logged as an `ACCESS_DENIED_VAULT` or `ACCESS_DENIED_CREDENTIAL` audit event.

### Field-Level Access Control

Response DTOs explicitly omit sensitive fields:

- `CredentialResponse` excludes `encryptedPassword` — only `serviceName`, `username`, `url`, `notes`, and `vaultId` are exposed.
- `UserResponse` excludes the password hash.
- Request DTOs use write-level validation (`@NotBlank`, `@Size`) to restrict acceptable input per field.

---

## V2.1.1 — Input Validation Rules

### Vault Module

| Field | Type | Required | Constraints | Enforced By |
|---|---|---|---|---|
| `name` | String | Yes | `@NotBlank`, min 1, max 100 chars | `CreateVaultRequest`, `UpdateVaultRequest` |
| `description` | String | No | max 500 chars | `CreateVaultRequest`, `UpdateVaultRequest` |

### Credential Module

| Field | Type | Required | Constraints | Enforced By |
|---|---|---|---|---|
| `serviceName` | String | Yes | `@NotBlank`, max 100 chars | `CreateCredentialRequest` |
| `username` | String | Yes | `@NotBlank`, max 100 chars | `CreateCredentialRequest` |
| `password` | String | Yes | `@NotBlank` | `CreateCredentialRequest` |
| `url` | String | No | max 500 chars | `CreateCredentialRequest` |
| `notes` | String | No | max 500 chars | `CreateCredentialRequest` |
| `vaultId` | UUID | Yes | `@NotNull`, must be owned by requester | `CreateCredentialRequest` |

### Auth Module

| Field | Type | Required | Constraints | Enforced By |
|---|---|---|---|---|
| `username` | String | Yes | `@NotBlank` | `RegisterRequest`, `LoginRequest` |
| `email` | String | Yes | `@Email`, `@NotBlank` | `RegisterRequest` |
| `password` | String | Yes | `@NotBlank`, min 12 chars | `RegisterRequest`, `LoginRequest` |

### Validation Enforcement

All validation occurs server-side in the trusted service layer. Bean Validation annotations (`jakarta.validation.constraints`) are applied to DTO records. The `@Valid` annotation on controller method parameters triggers validation before business logic executes. Invalid input returns HTTP 400 with a structured error message via `GlobalExceptionHandler.handleValidation`.

---

## V2.1.3 — Business Logic Limits

### Per-User Limits

| Resource | Limit | Enforcement |
|---|---|---|
| Vaults per user | 50 | `VaultService.create()` checks `countByOwnerId` before saving |
| Login attempts | 5 per minute per user | `AuthService` — 15 min lockout after 5 failures |
| Import requests | 5 per minute per user | `ImportExportRateLimiter` |
| Export requests | 5 per minute per user | `ImportExportRateLimiter` |

### Global Limits

| Resource | Limit | Enforcement |
|---|---|---|
| Upload file size | 5 MiB | `ImportExportController` (HTTP 413) + `FileHandlingService` |
| Import record count | 50,000 records | `CredentialImportExportService` |
| Multipart request size | 10 MB | `application.properties` (`spring.servlet.multipart.max-request-size`) |

### Error Responses for Limits

When a limit is exceeded, the application returns:

- **Vault limit**: HTTP 400 with message "Maximum number of vaults (50) reached"
- **Rate limit**: HTTP 429 (Too Many Requests) via `RateLimitExceededException`
- **File size**: HTTP 413 (Payload Too Large)

---

## V14.2.1 — Sensitive Data Classification

### Data Classification

| Data Item | Classification | Storage | Transport | Notes |
|---|---|---|---|---|
| User password (hash) | Critical | Argon2 hash in DB | HTTPS only, never in URL/query params | Never returned in API responses |
| Credential password | Critical | AES-256-GCM encrypted in DB | HTTPS only, in request body only | Encrypted at rest via `EncryptionService` |
| JWT token | High | Not persisted (stateless) | Authorization header (Bearer) only | Signed with HS256, audience=kryptos |
| JWT secret | Critical | Environment variable | Never transmitted | Min 32 bytes enforced by `JwtService` |
| Encryption secret | Critical | Environment variable | Never transmitted | SHA-256 derived AES key |
| Reset token | High | DB column on User entity | Request body only | UUID, 15 min TTL, cleared after use |
| Audit log hash chain | High | DB (immutable) | Internal only | SHA-256, tamper-evident chain |
| Vault name/description | Medium | Plaintext in DB | HTTPS only, in request body | Sanitized before audit logging |
| Username/email | Medium | Plaintext in DB (unique) | HTTPS only | Email in body only, never in URL |

### Sensitive Data in HTTP Messages

All sensitive data is transmitted exclusively in HTTP request/response bodies or the Authorization header. Specifically:

- Credentials, passwords, and tokens are never placed in URL paths or query parameters.
- Vault IDs appear as path parameters (`/api/vaults/{id}`) which is acceptable as UUIDs are opaque identifiers with no inherent sensitivity.
- Export files are served with `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

---

## V16.3.2 / V16.3.3 — Security Event Logging

### Logged Security Events

| Event | AuditAction Constant | When Triggered |
|---|---|---|
| Login success | `LOGIN` | Successful authentication |
| Login failure | `LOGIN_FAILED` | Invalid credentials |
| Vault access denied | `ACCESS_DENIED_VAULT` | Read/update/delete on a vault not owned by the requester |
| Credential access denied | `ACCESS_DENIED_CREDENTIAL` | Read/create/list/delete on a credential not owned by the requester |
| Vault created | `VAULT_CREATE` | Successful vault creation |
| Vault updated | `VAULT_UPDATE` | Successful vault update |
| Vault deleted | `VAULT_DELETE` | Successful vault deletion |
| Credential created | `CREDENTIAL_CREATE` | Successful credential creation |
| Credential deleted | `CREDENTIAL_DELETE` | Successful credential deletion |
| User registered | `REGISTER` | Successful registration |
| Data export | `EXPORT` | User exports credentials |
| Data import | `IMPORT` | User imports credentials |
| Secure wipe | `SECURE_WIPE` | User wipes all data |

### Audit Log Entry Format

Each audit log entry contains: `action`, `performedBy` (username), `targetResource` (e.g., "vault:uuid"), `details` (sanitized), `timestamp`, `hash` (SHA-256), and `previousHash` (chain link). Details are sanitized to remove control characters before persistence.

---

## V9.2.3 — JWT Audience Validation

JWTs are issued with `aud: "kryptos"` and validated at parse time using `requireAudience("kryptos")` in `JwtService.extractAllClaims()`. Tokens without the correct audience claim are rejected.
