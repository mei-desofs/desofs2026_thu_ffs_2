# Authorization Documentation (ASVS V8.1.1 & V8.1.2)

This document maps the function-level, data-level, and field-level access control rules enforced by Kryptos. It serves as the formal authorization documentation required by ASVS V8.1.1 and V8.1.2.

## 1. Function-Level and Data-Specific Access (V8.1.1)

Access to API endpoints is controlled at the function level using Spring Security's `@PreAuthorize` annotations. Data-specific access (ownership checks) is enforced within the service layer to ensure users can only access their own data.

### 1.1 Authentication & Registration (`AuthController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/auth/register` | `POST` | *None* (Public) | Checks for duplicate username/email. |
| `/api/auth/login` | `POST` | *None* (Public) | Account lockout rules apply. |
| `/api/auth/verify-2fa` | `POST` | *None* (Public) | Validates 2FA code. |
| `/api/auth/2fa/enable` | `POST` | *Authenticated* | Requires recent authentication (Step-up). |
| `/api/auth/2fa/disable`| `POST` | *Authenticated* | Requires recent authentication (Step-up). |
| `/api/auth/reset-password` | `POST` | *None* (Public) | Rate-limited. |
| `/api/auth/reset-password/confirm` | `POST` | *None* (Public) | Validates reset token. |
| `/api/auth/logout` | `POST` | *Authenticated* | Invalidates JWT token. |

### 1.2 User Management (`UserController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/users` | `GET` | `ADMIN` | Returns all users. |
| `/api/users/{id}` | `GET` | `ADMIN` or `USER` | `USER` can only view their own profile. |
| `/api/users/{id}` | `PUT` | `ADMIN` or `USER` | `USER` can only update their own profile. Requires recent authentication (Step-up). |
| `/api/users/{id}` | `DELETE`| `ADMIN` | Soft deletes user and invalidates sessions. |
| `/api/users/{id}/role` | `PUT` | `ADMIN` | Updates user role. |
| `/api/users/{id}/activate` | `PUT` | `ADMIN` | Reactivates user. |

### 1.3 Credential Management (`CredentialController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/credentials` | `POST` | `USER` | Creates credential linked to the caller's ID. |
| `/api/credentials` | `GET` | `USER` | Returns only credentials owned by the caller. |
| `/api/credentials/{id}`| `GET` | `USER` | Must be owned by the caller. |
| `/api/credentials/{id}`| `PUT` | `USER` | Must be owned by the caller. |
| `/api/credentials/{id}`| `DELETE` | `USER` | Must be owned by the caller. |

### 1.4 Vault Management (`VaultController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/vaults` | `POST` | `USER` | Creates vault linked to the caller's ID. |
| `/api/vaults` | `GET` | `USER` | Returns only vaults owned by the caller. |
| `/api/vaults/{id}` | `GET` | `USER` | Must be owned by the caller. |
| `/api/vaults/{id}` | `PUT` | `USER` | Must be owned by the caller. |
| `/api/vaults/{id}` | `DELETE` | `USER` | Must be owned by the caller. |

### 1.5 Trusted Devices (`TrustedDeviceController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/trusted-devices` | `POST` | `USER` | Registers device to the caller's account. |
| `/api/trusted-devices` | `GET` | `USER` | Returns devices owned by the caller. |
| `/api/trusted-devices/{id}` | `DELETE`| `USER` | Must be owned by the caller. |
| `/api/trusted-devices/verify` | `POST` | `USER` | Verifies device for the caller. |
| `/api/trusted-devices/report` | `POST` | `USER` | Reports device for the caller. |

### 1.6 File Handling / Import & Export (`ImportExportController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/files/export` | `GET` | `USER` | Exports only the caller's credentials. Rate-limited. |
| `/api/files/import` | `POST` | `USER` | Imports credentials to the caller's account. Rate-limited. |

### 1.7 Audit Logs (`AuditController`)
| Endpoint | Method | Required Role | Ownership / Data Rules |
|----------|--------|---------------|------------------------|
| `/api/audit` | `GET` | `ADMIN` or `AUDITOR` | Returns all audit logs. |
| `/api/audit/user/{username}` | `GET` | `ADMIN` or `AUDITOR` | Returns logs for a specific user. |
| `/api/audit/log` | `POST` | `USER` or `ADMIN` | Client-side log ingestion. |

---

## 2. Field-Level Access Restrictions (V8.1.2)

Field-level access is implemented by strictly separating domain entities from response DTOs. Sensitive fields are never serialized into JSON responses. Read and write restrictions are implicitly enforced by the attributes mapped in DTOs.

### 2.1 User Entity (Read Restrictions)
The `UserResponse` DTO exposes only non-sensitive fields.

**Allowed for Read (`UserResponse`):**
- `id`
- `username`
- `email`
- `role`

**Restricted (Never exposed to clients):**
- `password` (BCrypt hash)
- `twoFaEnabled`
- `twoFaCode`
- `twoFaCodeExpiresAt`
- `resetToken`
- `resetTokenExpiresAt`
- `sessionTokenValidAfter`
- `accountLockedUntilAdmin`

### 2.2 User Entity (Write Restrictions)
The `UpdateUserRequest` restricts which fields a user can modify.
- Users can only update `email` and `username`.
- Role modifications are restricted to `ADMIN` via a dedicated endpoint (`/api/users/{id}/role`).
- Password updates are handled exclusively via the authentication flow.

### 2.3 Credential Entity (Read Restrictions)
The `CredentialResponse` DTO exposes metadata but hides the raw encrypted password payload by default unless explicitly requested and decrypted in memory (on client side).

**Allowed for Read (`CredentialResponse`):**
- `id`
- `title`
- `username`
- `url`
- `notes`
- `createdAt`
- `updatedAt`
- `vaultId`

**Restricted (Never exposed in list views):**
- `encryptedPassword` (Base64 payload) -> *Only accessible when explicitly fetching the single credential for decryption.*

### 2.4 Credential Entity (Write Restrictions)
The `CreateCredentialRequest` and `UpdateCredentialRequest` strictly bind allowable inputs.
- Read-only fields like `createdAt`, `updatedAt`, and `owner` (user association) cannot be modified by the client. The backend forcibly associates the credential with the currently authenticated user context.

### 2.5 Vault Entity (Read/Write Restrictions)
- **Read (`VaultResponse`):** Exposes `id`, `name`, `description`, and `ownerId`.
- **Write:** Clients can only provide `name` and `description`. The `ownerId` is implicitly bound to the caller.

### 2.6 Trusted Device Entity (Read/Write Restrictions)
- **Read (`TrustedDeviceResponse`):** Exposes `id`, `deviceName`, `deviceFingerprint`, `ipAddress`, `lastUsedAt`, and `active`. User relationships are not directly exposed.
- **Write:** Only `deviceName` and `deviceFingerprint` are accepted during registration.

### 2.7 Audit Log Entity (Read/Write Restrictions)
- **Read:** Admins and Auditors can view the full log including `action`, `performedBy`, `targetResource`, `details`, `timestamp`, `hash`, and `previousHash`.
- **Write:** Completely restricted. Audit logs are immutable and can only be appended sequentially by the backend service. Modifying or deleting logs is blocked at the entity (`@PreUpdate`, `@PreRemove`) and repository levels.

---

## 3. Adaptive Security Controls (V8.2.4)

Adaptive security controls evaluate a consumer's environmental and contextual attributes to make dynamic authentication and authorization decisions both at login and during an active session.

### 3.1 Context-Aware Authentication (Trusted Devices)
- **Login Flow:** The `/api/auth/login` endpoint analyzes the `X-Device-Fingerprint` header.
- **2FA Bypass:** If a user has 2FA enabled, but the authentication request originates from a registered and active "Trusted Device" associated with that user, the 2FA challenge is bypassed. For unknown devices, the 2FA challenge is strictly enforced.

### 3.2 Continuous Session Context Binding
- **JWT Context Embedding:** Upon issuance, JWTs embed the user's current IP Address (extracted safely considering proxies via `X-Forwarded-For`) and `User-Agent`.
- **Request Validation:** The `JwtAuthFilter` checks every incoming API request. If the request's IP Address or User-Agent do not match the claims embedded in the token, the session is rejected (protecting against session hijacking and token theft across devices).

---

## 4. Immediate Application of Authorization Decisions (V8.3.2)

To verify that changes to values on which authorization decisions are made are applied immediately without relying on token expiration delays (mitigating the stateless nature of JWTs):

- **Instant Revocation:** The system relies on the `sessionTokenValidAfter` timestamp within the `User` entity. The `JwtAuthFilter` strictly refuses any token issued prior to this timestamp.
- **Role Changes:** When an administrator alters a user's role (`UserService.updateUserRole`), the user's `sessionTokenValidAfter` is immediately set to `LocalDateTime.now()`. All active sessions for that user instantly become invalid.
- **Security Events:** Similar instant invalidations occur when an account is locked, deleted/deactivated, or when a password is successfully reset.
