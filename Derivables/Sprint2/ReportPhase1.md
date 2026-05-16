# Sprint 2 — Phase 1 Report

## 1. CI/CD Pipeline

The pipeline defined in `.github/workflows/ci.yml` runs on every push and pull request to the `main` branch, using **GitHub Actions** with **Ubuntu latest** runners. It is composed of four jobs:

### Job 1: Build & Test (`build-and-test`)
- Spins up a **PostgreSQL 16** service container (database `kryptos_test`, user `kryptos`).
- Checks out the repository and sets up **Java 21 (Temurin)** with Maven cache.
- Runs `mvn verify`, which compiles the project, runs all unit tests, and packages the application.
- Environment variables (`DB_URL`, `DB_USERNAME`, `DB_PASSWORD`, `JWT_SECRET`, `JWT_EXPIRATION`, `ENCRYPTION_SECRET`) are injected for integration tests.

### Job 2: SAST — SpotBugs + Find Security Bugs (`sast`)
- Depends on `build-and-test`.
- Runs `mvn compile spotbugs:check` with the **Find Security Bugs** plugin.
- Uploads the SpotBugs XML report as a build artifact. The build is not failed on SpotBugs findings (`continue-on-error: true`).

### Job 3: SCA — OWASP Dependency-Check (`sca`)
- Depends on `build-and-test`.
- Runs `mvn dependency-check:check` to scan project dependencies for known vulnerabilities.
- Configured with `failBuildOnCVSS >= 9` on pom. Uploads HTML/JSON/XML reports as artifacts.
- Uses `NVD_API_KEY` for vulnerability data from the NVD. Also set to `continue-on-error: true`.

### Job 4: DAST — OWASP ZAP Baseline Scan (`dast`)
- Depends on `build-and-test`.
- Starts the full application stack via `docker compose up -d --build` using the project's `docker-compose.yml`.
- Waits up to 5 minutes for the backend to become responsive on port 8080.
- Runs **OWASP ZAP Baseline Scan** against `http://localhost:8080` with alpha rules, AJAX spider, and a custom rules file (`.zap/rules.tsv`). Alerts are collected as artifacts but do not fail the build.
- Collects application logs on failure and tears down the stack (`docker compose down -v`).

## 2. Domain Functionality

The Kryptos backend follows **Domain-Driven Design (DDD)** with four main aggregates, a secure authentication layer, audit logging, and file handling for import/export.

### Aggregates & Core Domain

| Aggregate          | Entity          | Key Fields                                                               | Purpose                                           |
|--------------------|-----------------|--------------------------------------------------------------------------|---------------------------------------------------|
| **User**           | `User`          | id, username, email, password, role, active                              | Account management with RBAC                      |
| **Vault**          | `Vault`         | id, name, description, owner                           | Logical grouping of credentials per user          |
| **Credential**     | `Credential`    | id, serviceName, username, encryptedPassword (AES-GCM), url, notes, vault | Secure credential storage with encryption at rest |
| **Trusted Device** | `TrustedDevice` | id, deviceName, deviceFingerprint, registeredAt, active, user            | Device registration for access control            |

### Services & Controllers

| Bounded Context    | Service                                                                             | Controller                | Endpoints                                                                                                                                 | PreAuthorize                                       |
|--------------------|-------------------------------------------------------------------------------------|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| **Auth**           | `AuthService` — register/login with rate limiting (5 attempts → 15 min lockout)     | `AuthController`          | `POST /api/auth/register`<br>`POST /api/auth/login`                                                                                       | Public                                             |
| **User**           | `UserService` — CRUD, role update, activate/deactivate                              | `UserController`          | `GET /api/users`<br>`GET /api/users/{id}`<br>`DELETE /api/users/{id}`<br>`PATCH /api/users/{id}/role`<br>`PATCH /api/users/{id}/activate` | `GET /{id}`: ADMIN or USER (self)<br>others: ADMIN |
| **Vault**          | `VaultService` — CRUD with ownership validation                                     | `VaultController`         | `POST /api/vaults`<br>`GET /api/vaults`<br>`GET /api/vaults/{id}`<br>`DELETE /api/vaults/{id}`                                            | USER                                               |
| **Credential**     | `CredentialService` — CRUD with vault ownership checks, password encryption         | `CredentialController`    | `POST /api/credentials`<br>`GET /api/credentials/vault/{vaultId}`<br>`GET /api/credentials/{id}`<br>`DELETE /api/credentials/{id}`        | USER                                               |
| **Trusted Device** | `TrustedDeviceService` — register (idempotent), list, update, revoke                | `TrustedDeviceController` | `POST /api/devices`<br>`GET /api/devices`<br>`GET /api/devices/{id}`<br>`PUT /api/devices/{id}`<br>`DELETE /api/devices/{id}`             | USER                                               |
| **Audit**          | `AuditService` — log with SHA-256 hash chaining, CRLF sanitization                  | `AuditController`         | `GET /api/audit`<br>`GET /api/audit/action/{action}`                                                                                      | ADMIN / AUDITOR                                    |
| **File Handling**  | `CredentialImportExportService` + `FileHandlingService` + `ImportExportRateLimiter` | `ImportExportController`  | `POST /api/credentials/import`<br>`GET /api/credentials/export`                                                                           | USER                                               |

### Cross-Cutting Security

- **Password Hashing:** Argon2 (via Spring Security's `Argon2PasswordEncoder`).
- **Encryption at Rest:** AES-256/GCM/NoPadding with random 12-byte IV per credential (`EncryptionService`).
- **JWT Authentication:** HS256 tokens with configurable expiration; `JwtAuthFilter` validates on every request.
- **Audit Log Integrity:** SHA-256 hash chaining (each entry includes the previous entry's hash); `@PreUpdate`/`@PreRemove` throw `UnsupportedOperationException` to enforce immutability.
- **Secure File Handling:** Files stored in isolated temp directory (`kryptos.storage.temp-dir`) with `rw-------` (0600) permissions; path traversal prevention via `verifyWithinTempDir`; secure wipe with 3 passes (2× random + 1× zero fill) before OS deletion; 5 MB file size limit; 50 000 line record limit.
- **Rate Limiting:** Login endpoint (5 attempts/min → 15 min lockout), import/export endpoints (5 requests per minute per user).

## 3. Test Plan Execution

The following unit and integration tests were implemented against the security test scenarios defined in Sprint 1 (see `Derivables/Sprint1/SecurityTestPlanV2.md`):

### Authentication & Identity Management

| Threat | Test File | Test Method | Status |
|--------|-----------|-------------|--------|
| **R01** — Brute Force | `AuthServiceTest.java` | Stub (methods annotated TODO) | Pending |
| **R02** — JWT Manipulation | *(none)* | JWT validation logic is in `JwtService` — no dedicated unit test yet | Missing |
| **R03** — Credentials Exposed at Rest | `CredentialServiceTest.java` | `create_shouldEncryptPasswordAndSave` — verifies `encryptionService.encrypt()` is called | Implemented |
| **R03** — No plaintext in response | `CredentialServiceTest.java` | `create_shouldNotExposePasswordInResponse` — reflection check | Implemented |

### Authorization & Access Control (RBAC & IDOR)

| Threat | Test File | Test Method | Status |
|--------|-----------|-------------|--------|
| **R05** — IDOR on Credentials | `CredentialServiceTest.java` | `create_shouldThrow_whenVaultDoesNotBelongToOwner`, `findById_shouldThrow_whenCredentialDoesNotBelongToOwner`, `delete_shouldThrow_whenCredentialDoesNotBelongToOwner` | Implemented |
| **R07** — IDOR on Vaults | `VaultServiceTest.java` | `findById_shouldThrow_whenVaultDoesNotBelongToOwner`, `delete_shouldThrow_whenVaultDoesNotBelongToOwner` | Implemented |

### Data Handling, File I/O & OS Interaction

| Threat | Test File | Test Method | Status |
|--------|-----------|-------------|--------|
| **R08** — Oversize upload | `ImportExportController.java` (controller code rejects > 5 MB with 413) | *(controller-level — no test yet)* | Missing |
| **R13** — Path Traversal in Secure Wipe | `FileHandlingService.java` | `verifyWithinTempDir` + `secureDelete` throws `IllegalArgumentException` — no test class exists | Missing |

### Error Handling & Availability (DoS)

| Threat | Test File | Test Method | Status |
|--------|-----------|-------------|--------|
| **R06** — Plaintext Credential Leak | `EncryptionServiceTest.java` | `decrypt_shouldThrowEncryptionException_whenCiphertextIsInvalid`, `decrypt_shouldThrowEncryptionException_whenCiphertextIsTooShort`, `decrypt_shouldThrowEncryptionException_whenCiphertextIsTampered` | Implemented |

### Auditing & Cryptographic Integrity

| Threat | Test File | Test Method | Status |
|--------|-----------|-------------|--------|
| **R15** — Log Injection | `AuditServiceTest.java` | `log_shouldSanitizeDetails` — verifies CRLF and null chars are stripped | Implemented |
| **R14** — Audit Log Tampering | `AuditLog.java` | Immutability enforced at JPA level (`@PreUpdate`, `@PreRemove` throw) | Implemented in domain |
| Hash Chain Integrity | `AuditServiceTest.java` | `log_shouldBuildHashChain` — verifies `previousHash` is linked | Implemented |

### Threat-to-Test Summary by Requirement

| Requirement | Count | Status | File(s) |
|-------------|-------|--------|---------|
| R01 — Brute Force / Credential Stuffing | 1 | Pending (stubs) | `AuthServiceTest.java` |
| R02 — JWT Manipulation (EoP) | 0 | Missing | — |
| R03 — Credentials Exposed at Rest | 2 | Implemented | `CredentialServiceTest.java`, `EncryptionServiceTest.java` |
| R04 — Privilege Escalation (Mass Assignment) | 0 | Missing | — |
| R05 — IDOR on Credential Endpoints | 3 | Implemented | `CredentialServiceTest.java` |
| R06 — Plaintext Credential Leak | 3 | Implemented | `EncryptionServiceTest.java` |
| R07 — IDOR on Vault Endpoints | 2 | Implemented | `VaultServiceTest.java` |
| R08 — Malicious File Upload | 0 | Missing | — |
| R09 — Temporary File Exposed on Disk | 0 | Missing | — |
| R10 — IDOR on Export Endpoint | 0 | Missing | — |
| R11 — Export Endpoint Abuse (DoS) | 0 | Missing | — |
| R12 — Temporary File Not Securely Wiped | 0 | Missing | — |
| R13 — Path Traversal in Secure Wipe | 0 | Missing | — |
| R14 — Audit Log Tampering / Deletion | 1 | Implemented (domain) | `AuditLog.java` |
| R15 — Log Injection (Log4Shell-like) | 1 | Implemented | `AuditServiceTest.java` |
| R16 — Log Flooding (DoS) | 0 | Missing | — |
| R17 — Rogue Device Registration | 0 | Missing | — |
| R18 — Admin Actions Not Logged | 1 | Implemented (domain) | `UserService.java` |
| R19 — Session Hijacking for Vault Export | 0 | Missing | — |
| R20 — Wipe Failure Not Logged | 0 | Missing | — |

## 4. Security Requirements vs. Test Traceability

Mapping from **Sprint 1 Security Requirements** (`Derivables/Sprint1/SecurityTestPlan.md`) to implemented tests:

### General Requirements (GR)

| Req ID | Requirement | Implemented Tests | Status |
|--------|-------------|-------------------|--------|
| GR1 | Auth + RBAC on all endpoints | `AuditControllerTest` (Admin/Auditor roles), controller-level `@PreAuthorize` | Partial |
| GR2 | Input validation & sanitization | `AuditServiceTest.log_shouldSanitizeDetails` | Partial |
| GR3 | HTTPS/TLS | *(infrastructure-level, not testable in unit tests)* | N/A |
| GR4 | Log failed auth attempts | `AuthService.login` logs on failure (no test) | Missing |
| GR5 | Rate limiting on sensitive endpoints | `AuthService` (5 attempts), `ImportExportRateLimiter` (5/min) — no tests | Missing |
| GR6 | Strong password hashing (Argon2) | `SecurityConfig.passwordEncoder()` returns `Argon2PasswordEncoder` | Domain only |
| GR7 | JWT expiration validation | `JwtService` checks `isTokenExpired` — no test | Missing |
| GR8 | Credentials encrypted at rest | `CredentialServiceTest.create_shouldEncryptPasswordAndSave` | Implemented |
| GR9 | Secure wipe of temp files | `FileHandlingService.secureDelete` (3-pass) — no test class | Missing |
| GR10 | Audit logs restricted to Admin/Auditor | `AuditControllerTest` (Admin/Auditor 200, unauth 401) | Implemented |

### User Requirements (UR)

| Req ID | Requirement | Implemented Tests | Status |
|--------|-------------|-------------------|--------|
| UR1 | User only accesses own vaults/credentials | `VaultServiceTest` (IDOR checks), `CredentialServiceTest` (IDOR checks) | Implemented |
| UR2 | Stored credentials encrypted | `CredentialServiceTest.create_shouldEncryptPasswordAndSave`, `EncryptionServiceTest` (roundtrip) | Implemented |
| UR3 | Register trusted devices | `TrustedDeviceService` register with idempotency + fingerprint collision check — no test | Missing |
| UR4 | Import/export does not expose data | `CredentialImportExportService` double-encrypts export — no test | Missing |
| UR5 | Log important actions on user account | Audit logging on create/delete operations — verified in `CredentialServiceTest.delete_shouldDeleteAndAudit`, `VaultServiceTest.delete_shouldDeleteAndAudit` | Implemented |
| UR6 | Session expiration | JWT expiration enforced — no test | Missing |
| UR7 | Admin cannot access user credentials | No admin endpoints expose decrypted passwords — architectural guarantee | Domain only |
| UR8 | All admin actions logged | `UserService` logs on delete user / update role — no test | Missing |
| UR9 | Auditor can read logs without modifying | `AuditController` is read-only — `AuditLog` `@PreUpdate`/`@PreRemove` blocks modification | Implemented |
| UR10 | Audit records immutable | `AuditLog.java` — hash chain + JPA lifecycle guards | Implemented |

### Summary of Test Coverage by Test Category

| Test Category | Tests Implemented | GR/UR Coverage |
|---------------|------------------|----------------|
| Authentication Testing | Stubs only (TODO) | GR4, GR5, GR7 |
| Authorization Testing | **VaultServiceTest** (IDOR), **CredentialServiceTest** (IDOR), **AuditControllerTest** (roles) | GR1, GR10, UR1, UR9 |
| Session Management Testing | *(none)* | GR7, UR6 |
| Input Validation Testing | **AuditServiceTest** (sanitization) | GR2 |
| Cryptography Testing | **EncryptionServiceTest** (11 tests), **CredentialServiceTest** (encrypt mock) | GR3, GR6, GR8, UR2, UR4 |
| Business Logic Testing | Vault/Credential ownership verification | GR8, GR9, UR1, UR7 |
| File Handling Testing | *(none — domain code exists)* | GR9, UR4 |
| Audit & Logging Testing | **AuditServiceTest** (hash chain, sanitize), **AuditLog** (immutability) | GR4, GR10, UR5, UR8, UR9, UR10 |
