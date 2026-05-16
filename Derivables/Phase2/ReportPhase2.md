# Sprint 1 — Phase 2 Report

## 1. CI/CD Pipeline

The pipeline is defined in `.github/workflows/ci.yml`, runs on every push and
pull request to `main`, and uses GitHub Actions on `ubuntu-latest` runners.
Four jobs run in sequence: `build-and-test` produces the Maven artefact and is
a prerequisite for the three security jobs (`sast`, `sca`, `dast`), which run
in parallel afterwards.

All runtime secrets live in **GitHub repo secrets** and are referenced via
`${{ secrets.* }}` — no value is hardcoded. The variable names mirror those in
`backend/.env.example` so a developer's local `.env` and the CI environment
share the same contract.

| Secret              | Used by                  | Purpose                                                  |
|---------------------|--------------------------|----------------------------------------------------------|
| `DB_PASSWORD`       | `build-and-test`, `dast` | PostgreSQL service container password (test + DAST stack) |
| `JWT_SECRET`        | `build-and-test`, `dast` | HS256 signing key (≥ 32 bytes, validated at startup)     |
| `ENCRYPTION_SECRET` | `build-and-test`, `dast` | Seed for the AES-256/GCM key (rejected if blank)         |
| `NVD_API_KEY`       | `sca`                    | Avoids NVD rate-limit penalties on Dependency-Check      |
| `SONAR_TOKEN`       | `sast`                   | SonarCloud upload token                                  |
| `GITHUB_TOKEN`      | `sast`                   | SonarCloud PR decoration                                 |

`DB_URL`, `DB_USERNAME`, `JWT_EXPIRATION` and `kryptos.storage.temp-dir` are
plain (non-secret) env values. If `JWT_SECRET` or `ENCRYPTION_SECRET` are
missing or too short the application fails fast at startup (validation in
`JwtService.getSigningKey` and the `EncryptionService` constructor), so a
misconfigured environment cannot silently fall back to insecure defaults.

### Job 1 — Build & Test (`build-and-test`)
- Provisions a **PostgreSQL 16 (alpine)** service container
  (`kryptos_test`, user `kryptos`).
- Sets up **Java 21 (Temurin)** with the Maven cache.
- Runs `mvn verify` (compile, unit tests, package).
- Uploads `backend/target/` as the `maven-target-folder` artefact so the SAST
  job can reuse the compiled classes.

### Job 2 — SAST: SpotBugs + Find Security Bugs + SonarCloud (`sast`)
- Downloads the prebuilt `target/` from `build-and-test`.
- Runs `mvn spotbugs:check -DskipTests` with the **Find Security Bugs**
  plugin loaded (configured in `pom.xml`: spotbugs 4.8.6.4, findsecbugs
  1.13.0, effort `Max`, threshold `Medium`, `failOnError=false`).
- Uploads the SpotBugs XML report as `spotbugs-report`.
- Runs the **SonarCloud** scanner against project key `mei-desofs-kryptos`,
  organization `mei-desofs-kryptos` (host `sonarcloud.io`). PRs are
  decorated via `GITHUB_TOKEN` and the upload is authenticated with
  `SONAR_TOKEN`.

### Job 3 — SCA: OWASP Dependency-Check (`sca`)
- Runs `mvn dependency-check:check -DskipTests`
  (`dependency-check-maven` 10.0.4).
- `failBuildOnCVSS=9` is set in `pom.xml`; `continue-on-error: true` is set
  at the workflow level to ensure the SCA report is always published even
  when a CVE is found.
- Uses `NVD_API_KEY` to avoid rate-limit penalties from the NVD.
- Uploads `target/dependency-check*` (HTML + JSON + XML) as
  `dependency-check-report` (always, even on failure).

### Job 4 — DAST: OWASP ZAP Baseline (`dast`)
- Boots the full stack with `docker compose up -d --build`, exposing the
  same secrets to the compose file so `docker-compose.yml` can resolve
  `${DB_USERNAME}`, `${DB_PASSWORD}`, `${JWT_SECRET}`, `${JWT_EXPIRATION}`,
  and `${ENCRYPTION_SECRET}`.
- Polls `http://localhost:8080/api/auth/login` for up to 5 minutes (60 ×
  5 s) until the backend stops returning `502/503/504/000`.
- Runs **OWASP ZAP Baseline** (`zaproxy/action-baseline@v0.14.0`) with
  alpha rules (`-a`), AJAX spider (`-j`), `-m 5 -T 10` caps, and the
  baseline rule overrides in `.zap/rules.tsv` tuned for a stateless JWT
  REST API surface (CSP / CSRF / cookie checks downgraded to `WARN`;
  injection / transport / disclosure checks stay at `FAIL`).
- Collects `docker compose logs` for both `app` and `db` into
  `dast-logs/`, then runs `docker compose down -v`.
- Uploads the HTML / Markdown / JSON reports as `zap-report` and the
  collected logs as `dast-app-logs`.

### Artefacts produced per pipeline run

| Job  | Artefact                  | Format(s)              |
|------|---------------------------|------------------------|
| build-and-test | `maven-target-folder` | compiled `target/` (retention 1 day) |
| sast | `spotbugs-report`         | XML                    |
| sca  | `dependency-check-report` | HTML + JSON + XML      |
| dast | `zap-scan-internal`       | ZAP action default     |
| dast | `zap-report`              | HTML + Markdown + JSON |
| dast | `dast-app-logs`           | plain text logs        |

---

## 2. Domain Functionality

The Kryptos backend follows **Domain-Driven Design (DDD)** with four main
aggregates, a secure authentication layer, an immutable audit log, and a
file-handling module for import/export.

### Aggregates & core domain

| Aggregate          | Entity          | Key fields                                                                | Purpose                                           |
|--------------------|-----------------|---------------------------------------------------------------------------|---------------------------------------------------|
| **User**           | `User`          | id, username, email, password (Argon2), role, active                       | Account management with RBAC                      |
| **Vault**          | `Vault`         | id, name, description, owner                                              | Logical grouping of credentials per user          |
| **Credential**     | `Credential`    | id, serviceName, username, encryptedPassword (AES-GCM), url, notes, vault | Secure credential storage with encryption at rest |
| **Trusted Device** | `TrustedDevice` | id, deviceName, deviceFingerprint, registeredAt, active, user             | Device registration for access control            |
| **Audit Log**      | `AuditLog`      | id, action, performedBy, targetResource, details, timestamp, hash, previousHash | Append-only forensic trail                    |

### Services, controllers & authorization

| Bounded context | Service                                                                        | Controller                | Endpoints                                                                                                                                                | `@PreAuthorize`                                  |
|-----------------|--------------------------------------------------------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------|
| Auth            | `AuthService` — register/login with rate limiting (5 attempts → 15 min lockout) | `AuthController`          | `POST /api/auth/register`<br>`POST /api/auth/login`                                                                                                       | Public (`/api/auth/**` permitted in `SecurityConfig`) |
| User            | `UserService` — CRUD, role update, activate/deactivate                          | `UserController`          | `GET /api/users`<br>`GET /api/users/{id}`<br>`DELETE /api/users/{id}`<br>`PATCH /api/users/{id}/role`<br>`PATCH /api/users/{id}/activate`                  | `GET /{id}`: ADMIN or USER (self)<br>others: ADMIN |
| Vault           | `VaultService` — CRUD with ownership validation                                 | `VaultController`         | `POST /api/vaults`<br>`GET /api/vaults`<br>`GET /api/vaults/{id}`<br>`DELETE /api/vaults/{id}`                                                            | USER                                             |
| Credential      | `CredentialService` — CRUD with vault-ownership checks, password encryption     | `CredentialController`    | `POST /api/credentials`<br>`GET /api/credentials/vault/{vaultId}`<br>`GET /api/credentials/{id}`<br>`DELETE /api/credentials/{id}`                        | USER                                             |
| Trusted Device  | `TrustedDeviceService` — register (idempotent), list, update, revoke            | `TrustedDeviceController` | `POST /api/devices`<br>`GET /api/devices`<br>`GET /api/devices/{id}`<br>`PUT /api/devices/{id}`<br>`DELETE /api/devices/{id}`                              | USER                                             |
| Audit           | `AuditService` — write with SHA-256 hash chaining and CRLF sanitization         | `AuditController`         | `GET /api/audit` (paginated)<br>`GET /api/audit/action/{action}` (paginated)                                                                              | ADMIN or AUDITOR                                 |
| File Handling   | `CredentialImportExportService` + `FileHandlingService` + `ImportExportRateLimiter` | `ImportExportController`  | `POST /api/credentials/import`<br>`GET /api/credentials/export`                                                                                          | USER                                             |

### Cross-cutting security

- **Password hashing:** Argon2 via `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`.
- **Encryption at rest:** AES-256/GCM/NoPadding with a fresh random 12-byte
  IV per credential and a 128-bit GCM tag (`EncryptionService`). The key is
  derived from `ENCRYPTION_SECRET` via SHA-256 once, at startup.
- **JWT authentication:** HS256 with key length validated at sign/verify
  time (`getSigningKey` throws `IllegalStateException` if `JWT_SECRET` is
  shorter than 32 bytes). `JwtAuthFilter` validates every request; sessions
  are stateless (`SessionCreationPolicy.STATELESS`).
- **HTTP security headers:** strict CSP, HSTS with `includeSubDomains` and
  one-year `max-age`, `X-Frame-Options: DENY` (`SecurityConfig`).
- **Audit log integrity:** SHA-256 hash chain (`previousHash` ← prior
  entry's `hash`); JPA `@PreUpdate` / `@PreRemove` callbacks on `AuditLog`
  throw `UnsupportedOperationException` so updates and deletes are blocked
  at the ORM layer.
- **Secure file handling:** files stored in an isolated temp directory
  (`kryptos.storage.temp-dir`) with `rwx------` (0700) directory permissions
  and `rw-------` (0600) per-file permissions; path-traversal prevention via
  `verifyWithinTempDir`; secure wipe with 3 passes (2× random + 1× zero
  fill) before OS deletion; 5 MiB file size cap returning **HTTP 413** at
  the controller; 50 000 line record limit at the service.
- **Rate limiting:** login endpoint (5 attempts/min/principal → 15 min
  lockout via `AuthService`) and import/export endpoints (5
  requests/min/principal via `ImportExportRateLimiter` → **HTTP 429**).
- **Pagination:** `AuditController.findAll` / `findByAction` accept
  `Pageable` and return `Page<AuditLog>` (NFR9 — partial: still TODO for
  user / vault / credential / device list endpoints).

---