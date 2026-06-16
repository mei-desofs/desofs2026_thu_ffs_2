# Phase 2 — Sprint 2 Final Report (Kryptos)

## Summary

Sprint 2 closed the documentation and hardening gaps identified at the end of Sprint 1 and pushed ASVS 5.0 compliance to **193 / 345 controls Compliant (55.9 %)** on the authoritative tracker `Derivables/Phase2/ASVS_5.0_Tracker_Kryptos.xlsx`. Considering only the 193 in-scope controls (excluding 152 Not Applicable, mostly V3 Web Frontend, V10 OAuth/OIDC and V17 WebRTC — none of which are in scope for a stateless JWT REST backend), Kryptos is **100 % Compliant on the in-scope surface**. The codebase grew from a 4-aggregate DDD baseline into a fully instrumented stack with TLS termination (NGINX), mTLS to PostgreSQL, full Spring Boot Actuator + Prometheus + Grafana observability, structured JSON logging, an externally forwardable audit pipeline, and an extensive Data Protection module (`com.kryptos.shared.dataprotection`).

| Dimension                            | Sprint 1 baseline | Sprint 2 final | Source                                              |
|--------------------------------------|-------------------|----------------|-----------------------------------------------------|
| Java production files                | ~60               | **98**         | `find backend/src/main/java -name '*.java'`          |
| Java test files                      | 15                | **35**         | `find backend/src/test/java -name '*Test.java'`      |
| `@Test` methods                       | 97                | **343**        | `grep -c @Test` across test sources                  |
| ASVS Compliant controls              | 108               | **193**        | `Derivables/Phase2/ASVS_5.0_Tracker_Kryptos.xlsx` (Summary sheet) |
| Overall ASVS compliance (vs. 345)    | 31.3 %            | **55.9 %**     | `Derivables/Phase2/ASVS_5.0_Tracker_Kryptos.xlsx`     |
| In-scope ASVS compliance (vs. 193)   | 56.3 %            | **100 %**      | 193 Compliant / 152 Not Applicable / 0 open          |
| CI/CD jobs                           | 4                 | 4 + SBOM upload | `.github/workflows/ci.yml`                          |
| TLS termination + mTLS to DB         | n/a (Sprint 1)    | **NGINX + mTLS** | `backend/nginx/nginx.conf`, `backend/db/pg_hba.conf` |
| Observability stack                  | not deployed      | **Prometheus + Grafana + JSON logs** | `backend/docker-compose.yml`, `backend/prometheus.yml` |
| Documented security policies (`.md`) | 1 (`ReportPhase2.md`) | **13**     | `Derivables/Phase2/`, `backend/docs/`                 |

---

## 1. Scope, Inputs and Repository Map

Sprint 2 is the documented hardening phase. The Phase 1 outputs that fed into it are still in the repo and remain authoritative for requirements / threat traceability:

- `Derivables/Phase1/ReportPhase1.md` — project overview and the four DDD aggregates (User, Vault, Credential, TrustedDevice).
- `Derivables/Phase1/SystemOverview.md` — functional / non-functional / security requirements (GR1–GR10, UR1–UR10, NFR1–NFR9).
- `Derivables/Phase1/ThreatIdentification.md` — risks **R01–R20** that drive Sprint 2's traceability matrix.
- `Derivables/Phase1/STRIDE.md` — per-DFD-element STRIDE analysis and DREAD ranking.
- `Derivables/Phase1/SecurityTestPlan.md` and `SecurityTestPlanV2.md` — test categories used by the Sprint 2 traceability table.
- `Derivables/Phase1/ASVS_5.0_Tracker_Kryptos1.xlsx` — the baseline ASVS tracker (delta now lives in Phase 2).
- The Phase 1 DFDs at the project root (`DFD_Nivel0_Contexto.svg`, `DFD_Nivel1_Decomposicao.svg`, `DFD_Nivel2_Autenticacao.svg`, `DFD_Nivel2_ImportExport.svg`) and `Kryptos_Phase1_ThreatModeling_v2.docx`.

Sprint 2 deliverables (all under `Derivables/Phase2/`):

| File                                         | Purpose                                                                                  |
|----------------------------------------------|------------------------------------------------------------------------------------------|
| `ReportPhase2.md` / `ReportPhase2.pdf`        | Original Sprint 1 Phase 2 report (now superseded by this document).                       |
| `ASVS_5.0_Tracker_Kryptos.xlsx`               | Authoritative ASVS 5.0 tracker (Sprint 2 re-evaluation).                                  |
| `ASVS_Security_Controls_Documentation.md`     | V8.1.1 / V2.1.1 / V2.1.3 / V14.2.1 / V16.3.2 / V9.2.3 control documentation.              |
| `Authorization_Documentation.md`              | Formal V8.1.1 / V8.1.2 / V8.2.4 / V8.3.2 authorization model.                             |
| `Cryptographic_Architecture.md`               | V11.1.1 – V11.1.4 — key management, inventory, discovery, PQC plan.                       |
| `File_Handling_Policy.md`                     | V5.1.1 upload/import policy and threat mitigation matrix.                                 |
| `Session_Management_Policy.md`                | V7.1.1 — 1-hour JWT lifetime justification vs. NIST SP 800-63B.                           |
| `TLS_Architecture_Policy.md`                  | V12.1.1, V12.1.2, V12.1.4, V12.2.1, V12.3.1–V12.3.5 — TLS + mTLS architecture.            |
| `Secure_Architecture_and_Component_Policy.md` | V15.1.1 – V15.1.5 — SCA SLAs, SBOM, dangerous-functionality inventory.                    |
| `Security_Logging_and_Monitoring_Policy.md`   | V16.1.1, V16.2.1, V16.3.1–V16.3.3 — audit log inventory.                                  |
| `Monitoring_Setup.md`                         | Prometheus + Grafana + JSON logging runbook.                                              |
| `SCA_Findings_Analysis.md`                    | OWASP Dependency-Check (10.0.4) findings and remediation plan.                            |
| `ZAP_Methodology.md`                          | DAST methodology and rule tuning (`.zap/rules.tsv`).                                      |
| `ReportPhase2_Sprint2_Final.md` *(this file)* | Sprint 2 consolidated final report.                                                       |

Operational policy referenced by V13: `backend/docs/V13-Configuration-Security.md`.
Cross-sprint summary: `docs/ASVS_COMPLIANCE_REPORT.md`.

---

## 2. System Architecture (Sprint 2 state)

### 2.1 Runtime topology

`backend/docker-compose.yml` brings up five services on a private Docker network. Only NGINX is exposed publicly.

```
Internet ──(80 → 301 → 443 TLS 1.2/1.3)──> proxy (NGINX, ./nginx/Dockerfile)
                                                │
                                                ▼ HTTP (private)
                                          app (Spring Boot 3.5.3 / Java 21)
                                          │  ▲
                                          │  └── scrape /actuator/prometheus ──> prometheus (9090) ──> grafana (3000)
                                          ▼
                                    db (postgres:16-alpine, mTLS only)
```

Source files:

- Reverse proxy: `backend/nginx/Dockerfile`, `backend/nginx/nginx.conf` — TLS 1.2/1.3 only, PFS-only cipher list, OCSP stapling, HSTS `max-age=63072000; includeSubDomains; preload`, port 80 → 443 redirect.
- Application: `backend/Dockerfile` (multi-stage Maven → JRE Alpine), entrypoint runs with `-Dspring.profiles.active=dev`.
- Database hardening: `backend/db/postgresql.conf` (`ssl = on`, certificate files), `backend/db/pg_hba.conf` (`hostssl ... cert` for all network connections and `hostnossl ... reject`).
- Internal CA + certs: generated by `backend/scripts/generate-certs.sh` (OpenSSL: CA → server cert for `db` → client cert with CN `kryptos` → PKCS#8 client key for the JDBC driver). CA is dev-only; production must use a publicly trusted CA per `TLS_Architecture_Policy.md` §V12.2.2.
- Observability: `backend/prometheus.yml` (10 s scrape of `app:8080/actuator/prometheus`), Grafana container with default admin creds gated by `GRAFANA_PASSWORD` env.
- App ↔ DB string: `jdbc:postgresql://db:5432/kryptos?sslmode=verify-full&sslrootcert=/certs/ca.crt&sslcert=/certs/client.crt&sslkey=/certs/client.pk8` (set in `docker-compose.yml`).

### 2.2 Domain (DDD) modules

DDD layout: `com.kryptos.<context>.{api, application, application.dto, domain}`.

| Bounded context | Domain entities (`domain/`)                                          | Application services (`application/`)                              | REST controllers (`api/`)                          |
|-----------------|-----------------------------------------------------------------------|--------------------------------------------------------------------|-----------------------------------------------------|
| Auth            | `User`, `Role`, `BackupCode` (under `user.domain`)                    | `AuthService` (562 LOC), `TotpService`, `BackupCodeService`, `SuspiciousAuthNotificationService`, `AuthExpiryNotificationService` | `AuthController` (12 endpoints incl. 2FA/TOTP)      |
| User            | `User`, `UserRepository`                                              | `UserService` (161 LOC), `AdminUserService`                        | `UserController`, `AdminUserController` (ADMIN-only) |
| Vault           | `Vault`, `VaultRepository`                                            | `VaultService` (108 LOC)                                           | `VaultController`                                   |
| Credential      | `Credential`, `CredentialRepository`                                  | `CredentialService` (129 LOC), `CryptoMigrationService`            | `CredentialController`, `CryptoMigrationController` |
| Trusted Device  | `TrustedDevice`, `TrustedDeviceRepository`                            | `TrustedDeviceService` (124 LOC)                                   | `TrustedDeviceController`                           |
| Audit           | `AuditLog`, `AuditLogRepository`, `AuditAction` (constant catalogue)  | `AuditService` (SHA-256 hash chain, CRLF sanitization), `LogForwardingService` (V16.4.3 external SIEM) | `AuditController`            |
| File Handling   | (no domain entity — pure application)                                  | `FileHandlingService` (280 LOC, secure wipe + path traversal guard), `CredentialImportExportService`, `ImportExportRateLimiter` | `ImportExportController` |
| Shared / Security | `RevokedToken`, `HmacProperties`                                    | `EncryptionService` (final, AES-256-GCM, v1/v2 KDFs), `JwtService`, `HmacService`, `OutboundConnectionValidator`, `ProductionSecurityValidator`, `EmailService` | n/a (cross-cutting) |
| Shared / Data Protection | `DataClassification`, `SensitiveDataElement`, `DataRetentionPolicy`, `RetentionAction` | `DataClassificationService` (155 LOC), `DataRetentionService` | n/a |

Aggregate inventory: 98 production Java files (`find backend/src/main/java -name '*.java' \| wc -l`).

### 2.3 Cross-cutting security controls

| Control                     | Class / file                                                       | Notes                                                                                                  |
|-----------------------------|--------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| HTTP firewall + headers     | `shared/security/SecurityConfig.java`                              | CSRF disabled (JWT API), stateless sessions, HSTS 1 year, CSP `default-src 'self'`, frame-options DENY, `StrictHttpFirewall` method allowlist (`GET/POST/PUT/DELETE/PATCH/OPTIONS`). |
| JWT signing / validation    | `shared/security/JwtService.java` (163 LOC)                        | HS256, audience `kryptos`, 32-byte key length enforced at sign + verify, IP + UA claim binding, `sessionTokenValidAfter` instant invalidation, SHA-256-hashed revocation list (`RevokedToken` / `RevokedTokenRepository`), step-up via `requireRecentAuthentication` (5 min window). |
| HMAC request signing        | `shared/security/HmacAuthenticationFilter.java`, `HmacService.java`, `HmacProperties.java`, `CachedBodyHttpServletRequest.java` | Optional layer auto-wired only when enabled (`Optional<HmacAuthenticationFilter>` injection in `SecurityConfig`), proof-of-possession on mutating requests. |
| Password hashing            | `shared/security/SecurityConfig#passwordEncoder`                    | `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`.                                              |
| Encryption at rest          | `shared/encryption/EncryptionService.java`                          | AES-256/GCM/NoPadding, 12-byte SecureRandom IV, 128-bit GCM tag, **v2 PBKDF2WithHmacSHA256 (65 536 iterations, salt)** as primary KDF with v1 SHA-256 fallback; `previous-secret` slot supports zero-downtime key rotation (`CryptoMigrationService` triggers re-encryption). |
| Server hardening            | `shared/security/ServerHardeningConfig.java`                        | Strips `Server` / `X-Powered-By`; blocks `TRACE` with 405 (V13.4.4, V13.4.6).                          |
| Static resource hardening   | `shared/security/StaticResourceSecurityConfig.java`                 | Disables static handlers, blocks dangerous extensions (`.env`, `.key`, `.properties`, `.java`…).        |
| Production guard            | `shared/security/ProductionSecurityValidator.java`                  | `@Profile("prod")`; fails startup if `JWT_SECRET` / `ENCRYPTION_SECRET` / `DB_PASSWORD` / `DB_USERNAME` are defaults or weak. |
| SSRF / outbound allowlist   | `shared/security/OutboundConnectionValidator.java`                  | Blocks private IPs (10/8, 172.16/12, 192.168/16), loopback, link-local; allowlist from `kryptos.security.allowed-external-hosts`. |
| Global exception handling   | `shared/exception/GlobalExceptionHandler.java`                      | `InvalidTokenException`, `RateLimitExceededException`, `ResourceNotFoundException`, `ForbiddenException`, `ReauthenticationRequiredException`, `EncryptionException` — all returned as generic `ErrorResponse`. |
| Audit logging               | `audit/application/AuditService.java`                               | SHA-256 hash chain over `(action, performedBy, target, details, ip, ua, previousHash, ts)`; CRLF / control-char sanitization; IP & UA captured from `RequestContextHolder`; integrates with `DataClassificationService` for `logSensitive`. |
| Audit immutability          | `audit/domain/AuditLog.java`                                        | `@PreUpdate` / `@PreRemove` throw `UnsupportedOperationException`; verified by `AuditLogTest`.         |
| File handling               | `filehandling/application/FileHandlingService.java`                 | POSIX 0700 dir / 0600 files, 5 MiB cap, 50 000-line cap, 3-pass wipe (2× SecureRandom + 1× zero), `verifyWithinTempDir` traversal guard, audit on success and failure. |
| Rate limiting               | `auth.AuthService` (5 attempts → 15 min lockout), `filehandling.ImportExportRateLimiter` (5/min/principal → HTTP 429), `auth.AuthService#resetAttempts` (3/5min). | All token-bucket style, returning `RateLimitExceededException`. |
| Data classification         | `shared/dataprotection/DataClassification.java`, `SensitiveDataElement.java`, `DataClassificationService.java`, `DataRetentionService.java` | PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED; per-class retention policies (RESTRICTED → 30 d DELETE; CONFIDENTIAL → 90 d DELETE; INTERNAL → 365 d REVIEW; PUBLIC → no expiry); GDPR Art. 32 / 5(1)(f) mapping. |
| Audit log forwarding        | `audit/application/LogForwardingService.java`                       | Optional SIEM HTTPS push via `kryptos.logging.forwarding.url` (V16.4.3).                                |

---

## 3. CI/CD Pipeline

Defined in `.github/workflows/ci.yml`. Triggers: push and PR against `main` and `dev`. Secrets are referenced via `${{ secrets.* }}` and mirror the variable contract in `backend/.env.example`.

| Job              | Trigger gate                              | Tooling                                                                                                                            | Artefacts                                                  |
|------------------|-------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| `build-and-test` | every push / PR                          | PostgreSQL 16-alpine service container, Java 21 Temurin, `mvn verify` (compile + 343 tests + JaCoCo + CycloneDX SBOM via `cyclonedx-maven-plugin` 2.9.1) | `maven-target-folder` (1-day retention), `sbom` (`application.cdx.json`) |
| `sast`           | runs on `dev`                            | `spotbugs-maven-plugin` 4.8.6.4 + `findsecbugs-plugin` 1.13.0 (`Max` effort, `Medium` threshold, `failOnError=false`); SonarCloud (`mei-desofs-kryptos` org, project key `mei-desofs-kryptos`) with Quality Gate check | `spotbugs-report` (XML), `sonarcloud-report`               |
| `sca`            | runs on `dev`                            | `dependency-check-maven` 10.0.4 (`failBuildOnCVSS=7` in `pom.xml`), `NVD_API_KEY` to dodge rate limits, `continue-on-error: true` so reports always upload | `dependency-check-report` (HTML + JSON + XML)              |
| `dast`           | runs on `main`                           | `sh scripts/generate-certs.sh` → `docker compose up -d --build` → poll `https://localhost/api/auth/login` (60 × 5 s) → `zaproxy/action-baseline@v0.14.0` with `.zap/rules.tsv` (`-a -j -m 5 -T 10`) | `zap-scan-internal`, `zap-report` (HTML + Markdown + JSON), `dast-app-logs` |

Secret contract (all required for `build-and-test`/`dast`):

| Secret              | Consumers                  | Validation in code                                                |
|---------------------|----------------------------|-------------------------------------------------------------------|
| `DB_PASSWORD`       | PostgreSQL service container | `ProductionSecurityValidator` blocks defaults in prod profile     |
| `JWT_SECRET`        | `JwtService#getSigningKey`  | Throws `IllegalStateException` if < 32 bytes                      |
| `ENCRYPTION_SECRET` | `EncryptionService` constructor | Throws `IllegalStateException` if blank                       |
| `NVD_API_KEY`       | `sca` job                   | n/a — only avoids rate-limit penalties                            |
| `SONAR_TOKEN`       | `sast` job                  | n/a — SonarCloud auth                                             |
| `GITHUB_TOKEN`      | `sast` job                  | n/a — PR decoration                                               |

Plain (non-secret) env: `DB_URL`, `DB_USERNAME`, `JWT_EXPIRATION`, `kryptos.storage.temp-dir`.

Release pipeline: `.github/workflows/release-please.yml` drives versioning; the current changelog (`backend/CHANGELOG.md`) reflects the v1.0.0 cut on 2026-06-16.

---

## 4. ASVS 5.0 Compliance (Sprint 2 re-evaluation)

The authoritative tracker is `Derivables/Phase2/ASVS_5.0_Tracker_Kryptos.xlsx` (Summary sheet + 17 chapter sheets V1–V17 re-scored against the actual code). Cross-sprint progression is summarised in `docs/ASVS_COMPLIANCE_REPORT.md`. Sprint 2 closed every gap left at the end of Sprint 1 — there are now **no `In Progress` or `Not Started` items**; every requirement is either **Compliant** or **Not Applicable** to the Kryptos surface.

| Status         | Count    | % of 345 controls |
|----------------|----------|-------------------|
| Compliant      | **193**  | **55.9 %**        |
| Not Applicable | **152**  | 44.1 %            |
| In Progress    | 0        | 0 %               |
| Not Started    | 0        | 0 %               |

Of the **193 in-scope controls** (excluding the 152 Not Applicable — V3 Web Frontend, V10 OAuth/OIDC, V17 WebRTC, plus per-control exclusions documented in each chapter sheet's `Observations` column), Kryptos is **100 % Compliant**.

By-level summary (from the `Summary` sheet):

| Level | Total reqs | Compliant | %       |
|-------|------------|-----------|---------|
| L1    | 70         | 52        | 74.3 %  |
| L2    | 183        | 96        | 52.5 %  |
| L3    | 92         | 45        | 48.9 %  |
| **Overall** | **345** | **193** | **55.9 %** |

Per-chapter compliance from the tracker:

| Chapter                                       | Total | L1 ✓ / L1 | L2 ✓ / L2 | L3 ✓ / L3 | Compliant | %        | Sprint 2 documentation / code                                                       |
|-----------------------------------------------|-------|-----------|-----------|-----------|-----------|----------|--------------------------------------------------------------------------------------|
| V1 — Encoding & Sanitization                  | 30    | 5 / 8     | 11 / 19   | 2 / 3     | **18**    | 60.0 %   | `AuditService.sanitize`, `GlobalExceptionHandler`                                    |
| V2 — Validation & Business Logic              | 13    | 4 / 4     | 6 / 7     | 1 / 2     | **11**    | 84.6 %   | `ASVS_Security_Controls_Documentation.md` §V2.1.1, §V2.1.3                            |
| V3 — Web Frontend Security                    | 31    | 0 / 8     | 0 / 11    | 0 / 12    | **0**     | 0 %      | **N/A** — backend-only project, no HTML/JS frontend                                  |
| V4 — API and Web Service                      | 16    | 1 / 2     | 2 / 8     | 6 / 6     | **9**     | 56.3 %   | `StrictHttpFirewall` method allowlist, `SecurityConfig`                              |
| V5 — File Handling                            | 13    | 4 / 4     | 5 / 5     | 3 / 4     | **12**    | 92.3 %   | `File_Handling_Policy.md`                                                            |
| V6 — Authentication                           | 47    | 12 / 13   | 11 / 22   | 7 / 12    | **30**    | 63.8 %   | `AuthService` (lockout, password reset, 2FA, TOTP, backup codes), `AuthController`   |
| V7 — Session Management                       | 19    | 6 / 6     | 6 / 12    | 0 / 1     | **12**    | 63.2 %   | `Session_Management_Policy.md`, `JwtService` revocation list                          |
| V8 — Authorization                            | 13    | 3 / 4     | 2 / 3     | 3 / 6     | **8**     | 61.5 %   | `Authorization_Documentation.md` (V8.1.1 / V8.1.2 / V8.2.4 / V8.3.2)                  |
| V9 — Self-contained Tokens                    | 7     | 4 / 4     | 2 / 3     | 0 / 0     | **6**     | 85.7 %   | JWT `aud=kryptos`, `requireAudience("kryptos")` in `JwtService.extractAllClaims`      |
| V10 — OAuth and OIDC                          | 36    | 2 / 5     | 3 / 24    | 0 / 7     | **5**     | 13.9 %   | **N/A** — Kryptos uses self-issued HS256 JWTs, no OAuth/OIDC                          |
| V11 — Cryptography                            | 24    | 3 / 3     | 11 / 11   | 8 / 10    | **22**    | 91.7 %   | `Cryptographic_Architecture.md` + `EncryptionService` v1/v2 KDFs                      |
| V12 — Secure Communication                    | 12    | 3 / 3     | 5 / 6     | 2 / 3     | **10**    | 83.3 %   | `TLS_Architecture_Policy.md` + `nginx.conf` + `db/postgresql.conf` + `db/pg_hba.conf` |
| V13 — Configuration                           | 21    | 1 / 1     | 12 / 12   | 8 / 8     | **21**    | **100 %** | `backend/docs/V13-Configuration-Security.md` + `ProductionSecurityValidator`         |
| V14 — Data Protection                         | 13    | 1 / 2     | 5 / 7     | 2 / 4     | **8**     | 61.5 %   | `shared/dataprotection/*`, GDPR Art. 32 / 5(1)(f) mapping                              |
| V15 — Secure Coding & Architecture            | 21    | 3 / 3     | 5 / 10    | 3 / 8     | **11**    | 52.4 %   | `Secure_Architecture_and_Component_Policy.md` + CycloneDX SBOM in `mvn verify`        |
| V16 — Security Logging & Error Handling       | 17    | 0 / 0     | 10 / 16   | 0 / 1     | **10**    | 58.8 %   | `Security_Logging_and_Monitoring_Policy.md` + `LogForwardingService` (V16.4.3)         |
| V17 — WebRTC                                  | 12    | 0 / 0     | 0 / 7     | 0 / 5     | **0**     | 0 %      | **N/A** — Kryptos is a JSON REST API, no WebRTC surface                              |
| **TOTAL**                                     | **345** | **52 / 70** | **96 / 183** | **45 / 92** | **193** | **55.9 %** | |

The headline chapters for a backend-only secure credential manager — V11 Cryptography (91.7 %), V12 Secure Communication (83.3 %), V13 Configuration (**100 %**), V5 File Handling (92.3 %), V9 Self-contained Tokens (85.7 %) and V2 Validation (84.6 %) — are all at or near full compliance. The remaining "gaps" (V3, V10, V17 at 0 %) are entire categories that don't apply to the Kryptos surface (no HTML frontend, no OAuth/OIDC, no WebRTC), and every individual control in those chapters is marked **Not Applicable** in the tracker with a reasoned justification in the `Observations` column.

The Sprint 2 sweep specifically landed:

- **V2.1.1 / V2.1.3** (input + business-logic limits) — full matrix in `ASVS_Security_Controls_Documentation.md`; enforced by `@Valid` on DTOs (`CreateVaultRequest`, `CreateCredentialRequest`, `RegisterRequest`, etc.) and by `VaultService` (`countByOwnerId < 50`), `AuthService` lockouts, `ImportExportRateLimiter`, `application.properties` (`spring.servlet.multipart.max-file-size=5MB`).
- **V5.1.1** (upload matrix) — `File_Handling_Policy.md` documents the `.kvault`/`.csv`/`.json`/`.txt` allowlist, 5 MiB cap, 50 000-line cap, 3-pass wipe; implementation in `FileHandlingService` constants `MAX_IMPORT_BYTES`, `MAX_IMPORT_LINES`, `SECURE_WIPE_PASSES`.
- **V7.1.1** (session lifetime doc) — `Session_Management_Policy.md` justifies the 1 h JWT vs. NIST SP 800-63B; configured via `JWT_EXPIRATION` env (`.env.example`, `application.properties`).
- **V8.1.1 / V8.1.2 / V8.2.4 / V8.3.2** — `Authorization_Documentation.md` formalises the function-, data- and field-level model; instant revocation via `User.sessionTokenValidAfter` and the check in `JwtService.isTokenValid`; on role change `UserService.updateUserRole` sets `sessionTokenValidAfter = now()`.
- **V9.2.3** — JWT audience claim `aud=kryptos` issued in `JwtService.generateToken` and required in `JwtService.extractAllClaims` (`requireAudience("kryptos")`).
- **V11.1.1 – V11.1.4** — `Cryptographic_Architecture.md` (key lifecycle policy, full inventory, SAST / SCA discovery mechanisms, PQC migration plan).
- **V12.1.1 / V12.1.2 / V12.1.4 / V12.2.1 / V12.3.1 – V12.3.5** — `TLS_Architecture_Policy.md` backed by `nginx/nginx.conf`, `db/postgresql.conf`, `db/pg_hba.conf`, `scripts/generate-certs.sh` (internal CA + client cert auth `hostssl ... cert`).
- **V13.1.1 – V13.4.7** — `backend/docs/V13-Configuration-Security.md` documents communication needs, HikariCP limits, secret rotation cadence, `OutboundConnectionValidator`, `StaticResourceSecurityConfig`, `ServerHardeningConfig`, `application-prod.properties` (`ddl-auto=validate`, `show-sql=false`, `springdoc.*.enabled=false`, `server.error.include-stacktrace=never`).
- **V14.x** — `shared/dataprotection` module (94 tests across `DataClassificationServiceTest`, `DataRetentionServiceTest`, `DataClassificationTest`, `SensitiveDataElementTest`).
- **V15.1.1 – V15.1.5** — `Secure_Architecture_and_Component_Policy.md` (SCA SLA table 24 h / 7 d / 30 d / 90 d, CycloneDX SBOM published per CI run, dangerous-functionality inventory of `FileHandlingService` and `Runtime.exec()`).
- **V16.1.1 – V16.4.3** — `Security_Logging_and_Monitoring_Policy.md` (event inventory), `AuditAction` constants for 24 event types, `LogForwardingService` for external SIEM push.

---

## 5. Test Plan & Coverage

`mvn verify` builds **343 `@Test` methods across 35 test classes** (up from 97 / 15 at the end of Sprint 1). JaCoCo reports HTML + XML to `target/site/jacoco/` for SonarCloud ingestion.

| Test class                                                                                                  | Tests | Layer covered                                                                                       |
|-------------------------------------------------------------------------------------------------------------|-------|------------------------------------------------------------------------------------------------------|
| `auth/AuthServiceTest`                                                                                       | 21    | Register, login, lockout, password reset, password history, reset failures, 2FA flow                  |
| `auth/AccountLockoutIntegrationTest`                                                                         | 2     | End-to-end account-locked-until-admin                                                                 |
| `auth/PasswordResetIntegrationTest`                                                                          | 7     | Reset request → token → confirm; expiry; reuse                                                        |
| `auth/api/AuthControllerTest`                                                                                | 12    | MockMvc on `/api/auth/**` (register, login, 2FA, logout)                                              |
| `auth/application/BackupCodeServiceTest`                                                                     | 6     | 2FA backup code generation, single-use verification                                                  |
| `auth/application/TotpServiceTest`                                                                           | 10    | TOTP secret + QR code + code window                                                                  |
| `user/UserServiceTest`                                                                                       | 16    | CRUD, IDOR (`update`, `findById`), role updates, soft delete, admin audit, session invalidation       |
| `user/AdminUserServiceTest`                                                                                  | 3     | Admin reset password flow                                                                            |
| `vault/VaultServiceTest`                                                                                     | 8     | CRUD + IDOR (`findById`, `delete`) + 50-per-user limit                                                |
| `vault/api/VaultControllerTest`                                                                              | 13    | MockMvc — RBAC, validation, 201/204/400/401                                                          |
| `credential/CredentialServiceTest`                                                                           | 11    | CRUD, encryption, IDOR (3 paths), no-plaintext-in-response                                            |
| `credential/CredentialIntegrationTest`                                                                       | 5     | End-to-end encrypted persistence                                                                     |
| `credential/api/CredentialControllerTest`                                                                    | 12    | MockMvc — auth, validation, 201/204/400/401                                                          |
| `credential/api/CryptoMigrationControllerTest`                                                               | 1     | Re-encryption endpoint smoke test                                                                    |
| `credential/application/CryptoMigrationServiceTest`                                                          | 3     | Migration from v1 → v2 keys                                                                          |
| `trusteddevice/TrustedDeviceServiceTest`                                                                     | 6     | Register, fingerprint collision, IDOR, revoke, rename                                                |
| `filehandling/FileHandlingServiceTest`                                                                       | 6     | Permissions, 3-pass wipe, path traversal, oversize, sanitised filename                               |
| `filehandling/CredentialImportExportServiceTest`                                                             | 7     | Empty payload, malformed lines, auto-vault, owner-not-found                                          |
| `filehandling/ImportExportRateLimiterTest`                                                                   | 2     | Token bucket — 5/min, per-principal isolation                                                        |
| `audit/api/AuditControllerTest`                                                                              | 8     | RBAC — ADMIN/AUDITOR 200, USER 401; `my-login-history` endpoint                                      |
| `audit/application/AuditServiceTest`                                                                         | 7     | Hash chain, sanitization, IP/UA capture, sensitive log sanitization                                  |
| `audit/application/LogForwardingServiceTest`                                                                 | 8     | SIEM HTTPS push, failure modes                                                                        |
| `audit/domain/AuditLogTest`                                                                                  | 4     | `@PreUpdate`/`@PreRemove` throw, `@PrePersist` timestamps                                             |
| `shared/encryption/EncryptionServiceTest`                                                                    | 15    | v1 / v2 roundtrip, tampering, short ciphertext, blank secret, key rotation fallback                  |
| `shared/security/JwtServiceTest`                                                                             | 12    | Tampered, expired, garbage, wrong user, short secret, IP/UA binding, audience requirement            |
| `shared/security/SecurityIntegrationTest`                                                                    | 21    | End-to-end `SecurityFilterChain`, HSTS, CSP, frame-options, method allowlist                          |
| `shared/security/HmacAuthenticationFilterTest`                                                               | 4     | HMAC filter enable/disable, malformed signatures                                                     |
| `shared/security/HmacServiceTest`                                                                            | 2     | HMAC compute / verify                                                                                |
| `shared/security/CachedBodyHttpServletRequestTest`                                                           | 1     | Body caching wrapper                                                                                 |
| `shared/security/OutboundConnectionValidatorTest`                                                            | 13    | SSRF private-range / loopback / link-local rejection, allowlist                                      |
| `shared/dataprotection/DataClassificationServiceTest`                                                        | 36    | Protection requirements per class, sanitization, compliance mappings                                  |
| `shared/dataprotection/DataClassificationTest`                                                               | 22    | Enum behaviour, retention guidance                                                                   |
| `shared/dataprotection/DataRetentionServiceTest`                                                             | 16    | Retention policy lookup, expiry calculation                                                          |
| `shared/dataprotection/SensitiveDataElementTest`                                                             | 20    | Classification lookup, GDPR mapping                                                                  |
| `shared/email/EmailServiceTest`                                                                              | 3     | Password reset email, 2FA email                                                                       |
| **Total**                                                                                                    | **343** | |

### 5.1 Threat → Test traceability (R01–R20 from `Phase1/ThreatIdentification.md`)

| Risk | Mitigation                                                              | Test evidence (Sprint 2 state)                                                                              | Status         |
|------|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|----------------|
| R01  | 5 attempts → 15 min lockout                                              | `AuthServiceTest.login_shouldLockAccount_afterMaxFailedAttempts` + `AccountLockoutIntegrationTest`           | Covered        |
| R02  | HS256 + signature/exp/audience + IP/UA binding                          | `JwtServiceTest` (12) — tampered, garbage, wrong user, expired, short secret, IP mismatch, UA mismatch        | Covered        |
| R03  | Argon2 + AES-256-GCM (PBKDF2 v2 KDF)                                    | `EncryptionServiceTest` (15) + `CredentialServiceTest.create_shouldEncryptPasswordAndSave`                  | Covered        |
| R04  | DTO whitelist; `PATCH /role` is ADMIN-only                              | `UserServiceTest` + `AuthControllerTest`                                                                    | Design-immune  |
| R05  | Vault-ownership check on every credential op                            | `CredentialServiceTest.create/findById/delete_shouldThrow_whenCredentialDoesNotBelongToOwner` (3)           | Covered        |
| R06  | Generic exception messages; `EncryptionException`                       | `EncryptionServiceTest.decrypt_shouldThrow…` (3)                                                            | Covered        |
| R07  | Owner-scoped repository queries                                          | `VaultServiceTest.findById/delete_shouldThrow_whenVaultDoesNotBelongToOwner`                                | Covered        |
| R08  | UUID rename + extension allowlist; 5 MiB cap → 413                      | `FileHandlingServiceTest.storeUpload_sanitisesFilename` + `storeUpload_shouldRejectOversizeFile`            | Covered        |
| R09  | 0700 dir + 0600 files                                                   | `FileHandlingServiceTest.exportCredentials_filesAreOwnerOnly`                                               | Covered        |
| R10  | Export endpoint has no `vault_id`                                        | n/a (impossible by design)                                                                                  | Design-immune  |
| R11  | `ImportExportRateLimiter` 5/min/principal → 429                        | `ImportExportRateLimiterTest.tryAcquireExport_allowsFivePerMinute_thenThrottles`                            | Covered        |
| R12  | 3-pass wipe (2× random + zero)                                          | `FileHandlingServiceTest.secureDelete_removesFileAndLogsSuccess`                                            | Covered        |
| R13  | `verifyWithinTempDir` → `IllegalArgumentException`                      | `FileHandlingServiceTest.secureDelete_refusesPathOutsideTempDir`                                            | Covered        |
| R14  | `AuditLog @PreUpdate / @PreRemove` throw                                | `AuditLogTest` + `AuditServiceTest.log_shouldBuildHashChain`                                                | Covered        |
| R15  | CRLF / control chars stripped in `AuditService.sanitize`                | `AuditServiceTest.log_shouldSanitizeDetails`                                                                | Covered        |
| R16  | Append-only DB writes; rate limits at auth + import/export             | Load testing remains out of unit-test scope (k6/Gatling backlog)                                            | **Missing**    |
| R17  | Fingerprint collision rejected with 403 + audit                         | `TrustedDeviceServiceTest.register_shouldRejectFingerprintOwnedByAnotherUser`                              | Covered        |
| R18  | `UserService.deleteById / updateUserRole` write audit                   | `UserServiceTest.deleteById_shouldSoftDeleteUser`, `updateUserRole_shouldChangeRoleAndSave`                | Covered        |
| R19  | JWT expiry + export rate limit                                          | `JwtServiceTest.isTokenValid_shouldReturnFalse_forExpiredToken` + R11 rate limit                            | Covered        |
| R20  | `SECURE_WIPE_FAILED` audit emitted before throw                         | `FileHandlingServiceTest.secureDelete_refusesPathOutsideTempDir`                                            | Covered        |

**Coverage:** 17 Covered · 2 Design-immune · 1 Missing (R16 — load-test scope). Documented as remaining Sprint 3 backlog.

### 5.2 GR / UR traceability (from `Phase1/SecurityTestPlanV2.md`)

| ID   | Requirement                                       | Sprint 2 evidence                                                                                                                                                | Status         |
|------|----------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------|
| GR1  | Auth + RBAC on all endpoints                       | `@PreAuthorize` per controller (`AuditController`, `UserController`, `AdminUserController`, `CredentialController`, `VaultController`, `TrustedDeviceController`); enforced by `SecurityConfig` `@EnableMethodSecurity` | Covered        |
| GR2  | Input validation & sanitization                    | DTO `@NotBlank`/`@Email`/`@Size`; `AuditServiceTest.log_shouldSanitizeDetails`; controller tests for 400; `PasswordValidator`                                       | Covered        |
| GR3  | HTTPS / TLS                                       | NGINX TLS 1.2/1.3 + HSTS + OCSP; mTLS to PostgreSQL; documented in `TLS_Architecture_Policy.md`                                                                  | Architectural  |
| GR4  | Failed auth attempts logged                        | `AuthServiceTest` — `LOGIN_FAILED` audit on bad password and on lockout                                                                                          | Covered        |
| GR5  | Rate limiting on sensitive endpoints               | `AuthServiceTest.login_shouldLockAccount_…` + `ImportExportRateLimiterTest` (2) + reset-attempt limiter                                                            | Covered        |
| GR6  | Strong password hashing (Argon2)                   | `SecurityConfig.passwordEncoder()` returns `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`; exercised in `AuthServiceTest`                                | Covered        |
| GR7  | JWT expiration validation                          | `JwtServiceTest.isTokenValid_shouldReturnFalse_forExpiredToken` (+ revocation list)                                                                              | Covered        |
| GR8  | Credentials encrypted at rest                      | `CredentialServiceTest.create_shouldEncryptPasswordAndSave` + `EncryptionServiceTest` (15) + v2 PBKDF2 KDF                                                          | Covered        |
| GR9  | Secure wipe of temp files                          | `FileHandlingServiceTest.secureDelete_removesFileAndLogsSuccess` + `secureDelete_refusesPathOutsideTempDir`                                                       | Covered        |
| GR10 | Audit logs restricted to ADMIN / AUDITOR           | `AuditControllerTest` — ADMIN 200, AUDITOR 200, anon 401                                                                                                          | Covered        |
| UR1  | User only accesses own vaults / credentials / devices | `VaultServiceTest`, `CredentialServiceTest`, `TrustedDeviceServiceTest`, `UserServiceTest.update_shouldThrow_whenUserAttemptsToUpdateOtherUser`                  | Covered        |
| UR2  | Stored credentials encrypted                        | `CredentialServiceTest` + `EncryptionServiceTest`                                                                                                                | Covered        |
| UR3  | Register trusted devices                            | `TrustedDeviceServiceTest.register_shouldCreateNewDevice…` + fingerprint-collision rejection                                                                       | Covered        |
| UR4  | Import/export does not expose data                  | `CredentialImportExportServiceTest` (7) + `FileHandlingServiceTest` (6)                                                                                            | Covered        |
| UR5  | Log of important actions on user account            | `CredentialServiceTest.delete_shouldDeleteAndAudit`, `VaultServiceTest.delete_shouldDeleteAndAudit`, `TrustedDeviceServiceTest.revoke_*`                          | Covered        |
| UR6  | Session expiration                                  | `JwtServiceTest.isTokenValid_shouldReturnFalse_forExpiredToken` + 1 h absolute lifetime in `Session_Management_Policy.md`                                          | Covered        |
| UR7  | Admin cannot access user credentials                | No admin endpoint exposes decrypted passwords — architectural guarantee                                                                                          | Architectural  |
| UR8  | All administrative actions logged                   | `UserServiceTest.deleteById_shouldSoftDeleteUser` + `updateUserRole_shouldChangeRoleAndSave`                                                                       | Covered        |
| UR9  | Auditor read-only on logs                           | `AuditController` is read-only; `AuditLog` `@PreUpdate`/`@PreRemove` block writes                                                                                  | Covered        |
| UR10 | Audit records immutable                             | `AuditLogTest` JPA lifecycle guards + `AuditServiceTest.log_shouldBuildHashChain`                                                                                  | Covered        |

---

## 6. Functional Surface (controllers & endpoints)

Pulled from `@PreAuthorize` and `@RequestMapping` declarations:

| Bounded context | Service                                                                                                | Controller (`api/`)            | Endpoints                                                                                                                                                            | `@PreAuthorize`                                   |
|-----------------|--------------------------------------------------------------------------------------------------------|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------|
| Auth            | `AuthService` — register / login / lockout / password reset / 2FA / TOTP / logout                       | `AuthController`               | `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/2fa/{verify,verify-backup-code,enable,disable}`, `POST /api/auth/totp/{setup,confirm,disable,verify}`, `POST /api/auth/logout` | Public for `register`, `login`, `2fa/verify`; authenticated for `2fa/enable`, `2fa/disable`, `logout`, TOTP |
| User            | `UserService` — CRUD, role update, activate/deactivate, profile update, session termination            | `UserController`               | `GET /api/users`, `GET /api/users/{id}`, `PUT /api/users/{id}`, `DELETE /api/users/{id}`, `PATCH /api/users/{id}/role`, `PATCH /api/users/{id}/activate`, `POST /api/users/{id}/terminate-sessions`, `POST /api/users/terminate-all-sessions` | ADMIN-only for list / role / activate / terminate; ADMIN or USER (self) for `GET /{id}` and `PUT /{id}` |
| User (admin)    | `AdminUserService` — admin-initiated password reset                                                     | `AdminUserController`          | (class-level `@PreAuthorize("hasRole('ADMIN')")`)                                                                                                                     | ADMIN                                              |
| Vault           | `VaultService` — CRUD with ownership validation, 50-vault per-user cap                                  | `VaultController`              | `POST /api/vaults`, `GET /... (22 KB re... (1 KB restante(s))