# Kryptos — V13 Configuration Security Documentation

## V13.1.1 — Application Communication Needs

### External Communication Channels

| Channel | Protocol | Destination | Port | Purpose |
|---------|----------|-------------|------|---------|
| REST API | HTTPS (TLS 1.2+) | Clients (browser/mobile) | 8080 (behind reverse proxy on 443) | Primary application API |
| PostgreSQL | TCP (TLS recommended) | `DB_URL` (default: localhost:5432) | 5432 | Persistent data storage |
| SMTP | STARTTLS | `MAIL_HOST` (default: sandbox.smtp.mailtrap.io) | 25/587 | Email delivery (password reset, 2FA) |

### Internal Communication

- **JPA/Hibernate → PostgreSQL**: Connection pool via HikariCP. All credential data encrypted at application layer (AES-256-GCM) before storage.
- **EncryptionService**: Isolated service handling all cryptographic operations. No external calls.
- **AuditService**: Internal logging of security-relevant events to the database.

---

## V13.1.2 — Maximum Concurrent Connections

| Resource | Max Connections | Behaviour When Limit Reached |
|----------|----------------|------------------------------|
| HikariCP DB Pool | 10 (configurable via `HIKARI_MAX_POOL`) | Requests queue for up to 30s (`connection-timeout`), then fail with timeout exception |
| Minimum Idle Connections | 2 (`HIKARI_MIN_IDLE`) | Pool maintains at least 2 ready connections |
| SMTP | 1 per email send (synchronous) | Mail send blocks until SMTP server responds or timeout (10s) |
| HTTP API | Limited by Tomcat thread pool (default 200) | Requests queued; 429 returned by rate limiter for import/export endpoints |

---

## V13.1.3 — Resource Management Strategies

### Database Connections
- **Connection timeout**: 30,000ms — maximum wait for a connection from the pool
- **Idle timeout**: 600,000ms (10 min) — idle connections closed after this period
- **Max lifetime**: 1,800,000ms (30 min) — connections recycled to prevent stale connections
- **Leak detection**: 60,000ms — warns if a connection is held longer than 60s

### SMTP
- **Connection timeout**: 10,000ms
- **Read timeout**: 10,000ms
- **Write timeout**: 10,000ms
- **Retry strategy**: No automatic retry. Failed email sends are logged via AuditService. Manual retry by user (e.g., re-request password reset).

### Import/Export Rate Limiting
- Per-user rate limiting via `ImportExportRateLimiter`
- Prevents abuse of file import/export endpoints
- Returns HTTP 429 when exceeded

---

## V13.1.4 — Secrets Inventory and Rotation Schedule

| Secret | Storage | Rotation Schedule | Notes |
|--------|---------|-------------------|-------|
| `JWT_SECRET` | Environment variable | Every 90 days | Min 256 bits. Invalidates all active sessions on rotation. |
| `ENCRYPTION_SECRET` | Environment variable | Every 180 days | Used to derive AES-256 key. Rotation requires re-encryption of all vault data. |
| `DB_PASSWORD` | Environment variable | Every 90 days | Must not be a default value. Production validator blocks startup if default. |
| `MAIL_USERNAME` / `MAIL_PASSWORD` | Environment variable | Per provider policy | SMTP credentials for transactional email. |

### Rotation Procedure
1. Generate new secret value (min 256 bits, cryptographically random)
2. Update environment variable in deployment configuration (e.g., Docker secrets, cloud vault)
3. For `ENCRYPTION_SECRET`: run data migration to re-encrypt existing vault entries
4. For `JWT_SECRET`: all active sessions will be invalidated (users must re-authenticate)
5. Restart application instances
6. Verify via logs that `ProductionSecurityValidator` passes

---

## V13.2.1 — Backend Communication Authentication

- **Database**: Authenticated via username/password credentials from environment variables. Connection string uses PostgreSQL native authentication.
- **SMTP**: Authenticated via `MAIL_USERNAME`/`MAIL_PASSWORD` with STARTTLS.
- **Inter-service**: N/A — Kryptos is a monolithic application. No service-to-service calls.

## V13.2.2 — Least Privilege Backend Accounts

The database account configured via `DB_USERNAME` should have **only** the following permissions:

```sql
-- Production database user setup
CREATE USER kryptos_app WITH PASSWORD '<strong-random-password>';
GRANT CONNECT ON DATABASE kryptos TO kryptos_app;
GRANT USAGE ON SCHEMA public TO kryptos_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kryptos_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kryptos_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kryptos_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO kryptos_app;

-- Explicitly DENY dangerous operations
-- kryptos_app must NOT have: CREATE, DROP, ALTER, GRANT, TRUNCATE, REFERENCES, TRIGGER
```

## V13.2.4 / V13.2.5 — Allowlist of External Resources

The application uses `OutboundConnectionValidator` to enforce an allowlist of external hosts.

**Configured via**: `kryptos.security.allowed-external-hosts` (comma-separated)

**Default allowlist**:
- `sandbox.smtp.mailtrap.io` — SMTP email delivery

**SSRF Protections**:
- Blocks connections to private IP ranges (10.x, 172.16-31.x, 192.168.x)
- Blocks loopback addresses (127.0.0.1, ::1)
- Blocks link-local addresses (169.254.x)
- Validates hostname resolution before connection

**File upload destinations**:
- All imported files are stored exclusively in `kryptos.storage.temp-dir`
- Path traversal protection via `FileHandlingService.verifyWithinTempDir()`
- File permissions restricted to owner-only (POSIX 600)

---

## V13.3.1 — Secret Management Strategy

### Current Implementation
Secrets are managed via **environment variables**, injected at runtime through:
- Docker Compose `environment` section (referencing `.env` file)
- CI/CD pipeline secrets (GitHub Actions secrets)

### Production Requirements
- Secrets MUST NOT be committed to source control (`.env` is in `.gitignore`)
- `ProductionSecurityValidator` blocks startup if default/weak values are detected
- `.env.example` provides a template with placeholder values only

### Recommended Production Setup
For production deployments, upgrade to a dedicated secret management solution:
- **Docker Swarm**: Use Docker Secrets (`docker secret create`)
- **Kubernetes**: Use Kubernetes Secrets with encryption at rest
- **Cloud**: AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager
- **Self-hosted**: HashiCorp Vault

### V13.3.2 — Least Privilege Access to Secrets
- `JWT_SECRET`: Only accessed by `JwtService`
- `ENCRYPTION_SECRET`: Only accessed by `EncryptionService`
- `DB_PASSWORD`: Only accessed by Spring DataSource auto-configuration
- `MAIL_PASSWORD`: Only accessed by Spring Mail auto-configuration

Each secret is injected via `@Value` into exactly the component that needs it. No global secret store accessible to all components.

### V13.3.3 — Isolated Cryptographic Module
`EncryptionService` is a dedicated, final Spring `@Service` that:
- Encapsulates all AES-256-GCM encrypt/decrypt operations
- Holds the derived key in a private, immutable field
- Never exposes the raw key material
- Uses `SecureRandom` for IV generation
- Fails securely with generic `EncryptionException` (no oracle leaks)

---

## V13.4 — Unintended Information Leakage Controls

| Control | ASVS ID | Implementation |
|---------|---------|----------------|
| No `.git` in Docker image | V13.4.1 | `.dockerignore` excludes `.git`, `.env`, `target/`, IDE files |
| Debug disabled in prod | V13.4.2 | `application-prod.properties`: `show-sql=false`, `ddl-auto=validate`, no stack traces |
| No directory listing | V13.4.3 | `StaticResourceSecurityConfig` disables static resource handlers |
| TRACE disabled | V13.4.4 | `StrictHttpFirewall` allowlist only permits GET/POST/PUT/DELETE/PATCH/OPTIONS + `ServerHardeningConfig` filter |
| Swagger protected | V13.4.5 | Disabled in prod profile (`springdoc.*.enabled=false`); SecurityConfig blocks in prod |
| No version headers | V13.4.6 | `ServerHardeningConfig` strips `Server` and `X-Powered-By` headers |
| Extension allowlist | V13.4.7 | `StaticResourceSecurityConfig` blocks `.properties`, `.yml`, `.env`, `.java`, `.key`, etc. |
