# Security Test Plan

## Objectives
- Validate the security of Kryptos according to OWASP.

- Identify vulnerabilities in authentication, authorization, cryptography, file handling, and business logic.

- Ensure secure handling of sensitive data (credentials, vaults, trusted devices).

- Validate secure import/export operations and temporary file management.

- Confirm audit logging integrity and role‑based access control (RBAC).

## Scope of Testing

### In‑Scope Components 
   
- REST API endpoints
- Authentication & session mechanisms
- Role‑based access control (Admin, User, Auditor)
- Vault, Credential, Trusted Device aggregates
- Import/export file operations
- Database interactions
- Audit logging
- Server‑side file system interactions

### Out‑of‑Scope
- Frontend clients (none exist yet)
- Third‑party services not directly integrated

## Testing Methodology 

### Information Gathering
**Goal:** Identify application structure and attack surface

**Tests:**
- Enumerate API endpoints
- Identify technologies (frameworks, libraries)
- Map application architecture (DDD aggregates)
- Discover hidden endpoints or debug routes


### Configuration and Deployment Testing
**Goal:** Identify misconfigurations in infrastructure

**Tests:**
- Check HTTP headers (HSTS, CSP, CORS)
- Test HTTP methods (PUT, DELETE, OPTIONS abuse)
- Review exposed files (logs, backups)
- Verify secure server configuration


### Identity Management Testing
**Goal:** Validate user lifecycle security

**Tests:**
- User registration validation
- Role assignment correctness (Admin, User, Auditor)
- Account enumeration (error message analysis)
- Username policy enforcement


### Authentication Testing
**Goal:** Ensure secure authentication mechanisms

**Tests:**
- Password policy strength
- Brute-force protection (rate limiting, lockout)
- Token-based authentication (JWT/session)
- Credential transmission over HTTPS
- Authentication bypass attempts


### Authorization Testing
**Goal:** Verify access control enforcement

**Tests:**
- Role-based access control (RBAC) validation
- Horizontal privilege escalation (access other users’ vaults)
- Vertical privilege escalation (user → admin)


### Session Management Testing
**Goal:** Ensure secure session handling

**Tests:**
- Token expiration and renewal
- Session fixation
- Token leakage (logs, URLs)


### Input Validation Testing
**Goal:** Detect injection and validation flaws

**Tests:**
- SQL injection (DB queries)
- Command injection (file system operations)
- Path traversal (import/export directories)
- JSON/XML injection
- File upload validation


### Error Handling Testing
**Goal:** Prevent information leakage

**Tests:**
- Stack traces exposure
- Debug messages in API responses
- Sensitive data leakage in errors


### Cryptography Testing
**Goal:** Validate cryptographic controls

**Tests:**
- Password hashing algorithm 
- Encryption of stored credentials
- Secure key management


### Business Logic Testing
**Goal:** Identify logic flaws specific to Kryptos

**Tests:**
- Vault isolation enforcement
- Credential ownership validation
- Trusted device misuse
- Abuse of import/export workflows
- Replay attacks on API operations


###  File Handling & OS Interaction Testing
**Goal:** Ensure secure file operations and OS interactions

**Tests:**
- Path traversal in import/export
- Insecure temporary file handling
- Secure deletion validation


### API Testing
**Goal:** Validate REST API security

**Tests:**
- Endpoint authentication requirements
- Rate limiting / DoS protection
- Mass assignment vulnerabilities
- Improper HTTP status codes
- JSON schema validation


###  Audit & Logging Testing
**Goal:** Ensure accountability and traceability

**Tests:**
- Log integrity
- Sensitive data exposure in logs
- Coverage of critical actions
- Log injection attacks



## Traceability Matrix

The following matrix maps each security requirement (from [SystemOverview.md](./SystemOverview.md#security-requirements)) to the test categories defined in this plan that validate it.

**Requirement ID notation:**
- **GR** (General Requirement) — the 10 technical security controls applicable to all endpoints and system components (e.g. RBAC enforcement, password hashing, JWT validation)
- **UR** (User Requirement) — the 10 role-based security user stories expressing expectations from Common Users, Administrators, and Auditors

| Req ID | Security Requirement | Test Categories |
|--------|----------------------|-----------------|
| GR1 | All endpoints must enforce authentication and validate roles via RBAC | Authorization Testing · API Testing |
| GR2 | All endpoints must validate and sanitize input data | Input Validation Testing · API Testing |
| GR3 | All endpoints must use HTTPS/TLS — unencrypted connections must be rejected | Configuration and Deployment Testing · Cryptography Testing |
| GR4 | All failed authentication attempts must be logged | Authentication Testing · Audit & Logging Testing |
| GR5 | Rate limiting must be applied to sensitive endpoints | Authentication Testing · API Testing |
| GR6 | Passwords must be stored using a strong hashing algorithm (bcrypt or Argon2) | Cryptography Testing |
| GR7 | JWT tokens must have defined expiration times and be validated on every request | Authentication Testing · Session Management Testing |
| GR8 | Credentials must be encrypted at rest before being stored in the database | Cryptography Testing · Business Logic Testing |
| GR9 | Temporary files created during import/export must be securely wiped after use | File Handling & OS Interaction Testing · Business Logic Testing |
| GR10 | Access to audit logs must be restricted to Auditor or Administrator role | Authorization Testing · Audit & Logging Testing |
| UR1 | Common User can only access their own vaults, credentials, and trusted devices | Authorization Testing · Business Logic Testing |
| UR2 | Stored credentials must be encrypted (protected against database breach) | Cryptography Testing |
| UR3 | User can register trusted devices to control access | Identity Management Testing · Authorization Testing |
| UR4 | Import/export must not expose sensitive data during the process | File Handling & OS Interaction Testing · Cryptography Testing |
| UR5 | Log of important actions performed on user account | Audit & Logging Testing |
| UR6 | Session must expire after a defined period of inactivity | Session Management Testing |
| UR7 | Administrator cannot access individual users' stored credentials | Authorization Testing · Business Logic Testing |
| UR8 | All administrative actions must be logged | Audit & Logging Testing |
| UR9 | Auditor can consult logs without modifying them or accessing credential data | Authorization Testing · Audit & Logging Testing |
| UR10 | Audit records must be immutable | Audit & Logging Testing |

### Requirement Coverage by Test Category

| Test Category | Requirements Covered |
|---------------|----------------------|
| Authentication Testing | GR4, GR5, GR7 |
| Authorization Testing | GR1, GR10, UR1, UR3, UR7, UR9 |
| Session Management Testing | GR7, UR6 |
| Input Validation Testing | GR2 |
| Cryptography Testing | GR3, GR6, GR8, UR2, UR4 |
| Configuration and Deployment Testing | GR3 |
| Business Logic Testing | GR8, GR9, UR1, UR4, UR7 |
| File Handling & OS Interaction Testing | GR9, UR4 |
| Audit & Logging Testing | GR4, GR10, UR5, UR8, UR9, UR10 |
| Identity Management Testing | UR3 |
| API Testing | GR1, GR2, GR5 |
| Error Handling Testing | GR2 |

From: https://owasp.org/www-project-web-security-testing-guide/stable/