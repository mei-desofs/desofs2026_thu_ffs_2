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



From: https://owasp.org/www-project-web-security-testing-guide/stable/