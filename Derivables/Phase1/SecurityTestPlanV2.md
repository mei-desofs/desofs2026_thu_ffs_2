# Security Test Plan

## 1. Objectives

The primary objective of this Security Test Plan is to validate the effectiveness of the mitigations proposed in the Threat Model (Phase 1) by defining concrete, executable test scenarios.

Instead of relying on manual verification, Kryptos aims to integrate these security tests into an automated DevSecOps CI/CD pipeline using a combination of:

- **Unit & Integration Tests:** To validate business logic, RBAC, and boundary constraints.
- **Static Application Security Testing (SAST):** To catch vulnerable code patterns (e.g., hardcoded secrets, weak cryptographic algorithms).
- **Dynamic Application Security Testing (DAST):** To test the running API against common attack vectors (e.g., SQLi, XSS, Path Traversal).

So, we propose the following objectives:

- Validate the security of Kryptos according to OWASP.

- Identify vulnerabilities in authentication, authorization, cryptography, file handling, and business logic.

- Ensure secure handling of sensitive data (credentials, vaults, trusted devices).

- Validate secure import/export operations and temporary file management.

- Confirm audit logging integrity and role‑based access control (RBAC).

## 2. Scope of Testing

- **In-Scope:**
  - Kryptos REST API Endpoints;
  - JWT Authentication mechanisms;
  - Role-Based Access Control (RBAC);
  - File I/O operations (Import/Export);
  - Vault, Credential, Trusted Device aggregates;
  - Database access layers;
  - Cryptographic implementations;
  - Audit logging;
  - Server‑side file system interactions.
- **Out-of-Scope:** Client-side frontend applications and Third-party services not directly integrated.

## 3. Testing Methodology

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

---

## 4. Threat-to-Test Traceability Matrix

This matrix maps the identified risks (**R01–R20**) and their architectural mitigations to specific test scenarios. These scenarios will guide the creation of automated tests during the Phase 2 CI/CD pipeline implementation.

### Authentication & Identity Management

| Threat ID | Threat Description | Specific Mitigation | Test Scenario / Objective | Test Type |
| --- | --- | --- | --- | --- |
| **R01** | Brute Force / Credential Stuffing | Implement rate limiting (max 5 attempts/min) on `/api/auth/login`. | Simulate 6 rapid failed logins and verify the API blocks the 6th with a `429 Too Many Requests`. | Integration / DAST |
| **R02** | JWT Manipulation (EoP) | Enforce strong signature verification and reject tokens using the `none` algorithm. | Submit an API request using a JWT where the signature algorithm is explicitly set to `none` and assert a `401 Unauthorized`. | Unit |
| **R03** | Credentials Exposed in Rest | Encrypt passwords using Argon2 and Vaults using AES-GCM. | Inspect a mock database dump during tests to ensure no fields in the `credentials` or `users` tables contain plaintext passwords. | Integration |
| **R17** | Rogue Device Registration | Require re-authentication before associating a new trusted device. | Attempt to register a device using a session token that is older than the required MFA/re-auth timeout window. | Integration |
| **R19** | Session Hijacking for Vault Export | Enforce short token expiry and strict validation. | Attempt to trigger an export using a JWT that expired 1 second ago and assert it is rejected. | Unit |

### Authorization & Access Control (RBAC & IDOR)

| Threat ID | Threat Description | Specific Mitigation | Test Scenario / Objective | Test Type |
| --- | --- | --- | --- | --- |
| **R04** | Privilege Escalation (Mass Assignment) | Ignore the `role` field in user update payloads; require Admin endpoint for role changes. | Send a `PUT /api/users/me` request injecting `"role": "admin"` and verify the user's role remains unchanged. | Integration |
| **R05** | IDOR on Credential Endpoints | Validate that the `user_id` of the authenticated token matches the owner of the requested credential. | Authenticate as User A, request a specific Credential ID owned by User B, and verify the API returns `403 Forbidden`. | Integration |
| **R07** | IDOR on Vault Endpoints | Validate vault ownership on `GET/PUT/DELETE` requests. | Authenticate as User A, attempt to `DELETE` a Vault ID owned by User B, and verify the vault remains intact. | Integration |
| **R10** | IDOR on Export Endpoint | Validate vault ownership before generating the export file. | Submit an export request specifying a target `vault_id` that does not belong to the active JWT session. | Integration |

### Data Handling, File I/O & OS Interaction

| Threat ID | Threat Description | Specific Mitigation | Test Scenario / Objective | Test Type |
| --- | --- | --- | --- | --- |
| **R08** | Malicious File Upload (Path Traversal) | Strip directory traversal sequences (`../`) from uploaded filenames. | Upload a credential CSV named `../../../etc/passwd` and verify the backend sanitizes it or rejects it with a `400 Bad Request`. | Unit / SAST |
| **R08** | Malicious File Upload (Zip Bomb) | Enforce strict file size limits on the `/api/vaults/import` endpoint. | Attempt to upload a payload exceeding the 5MB limit and assert a `413 Payload Too Large` response. | Integration |
| **R09** | Temporary File Exposed on Disk | Create temp files with strict `0600` OS permissions in an isolated directory. | Trigger an export, pause execution, and check the OS-level file permissions of the generated temp file to ensure it is not `0644` or public. | Integration |
| **R12** | Temporary File Not Securely Wiped | Overwrite file contents with zeros before executing OS `unlink()`. | Trigger a secure wipe, intercept the process before OS deletion, and verify the file blocks are filled with null bytes. | Integration |
| **R13** | Path Traversal in Secure Wipe | Canonicalize paths before passing them to the wipe function. | Pass a relative path (`../system/file`) to the internal wipe utility and assert it throws an `IllegalArgumentException`. | Unit |

### Error Handling & Availability (DoS)

| Threat ID | Threat Description | Specific Mitigation | Test Scenario / Objective | Test Type |
| --- | --- | --- | --- | --- |
| **R06** | Plaintext Credential Leak | Disable stack traces in production; return generic API errors. | Deliberately trigger a decryption failure and assert the JSON response body contains no stack traces or plaintext variables. | DAST / SAST |
| **R11** | Export Endpoint Abuse (DoS) | Rate limit the expensive export endpoint independently of other APIs. | Spam the export endpoint 10 times in one minute and verify the system rate-limits the user to protect database resources. | Integration |
| **R16** | Log Flooding (DoS) | Filter low-priority logs under high load; rate limit generic exceptions. | Simulate a burst of 1,000 bad login requests and verify the database connection pool remains stable and the application does not crash. | Performance |

### Auditing & Cryptographic Integrity

| Threat ID | Threat Description | Specific Mitigation | Test Scenario / Objective | Test Type |
| --- | --- | --- | --- | --- |
| **R14** | Audit Log Tampering | Audit service uses a DB role lacking `DELETE` or `UPDATE` privileges. | Write a test that attempts to execute a `DELETE FROM audit_logs` SQL statement and verify the database strictly rejects it. | Integration |
| **R15** | Log Injection (Log4Shell-like) | Escape CRLF characters in HTTP headers before logging. | Send a request with a `User-Agent` containing `\r\n\r\n<script>alert(1)</script>` and verify the log output safely escapes the characters. | Unit |
| **R18** | Admin Actions Not Logged | Enforce logging aspect/interceptor on all `/api/admin/*` endpoints. | Hit an admin endpoint to suspend a user, then immediately query the audit table to assert a matching event was recorded. | Integration |
| **R20** | Wipe Failure Not Logged | Catch `IOException` during secure wipe and trigger critical alert log. | Mock an OS file-lock during the wipe process to force an exception, and assert that a "Wipe Failed" event appears in the audit log. | Integration |

---

## 5. Pipeline Integration Strategy (Phase 2 Roadmap)

To enforce this test plan, the Phase 2 CI/CD pipeline will be configured with the following quality gates:

1. **Pre-Commit / Build Phase:** Execution of all Unit Tests mapped in the matrix to ensure code-level security functions (like JWT validation and sanitization) are intact.
2. **SAST Scanning:** Integration of static analysis tools to scan the repository for hardcoded secrets, weak cryptographic primitives, and missing input validation.
3. **Integration Phase:** Execution of Integration Tests against an ephemeral test database to validate RBAC, IDOR mitigations, and File I/O cleanup behaviors.
4. **DAST Scanning:** Integration of dynamic testing tools against a staging instance to verify rate limiting, correct error handling, and runtime API vulnerabilities.
