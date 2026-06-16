# Security Logging and Monitoring Policy

This document provides a formal inventory of the logging performed at each layer of the Kryptos application's technology stack, detailing the events logged, formats, storage, access control, and retention to fulfill ASVS V16 (Architecture, Design and Threat Modeling - Security Logging and Monitoring) requirements.

## 1. Application Layer Logs (Spring Boot)
The Spring Boot backend generates application-level and access logs.

*   **Events Logged:** Application startup/shutdown events, unhandled exceptions, HTTP access logs (via container/embedded Tomcat), and general debug/info messages.
*   **Format:** Standard Spring Boot log format (Timestamp, Log Level, Thread, Logger, Message). 
*   **Storage:** Output to standard out (`stdout`) / standard error (`stderr`) following 12-factor app principles, intended to be aggregated by container orchestration tools (e.g., Docker daemon, ELK stack, or AWS CloudWatch).
*   **Access Control:** Access is restricted to infrastructure and DevOps administrators who manage the hosting environment.
*   **Retention:** Typically retained for 30 to 90 days depending on the cloud provider's logging infrastructure policy.

## 2. Security Audit Logs (Kryptos AuditService)
Kryptos implements a dedicated, high-fidelity security audit logging mechanism for all sensitive business and security events.

### 2.1 Logged Events Inventory (V16.1.1, V16.2.1, V16.3.1, V16.3.2, V16.3.3)
All of the following events are explicitly tracked and stored via the `AuditService`:

**Authentication & Session Management**
*   `LOGIN`: Successful user authentication.
*   `LOGIN_FAILED`: Failed login attempts (invalid credentials, rate-limited, etc.).
*   `LOGOUT`: User explicitly terminating their session.
*   `REGISTER`: New account registrations.
*   `PASSWORD_RESET_REQUESTED` & `PASSWORD_RESET_COMPLETED`: Account recovery lifecycle.

**Authorization & Access Control**
*   `ACCESS_DENIED_VAULT`: Denied attempt to access or mutate a Vault.
*   `ACCESS_DENIED_CREDENTIAL`: Denied attempt to access or mutate a Credential.

**High-Risk Data Operations & File Handling**
*   `EXPORT`: Successful export of the user's vault data.
*   `IMPORT`: Successful import of vault data.
*   `SECURE_WIPE`: Successful cryptographically secure wipe of user data.
*   `SECURE_WIPE_FAILED`: Failed attempt to perform a secure wipe.

**Resource Management (Vaults, Credentials, Devices, Users)**
*   `CREDENTIAL_CREATE`, `CREDENTIAL_UPDATE`, `CREDENTIAL_DELETE`: Modifications to credentials.
*   `VAULT_CREATE`, `VAULT_UPDATE`, `VAULT_DELETE`: Modifications to vaults.
*   `DEVICE_REGISTER`, `DEVICE_UPDATE`, `DEVICE_REVOKE`: Trusted device management.
*   `USER_DELETE`, `USER_ROLE_UPDATE`, `USER_PROFILE_UPDATE`: User account and profile mutations.

### 2.2 Format and Content
Audit logs are highly structured and are recorded in the relational database. Each entry captures:
*   **Timestamp:** Exact date and time of the event.
*   **Action:** The specific event type (from the inventory above).
*   **Principal/User:** The identity (username/ID) of the user performing the action.
*   **Context/Target:** The module, IP address, device context, or target entity affected.
*   **Description:** Additional metadata surrounding the success/failure state of the action.

*Important Note: Log entries never contain sensitive data such as plaintext passwords, master keys, session tokens, or decrypted credential payloads.*

### 2.3 Storage and Access Control
*   **Storage:** Audit records are persisted in the Kryptos PostgreSQL database within the `audit_logs` table.
*   **Access Control:** The application logic provides **append-only** access to the `audit_logs` table via the `AuditService`. The application does not expose any API endpoints to delete or modify audit logs. Direct read access to the database table is restricted to authorized Database Administrators (DBAs).

### 2.4 Retention
*   **Retention Policy:** Security audit logs are kept indefinitely within the active database by default. For production environments, older logs (e.g., > 1 year) should be safely archived to cold storage to comply with forensic readiness and compliance requirements, whilst maintaining query performance on the main database.
