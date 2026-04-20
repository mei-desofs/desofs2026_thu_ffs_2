# STRIDE

## Threat List

### User Authentication

| DFD Element                             | STRIDE                     | Threats Across Data Flow                                                                                               | Abuse Case                            |
|-----------------------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
| **External Entity:** Anonymous User     | **Spoofing**               | Attacker pretends to be a user using stolen credentials, API, or database (e.g., stolen credentials, fake services).   | **Brute Force / Credential Stuffing** |
| **Data Flow:** Submit Login Credentials | **Tampering**              | Data (credentials, queries, tokens) is modified during transmission or processing.                                     | **Session Fixation**                  |
| **Process:** Authentication Process     | **Repudiation**            | Actions cannot be traced because of missing or insufficient logging.                                                   | ---                                   |
| **Data Store:** User DB                 | **Information Disclosure** | Sensitive data (credentials, tokens, hashes) is exposed to unauthorized parties.                                       | ---                                   |
| **Process:** Authentication Process     | **Denial of Service**      | Login system or database is overwhelmed, making authentication unavailable.                                            | **Brute Force / Credential Stuffing** |
| **Data Flow:** JWT Token                | **Elevation of Privilege** | Attacker manipulates the token payload to gain higher access (e.g., admin rights) through stolen data or system flaws. | **JWT Manipulation**                  |

### User Management

| DFD Element                            | STRIDE                     | Threats Across Data Flow                                                                                  | Abuse Case               |
|----------------------------------------|----------------------------|-----------------------------------------------------------------------------------------------------------|--------------------------|
| **External Entity:** User              | **Spoofing**               | Attacker impersonates an admin, API, or database (e.g., stolen admin credentials, fake services).         | **Admin Account Takeover** |
| **Data Flow:** User Management Request | **Tampering**              | User management requests or database queries are modified (e.g., changing roles or permissions).          | ---                        |
| **Process:** Backend API               | **Repudiation**            | Admin actions cannot be verified due to missing or insufficient logging.                                  | ---                        |
| **Data Store:** User DB                | **Information Disclosure** | Sensitive user data (e.g., roles, emails) is exposed to unauthorized parties.                             | **Profile Data Scraping**  |
| **Process:** Backend API               | **Denial of Service**      | User management endpoints or database are overloaded, preventing admin operations.                        | **Mass Account Lockout**   |
| **Process:** Backend API               | **Elevation of Privilege** | Unauthorized users gain higher roles (e.g., becoming admin) through manipulated requests or system flaws. | **Privilege Escalation** |

### Vault Management

| DFD Element                             | STRIDE                     | Threats Across Data Flow                                                                                                                                                                     | Abuse Case                       |
|-----------------------------------------|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| **External Entity:** User               | **Spoofing**               | Attacker impersonates a legitimate user (via stolen JWT, session hijacking, or forged API requests) to access or manipulate vaults that do not belong to them.                               | ---                              |
| **Data Flow:** Vault Management Request | **Tampering**              | Vault requests are modified in transit to alter names, descriptions, or ownership; attacker rewrites vault records in the database or bypasses ownership checks to edit other users' vaults. | **Vault Metadata Injection**     |
| **Process:** Vault Management Process   | **Repudiation**            | Vault creation, update, or deletion events are not logged (or are logged without user/device context), allowing a user to deny having performed destructive actions.                         | ---                              |
| **Data Flow:** Query / Store Vault      | **Information Disclosure** | Vault metadata (names, descriptions, owner identifiers) is exposed to unauthorized users due to missing or incorrect authorization checks (IDOR on `/vaults/{id}`).                          | **Unauthorized Vault Deletion**  |
| **Process:** Vault Management Process   | **Denial of Service**      | Attacker abuses create/delete endpoints (mass vault creation, cascading deletes) to exhaust storage, saturate database connections, or lock tables.                                          | **Resource Exhaustion**          |
| **Process:** Vault Management Process   | **Elevation of Privilege** | Attacker bypasses role checks (e.g., uses a Regular User token to call admin-only vault endpoints) to manage vaults belonging to other users.                                                | **Unauthorized Vault Deletion**  |

### Credential Management

| DFD Element                                | STRIDE                     | Threats Across Data Flow                                                                                                                                                                                                               | Abuse Case                         |
|--------------------------------------------|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| **External Entity:** User                  | **Spoofing**               | Attacker uses stolen tokens or session cookies to read, modify, or delete credentials stored in another user's vault.                                                                                                                  | **Malicious Deletion**             |
| **Process:** Credential Management Process | **Tampering**              | Ciphertext is modified in transit or at rest (without authenticated encryption), leading to corrupted credentials that may decrypt into attacker-controlled plaintext; request payloads are tampered with to inject malicious content. | **Credential Tampering**           |
| **Process:** Credential Management Process | **Repudiation**            | Credential reads (especially decrypted reveals) and modifications are not logged or are logged without sufficient context, allowing a user to deny exfiltration.                                                                       | ---                                |
| **Data Store:** Credential DB              | **Information Disclosure** | Plaintext credentials leak via error messages, debug logs, memory dumps, or insecure responses; encryption keys are exposed via the key store or application memory; IDOR allows fetching another user's credentials.                  | **Mass Data Exfiltration**         |
| **Process:** Credential Management Process | **Denial of Service**      | Brute-force or enumeration requests on credential endpoints saturate the decryption service; repeated malformed ciphertext triggers expensive error paths.                                                                             | ---                                |
| **Data Flow:** Verify Vault Ownership      | **Elevation of Privilege** | Attacker who compromises one account moves laterally by exfiltrating credentials that grant access to other systems (credential reuse), or exploits missing authorization to read credentials from other users' vaults.                | **Unauthorized Credential Access** |

### Trusted Devices Management

| DFD Element                                      | STRIDE                       | Threats Across Data Flow                                                                                                                                   | Abuse Case                    |
|--------------------------------------------------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
| **External Entity:** User                        | **Spoofing**                 | Attacker steals an active session token (e.g., via Man-in-the-Middle or XSS) and impersonates the user to register their own device as trusted.            | **Rogue Device Registration** |
| **Data Flow:** Device Management Request         | **Tampering**                | Device registration payload (e.g., device ID, public key, or fingerprint) is modified in transit to alter the device binding.                              | ---                           |
| **Process:** Trusted Device Management Process   | **Repudiation**              | The registration or removal of a trusted device is not logged, allowing an attacker (or user) to deny that a new device was authorized.                    | ---                           |
| **Data Store:** Trusted Device (DB)              | **Information Disclosure**   | Device metadata, user associations, or potentially cryptographic material used for trust binding are exposed via insecure API responses or database dumps. | ---                           |
| **Process:** Trusted Device Management Process   | **Denial of Service**        | Attacker repeatedly sends bogus device registration requests to overwhelm the database or exhaust the maximum allowed devices per user.                    | **Unauthorized Device Removal** |
| **Process:** Trusted Device Management Process   | **Elevation of Privilege**   | Attacker manipulates the request to bind a device to a different user's account by exploiting an IDOR vulnerability, bypassing standard MFA challenges.    | **Rogue Device Registration** |

### Import Vault

| DFD Element                                       | STRIDE                     | Threats Across Data Flow                                                                                                                                                                    | Abuse Case                |
|---------------------------------------------------|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|
| **External Entity:** User                         | **Spoofing**               | Attacker uses a stolen session token to upload a credential file into a victim's account, potentially overwriting legitimate data.                                                          | ---                       |
| **Process:** Validate Imported Data               | **Tampering**              | The uploaded file contains malicious payloads (e.g., XSS in the username fields or Path Traversal characters like ../../../) to manipulate the system or other users when parsed.           | **Malicious File Upload** |
| **Process:** Log Import Operation                 | **Repudiation**            | The import action is not logged properly, allowing a malicious insider to upload compromised credentials and later deny having performed the action.                                        | ---                       |
| **Data Store:** Temporary file (OS / File System) | **Information Disclosure** | The temporary file containing unencrypted credentials is saved to the server's disk without strict read/write permissions, allowing other system processes to access it before it is wiped. | ---                       |
| **Process:** Receive Import File                  | **Denial of Service**      | Attacker uploads a massive file (e.g., a 50GB CSV or a Zip Bomb) to exhaust server memory, CPU during parsing, or disk space.                                                               | **Malicious File Upload** |
| **Process:** Persist credentials                  | **Elevation of Privilege** | Attacker manipulates the API request parameters alongside the file upload to force the system to import the credentials into a Vault ID they do not own (IDOR vulnerability).               | ---                       |

### Export Vault

| DFD Element                                       | STRIDE                     | Threats Across Data Flow                                                                                                                                                           | Abuse Case                     |
|---------------------------------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| **External Entity:** User                         | **Spoofing**               | Attacker uses a stolen session token or hijacked session to request a full export of the victim's vault.                                                                           | ---                            |
| **Data Flow:** Vault Exported                     | **Tampering**              | The exported file is intercepted and modified in transit (e.g., injecting malicious URLs into the credentials) before reaching the user's machine.                                 | ---                            |
| **Process:** Log Export Operation                 | **Repudiation**            | A massive data exfiltration (vault download) occurs but is not logged, preventing administrators from tracing the data leak back to the compromised account.                       | ---                            |
| **Data Store:** Temporary file (OS / File System) | **Information Disclosure** | The generated export file containing sensitive credentials is saved to a shared OS directory without strict read restrictions, allowing other internal processes/users to read it. | **Export Data Leakage**        |
| **Process:** Generate Export File                 | **Denial of Service**      | Attacker repeatedly spams the export endpoint, forcing the server to continuously query the database and exhaust CPU/Memory by formatting large export files.                      | ---                            |
| **Process:** Retrieve Credentials                 | **Elevation of Privilege** | Attacker manipulates the Vault Export Request parameter to specify a Vault ID they do not own (IDOR), bypassing authorization to extract another user's entire vault.              | **Extract Unauthorized Vault** |

### System Audit Log

| DFD Element                     | STRIDE                     | Threats Across Data Flow                                                                                                                   | Abuse Case                |
|---------------------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|
| **Process:** Write Audit Logs   | **Spoofing**               | Attacker spoofs an internal system service to inject fake log events (e.g., faking a successful login to cover tracks).                    | ---                       |
| **Data Store:** Audit Logs (DB) | **Tampering**              | A compromised admin or attacker alters, truncates, or deletes existing log entries to hide evidence of malicious activity.                 | **Audit Log Tampering**   |
| **Process:** Write Audit Logs   | **Repudiation**            | The logging process fails silently or drops events under heavy load, meaning critical system actions are not recorded.                     | ---                       |
| **Data Store:** Audit Logs (DB) | **Information Disclosure** | The log database inadvertently stores sensitive data (e.g., plaintext passwords or session tokens) and is exposed to unauthorized staff.   | ---                       |
| **Process:** Write Audit Logs   | **Denial of Service**      | Attacker floods the API with invalid requests to intentionally generate millions of log entries, exhausting disk space (Log Flooding).     | ---                       |
| **Process:** Write Audit Logs   | **Elevation of Privilege** | Attacker injects executable scripts or malicious payloads into the logs (e.g., similar to Log4Shell) to exploit the log viewing dashboard. | **Log Injection / False Trails** |

### Secure Wipe Temporary Files

| DFD Element                              | STRIDE                     | Threats Across Data Flow                                                                                                                                                            | Abuse Case |
|------------------------------------------|----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------|
| **Data Flow:** Wipe request              | **Spoofing**               | Attacker spoofs a wipe command to delete the temporary files prematurely, corrupting the ongoing Import/Export operation.                                                           | ---        |
| **Data Flow:** Secure delete request     | **Tampering**              | The deletion command is intercepted or blocked at the OS level, preventing the actual wipe from executing.                                                                          | ---        |
| **Data Flow:** Secure wipe event         | **Repudiation**            | The wipe process fails (e.g., due to file locks) but fails to send an error event to the Audit Log, silently leaving sensitive data on disk.                                        | ---        |
| **Data Store:** Temporary Files          | **Information Disclosure** | Files are deleted using standard OS deletion (removing the pointer) instead of cryptographic secure wiping (overwriting with zeros), allowing data recovery tools to extract them.  | ---        |
| **Data Store:** Temporary Files          | **Denial of Service**      | Attacker deliberately holds an OS-level lock on the temporary file, causing the secure wipe background job to hang or crash.                                                        | ---        |
| **Process:** Secure Wipe Temporary Files | **Elevation of Privilege** | Attacker manipulates the file path variable to trick the high-privileged secure wipe process into deleting critical system files instead of the temporary payload (Path Traversal). | ---        |


## Abuse Case Diagrams

### User Authentication
![Authentication Abuse Cases](./images/abuse-cases/authentication-abuse/authentication-abuse-case.png)

The login flow is threatened by **Brute Force / Credential Stuffing**, **Session Fixation**, and **JWT Manipulation**. Mitigations include rate limiting with account lockout, token rotation on login, and secure JWT validation over TLS.

### User Management / Administration
![Administration Abuse Cases](./images/abuse-cases/administration/administration-abuse-case.png)

Administrative operations are threatened by **Privilege Escalation** (role manipulation), **Profile Data Scraping** (bulk user enumeration), **Mass Account Lockout** (abusing delete/update endpoints), and **Admin Account Takeover**. Mitigations include strict RBAC verification, data pagination, re-authentication for destructive actions, and sensitive field masking in audit logs.

### Vault Management
![Vault Management Abuse Cases](./images/abuse-cases/vault/vault-management.png)

Vault operations are threatened by **Unauthorized Vault Deletion**, **Vault Metadata Injection** (malicious input in update requests), and **Resource Exhaustion**. Mitigations include ownership verification, input sanitization, and creation quotas per user.

### Credential Management
![Credential Management Abuse Cases](./images/abuse-cases/credential-management/credential_management-abuse-case.png)

Credential operations are threatened by **Unauthorized Access**, **Credential Tampering** (modifying ciphertext without authenticated encryption), **Mass Data Exfiltration** (bulk reads via enumeration), and **Malicious Deletion** (removing another user's credentials via stolen token). Mitigations include vault ownership verification, end-to-end encryption, and rate limiting.

### Trusted Device Management
![Trusted Device Abuse Cases](./images/abuse-cases/trusted-device/trusted_device_management-abuse-case.png)

Device management is threatened by **Rogue Device Registration** (attacker registers their own device using a stolen session) and **Unauthorized Device Removal** (attacker removes a legitimate device to lock out the owner). Mitigations include MFA re-authentication before registration or removal, and out-of-band notifications to the user on device changes.

### Import / Export
![Import Export Abuse Cases](./images/abuse-cases/import-export/import_export-abuse-case.png)

The import flow is threatened by **Malicious File Upload** (oversized files, zip bombs, or payloads with path traversal characters). The export flow is threatened by **Export Data Leakage** (unprotected temporary files readable by other processes). Mitigations include strict file schema validation and size limits for import, and encrypted/password-protected output for export.

### Audit Log
![Audit Log Abuse Cases](./images/abuse-cases/audit-log/audit-abuse-case.png)

Audit log operations are threatened by **Audit Log Tampering** (a compromised admin alters or deletes log entries to cover tracks) and **Log Injection / False Trails** (attacker injects malicious payloads into logged fields to exploit the log viewer or forge events). Mitigations include append-only storage with immutability guarantees and log integrity validation on read.


## Threat Tree Analysis

### User Authentication
![User Authentication Threat Tree](./images/threat-tree-analysis/authenticate-users.png)

The root goal is gaining unauthorized access to a user account. Attack paths include credential stuffing via automated tools, brute-forcing weak passwords, stealing session tokens via XSS or MitM, and forging or replaying JWT tokens with manipulated claims.

### User Management
![User Management Threat Tree](./images/threat-tree-analysis/manage-users.png)

The root goal is gaining elevated privileges or taking over administrative control. Attack paths include manipulating role assignment requests (privilege escalation), stealing admin credentials, and abusing account management endpoints to lock out legitimate users.

### Vault Management
![Vault Management Threat Tree](./images/threat-tree-analysis/manage-vaults/manage-vaults.png)

The root goal is accessing or destroying vaults that do not belong to the attacker. Attack paths include IDOR on vault endpoints (guessing or enumerating vault IDs), session hijacking to impersonate the vault owner, and injecting malicious metadata through unvalidated update requests.

### Credential Management
![Credential Management Threat Tree](./images/threat-tree-analysis/manage-credentials/manage-credentials.png)

The root goal is reading, modifying, or deleting credentials belonging to other users. Attack paths include IDOR on credential endpoints, tampering with ciphertext to corrupt stored data, exfiltrating credentials via bulk enumeration, and exploiting decryption error paths to leak plaintext values.

### Trusted Devices Management
![Trusted Devices Threat Tree](./images/threat-tree-analysis/manage-trustedDevices/manage-trustedDevices.png)

The root goal is binding a rogue device to a victim's account or removing a legitimate device. Attack paths include stealing an active session token to bypass MFA on device registration, and exploiting missing re-authentication on the remove endpoint to evict trusted devices.

### Import Vault
![Import Vault Threat Tree](./images/threat-tree-analysis/import-vault/import-vault.png)

The root goal is compromising the server or injecting malicious data through the import endpoint. Attack paths include uploading oversized or malformed files (zip bombs, malicious CSVs), injecting path traversal sequences in parsed fields, and targeting a vault the attacker does not own via IDOR on the import request.

### Export Vault
![Export Vault Threat Tree](./images/threat-tree-analysis/export-vault/export-vault.png)

The root goal is obtaining a full export of credentials belonging to another user. Attack paths include IDOR on the export endpoint (specifying another user's vault ID), session hijacking to impersonate the vault owner, and reading the unprotected temporary export file from the server filesystem.

### System Audit Log
![Audit Log Threat Tree](./images/threat-tree-analysis/audit-log/audit-log.png)

The root goal is either destroying evidence of malicious activity or exploiting the log pipeline. Attack paths include tampering with or deleting log entries via a compromised admin account, flooding the log store to exhaust disk space, and injecting executable payloads into logged fields (Log4Shell-style) to exploit the log viewer.

### Secure Wipe Temporary Files
![Secure Wipe Threat Tree](./images/threat-tree-analysis/secure-wipe/secure-wipe-temporary-file.png)

The root goal is leaving sensitive credential data on disk after an import or export operation. Attack paths include holding an OS-level file lock to prevent the wipe from executing, tricking the wipe process into deleting a wrong path via path traversal, and relying on standard OS deletion (which only removes the pointer) to allow data recovery with forensic tools.


## Threat Ranking

Threats are ranked using the **DREAD** risk assessment model. Each threat is scored from 1–10 across five factors:

| Factor | Question |
|--------|----------|
| **D**amage | How big would the damage be if the attack succeeded? |
| **R**eproducibility | How easy is it to reproduce the attack? |
| **E**xploitability | How much effort and expertise is needed to exploit it? |
| **A**ffected Users | What percentage of users would be affected? |
| **D**iscoverability | How easy is it for an attacker to discover this threat? |

**DREAD Score** = (D + R + E + A + Di) / 5 — ranges: High ≥ 7.5 | Medium 5.0–7.4 | Low < 5.0

| Risk ID | Threat | D | R | E | A | Di | Score | Level |
|---------|--------|---|---|---|---|----|-------|-------|
| R01 | Brute Force / Credential Stuffing | 8 | 10 | 9 | 10 | 9 | **9.2** | High |
| R02 | JWT Manipulation (EoP) | 9 | 7 | 6 | 5 | 6 | **6.6** | Medium |
| R03 | Credentials Exposed in Transit or at Rest | 9 | 7 | 6 | 10 | 5 | **7.4** | Medium |
| R04 | Privilege Escalation (role manipulation) | 9 | 6 | 6 | 7 | 5 | **6.6** | Medium |
| R05 | IDOR on Credential Endpoints | 9 | 9 | 9 | 10 | 8 | **9.0** | High |
| R06 | Plaintext Credential Leak | 9 | 6 | 6 | 7 | 5 | **6.6** | Medium |
| R07 | IDOR on Vault Endpoints | 7 | 9 | 8 | 10 | 8 | **8.4** | High |
| R08 | Malicious File Upload | 9 | 8 | 7 | 8 | 7 | **7.8** | High |
| R09 | Temporary File Exposed on Disk | 8 | 6 | 5 | 7 | 4 | **6.0** | Medium |
| R10 | IDOR on Export Endpoint | 9 | 9 | 9 | 10 | 8 | **9.0** | High |
| R11 | Export Endpoint Abuse (DoS) | 6 | 9 | 9 | 10 | 8 | **8.4** | High |
| R12 | Temporary File Not Securely Wiped | 9 | 7 | 6 | 8 | 5 | **7.0** | Medium |
| R13 | Path Traversal in Secure Wipe | 9 | 6 | 6 | 5 | 4 | **6.0** | Medium |
| R14 | Audit Log Tampering / Deletion | 8 | 4 | 4 | 5 | 3 | **4.8** | Low |
| R15 | Log Injection (Log4Shell-like) | 7 | 5 | 5 | 6 | 4 | **5.4** | Medium |
| R16 | Log Flooding (DoS) | 5 | 9 | 9 | 8 | 7 | **7.6** | High |
| R17 | Rogue Device Registration | 7 | 6 | 6 | 5 | 5 | **5.8** | Medium |
| R18 | Admin Actions Not Logged | 6 | 5 | 4 | 7 | 3 | **5.0** | Medium |
| R19 | Session Hijacking for Vault Export | 8 | 6 | 6 | 5 | 6 | **6.2** | Medium |
| R20 | Wipe Failure Not Logged | 7 | 6 | 5 | 7 | 3 | **5.6** | Medium |

### DREAD Priority Summary

| Level | Threshold | Count | Threat IDs |
|-------|-----------|-------|------------|
| **High** | Score ≥ 7.5 | 7 | R01, R05, R10, R07, R11, R08, R16 |
| **Medium** | Score 5.0–7.4 | 12 | R03, R12, R02, R04, R06, R19, R09, R13, R17, R20, R15, R18 |
| **Low** | Score < 5.0 | 1 | R14 |

For detailed mitigations for each identified risk, see [ThreatIdentification.md](./ThreatIdentification.md#mitigations).

From: https://owasp.org/www-community/Threat_Modeling_Process#threat-model-information-sample