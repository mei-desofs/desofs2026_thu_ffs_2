# STRIDE

## Threat List

### User Authentication

| DFD Element                             | STRIDE                     | Threats Across Data Flow                                                                                               | Abuse Case                            |
|-----------------------------------------|----------------------------|------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
| **External Entity:** Anonymous User     | **Spoofing**               | Attacker pretends to be a user using stolen credentials, API, or database (e.g., stolen credentials, fake services).   | **Brute Force / Credential Stuffing** |
| **Data Flow:** Submit Login Credentials | **Tampering**              | Data (credentials, queries, tokens) is modified during transmission or processing.                                     | ---                                   |
| **Process:** Authentication Process     | **Repudiation**            | Actions cannot be traced because of missing or insufficient logging.                                                   | ---                                   |
| **Data Store:** User DB                 | **Information Disclosure** | Sensitive data (credentials, tokens, hashes) is exposed to unauthorized parties.                                       | ---                                   |
| **Process:** Authentication Process     | **Denial of Service**      | Login system or database is overwhelmed, making authentication unavailable.                                            | **Brute Force / Credential Stuffing** |
| **Data Flow:** JWT Token                | **Elevation of Privilege** | Attacker manipulates the token payload to gain higher access (e.g., admin rights) through stolen data or system flaws. | ---                                   |

### User Management

| DFD Element                            | STRIDE                     | Threats Across Data Flow                                                                                  | Abuse Case               |
|----------------------------------------|----------------------------|-----------------------------------------------------------------------------------------------------------|--------------------------|
| **External Entity:** User              | **Spoofing**               | Attacker impersonates an admin, API, or database (e.g., stolen admin credentials, fake services).         | ---                      |
| **Data Flow:** User Management Request | **Tampering**              | User management requests or database queries are modified (e.g., changing roles or permissions).          | ---                      |
| **Process:** Backend API               | **Repudiation**            | Admin actions cannot be verified due to missing or insufficient logging.                                  | ---                      |
| **Data Store:** User DB                | **Information Disclosure** | Sensitive user data (e.g., roles, emails) is exposed to unauthorized parties.                             | ---                      |
| **Process:** Backend API               | **Denial of Service**      | User management endpoints or database are overloaded, preventing admin operations.                        | ---                      |
| **Process:** Backend API               | **Elevation of Privilege** | Unauthorized users gain higher roles (e.g., becoming admin) through manipulated requests or system flaws. | **Privilege Escalation** |

### Vault Management

| DFD Element                             | STRIDE                     | Threats Across Data Flow                                                                                                                                                                     | Abuse Case                       |
|-----------------------------------------|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------|
| **External Entity:** User               | **Spoofing**               | Attacker impersonates a legitimate user (via stolen JWT, session hijacking, or forged API requests) to access or manipulate vaults that do not belong to them.                               | ---                              |
| **Data Flow:** Vault Management Request | **Tampering**              | Vault requests are modified in transit to alter names, descriptions, or ownership; attacker rewrites vault records in the database or bypasses ownership checks to edit other users' vaults. | ---                              |
| **Process:** Vault Management Process   | **Repudiation**            | Vault creation, update, or deletion events are not logged (or are logged without user/device context), allowing a user to deny having performed destructive actions.                         | ---                              |
| **Data Flow:** Query / Store Vault      | **Information Disclosure** | Vault metadata (names, descriptions, owner identifiers) is exposed to unauthorized users due to missing or incorrect authorization checks (IDOR on `/vaults/{id}`).                          | **Unauthorized Vault Deletion**  |
| **Process:** Vault Management Process   | **Denial of Service**      | Attacker abuses create/delete endpoints (mass vault creation, cascading deletes) to exhaust storage, saturate database connections, or lock tables.                                          | ---                              |
| **Process:** Vault Management Process   | **Elevation of Privilege** | Attacker bypasses role checks (e.g., uses a Regular User token to call admin-only vault endpoints) to manage vaults belonging to other users.                                                | **Unauthorized Vault Deletion**  |

### Credential Management

| DFD Element                                | STRIDE                     | Threats Across Data Flow                                                                                                                                                                                                               | Abuse Case                         |
|--------------------------------------------|----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| **External Entity:** User                  | **Spoofing**               | Attacker uses stolen tokens or session cookies to read, modify, or delete credentials stored in another user's vault.                                                                                                                  | ---                                |
| **Process:** Credential Management Process | **Tampering**              | Ciphertext is modified in transit or at rest (without authenticated encryption), leading to corrupted credentials that may decrypt into attacker-controlled plaintext; request payloads are tampered with to inject malicious content. | **Credential Tampering**           |
| **Process:** Credential Management Process | **Repudiation**            | Credential reads (especially decrypted reveals) and modifications are not logged or are logged without sufficient context, allowing a user to deny exfiltration.                                                                       | ---                                |
| **Data Store:** Credential DB              | **Information Disclosure** | Plaintext credentials leak via error messages, debug logs, memory dumps, or insecure responses; encryption keys are exposed via the key store or application memory; IDOR allows fetching another user's credentials.                  | ---                                |
| **Process:** Credential Management Process | **Denial of Service**      | Brute-force or enumeration requests on credential endpoints saturate the decryption service; repeated malformed ciphertext triggers expensive error paths.                                                                             | ---                                |
| **Data Flow:** Verify Vault Ownership      | **Elevation of Privilege** | Attacker who compromises one account moves laterally by exfiltrating credentials that grant access to other systems (credential reuse), or exploits missing authorization to read credentials from other users' vaults.                | **Unauthorized Credential Access** |

## Threat Tree Analysis

### User Authentication
![User Authentication Threat Tree](./images/threat-tree-analysis/authenticate-users.png)

### User Management
![User Management Threat Tree](./images/threat-tree-analysis/manage-users.png)

### Vault Management
![Vault Management Threat Tree](./images/threat-tree-analysis/manage-vaults/manage-vaults.png)

### Credential Management
![Credential Management Threat Tree](./images/threat-tree-analysis/manage-credentials/manage-credentials.png)



## Threat Ranking




From: https://owasp.org/www-community/Threat_Modeling_Process#threat-model-information-sample