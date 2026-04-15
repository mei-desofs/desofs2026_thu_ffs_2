# Threat Identification

## Threat Model Information
Application Name: Kryptos
Application Version: 1.0

Description:
Kryptos is a secure credential management system designed to store sensitive authentication data like website logins. The application is structured around four main aggregates: User, Vault, Credential, and TrustedDevice.

Users can register and authenticate to access their personal data. Credentials are stored within vaults, allowing structured organization of sensitive information. The system also tracks trusted devices to enhance security monitoring.

Kryptos implements role-based access control with three types of users:
•	Regular Users – can manage their own vaults and credentials, and perform import/export operations
•	Administrators – can manage users, assign roles, and oversee system activity
•	Auditors – can review logs and monitor system operations for security and compliance


## External Dependencies

| ID | Description  |
|----|--------------|
| 1  | The database server will be SQL   |


## Entry Points

Entry points define the interfaces through which potential attackers can interact with the application or supply it with data.

| ID | Name | Description                                                                                                   | Trust Levels |
|----|------|---------------------------------------------------------------------------------------------------------------|--------------|
| 1  | HTTPS Interface | Kryptos is accessed via a secure HTTPS interface. All application features are exposed through this entry point. | (1) Anonymous User <br> (2) Authenticated User <br> (3) Administrator <br> (4) Auditor |
| 2  | Registration Page | Entry point where new users create an account by submitting personal and authentication data.                 | (1) Anonymous User |
| 3  | Login Page | Entry point where users provide credentials to authenticate and access the system.                            | (1) Anonymous User <br> (2) Authenticated User <br> (3) Administrator <br> (4) Auditor |
| 4  | Authentication Function | Processes user credentials, validates them against stored data, and establishes a session.                    | (2) Authenticated User <br> (3) Administrator <br> (4) Auditor |
| 5  | Vault Management Interface | Allows users to create, edit, and delete vaults used to organize credentials.                                 | (2) Authenticated User |
| 6  | Credential Management Interface | Allows users to create, view, update, and delete stored credentials.                                          | (2) Authenticated User |
| 7  | Trusted Device Management | Allows users to associate, view, and remove trusted devices linked to their account or credential access.     | (2) Authenticated User <br> (3) Administrator |
| 8  | Import Credentials Function | Allows users to upload credential s from local files into the system. Involves file reading and processing.   | (2) Authenticated User |
| 9  | Export Credentials Function | Allows users to export stored credentials into temporary files on the server. Involves file creation and storage. | (2) Authenticated User |
| 10 | User Management Interface | Allows administrators to manage users, assign roles, and control account status.                              | (3) Administrator |
| 11 | Audit Logs Interface | Allows administrators and auditors to view logs of system activities and security-relevant events.            | (3) Administrator <br> (4) Auditor |


## Exit Points
| ID | Name | Description |
|----|------|-------------|
| 1 | HTTPS Responses | All data returned to clients (HTML, JSON, API responses) is sent through HTTPS. Improper output encoding may expose the system to XSS or data leakage. |
| 2 | Registration Response | Returns success or error messages after account creation. Improper messages may reveal system logic or validation rules. |
| 3 | Login Response | Returns authentication results (success/failure). Detailed error messages may enable account enumeration or brute-force optimization. |
| 4 | Authentication Token / Session Creation | Generates and returns session tokens or authentication cookies. Weak handling may lead to session hijacking or leakage. |
| 5 | Vault Data Output | Returns vault information to the user interface. Improper access control or filtering may expose other users’ data. |
| 6 | Credential Data Output | Returns stored credentials (potentially sensitive data). Must ensure encryption and proper masking where applicable. |
| 7 | Trusted Device Data Output | Returns information about trusted devices. Improper exposure may leak device identifiers. |
| 8 | Imported Data Processing Output | Returns results of credential import (success/failure, parsed data). Errors may expose file structure or parsing logic. |
| 9 | Exported File Output | Generates files containing credentials and stores them temporarily on disk. Improper handling may lead to sensitive data exposure. |
| 10 | User Management Responses | Returns results of administrative actions (user creation, role changes). May expose sensitive system or user information if not controlled. |
| 11 | Audit Log Output | Returns system logs to administrators and auditors. Logs may contain sensitive operational or user data. |


## Assets
| ID  | Name | Description |
|-----|------|-------------|
| 1   | Users | Assets related to all system users (Regular Users, Administrators, Auditors). |
| 1.1 | User Login Credentials | Authentication data (e.g., usernames, passwords) used to access the system. |
| 1.2 | Personal User Data | Information stored about users (e.g., email). |
| 1.3 | User Roles and Permissions | Role assignments (User, Admin, Auditor) that control access to system functionality. |
| 2   | Credentials Management | Assets related to stored credentials and vault organization. |
| 2.1 | Stored Credentials | Sensitive authentication data (e.g., usernames, passwords) stored by users. |
| 2.2 | Vault Data | Logical grouping of credentials belonging to a user. |
| 2.3 | Trusted Device Data | Information about devices associated with user sessions and credential access. |
| 3   | System | Assets related to system infrastructure and execution environment. |
| 3.1 | Application Availability | The Kryptos system should remain available and accessible to authorized users. |
| 3.2 | File System Access | Ability of the application to create, read, and delete files on the server (used in import/export). |
| 3.3 | Execution Environment | The server environment where the application runs and processes requests. |
| 4   | Application | Assets related to application-level functionality and security. |
| 4.1 | User Sessions | Active authenticated sessions between users and the system. |
| 4.2 | Import/Export Data | Temporary credential data handled during import/export operations. |
| 4.3 | Audit Logs | Logs containing records of user actions and system events for monitoring and compliance. |
| 4.4 | Access Control Mechanism | Role-based access control system enforcing permissions across the application. |

## Trust Levels

| ID | Name | Description                                                                                                   |
|----|------|---------------------------------------------------------------------------------------------------------------|
| 1 | Anonymous User | A user who can access the Kryptos interface but has not authenticated and/or does not have valid credentials. |
| 2 | Authenticated User | A regular user who has successfully logged into the system and can manage their own vaults and credentials.   |
| 3 | Administrator | A privileged user who can manage users, assign roles, and oversee system operations.                          |
| 4 | Auditor | A user with read-only access to audit logs and system activity for monitoring and compliance purposes.        |


## Data Flow Diagrams



From: https://owasp.org/www-community/Threat_Modeling_Process#threat-model-information-sample