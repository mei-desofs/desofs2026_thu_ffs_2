# Project Overview
The selected project consists of the development of a backend system for the secure management of digital credentials, named Kryptos. This platform was designed to provide a set of essential services related to the storage, organization, consultation, and monitoring of credentials through a secure and well-structured RESTful API.
The system allows each user to register and authenticate in the application, having exclusive access to their own data. Credentials can be organized into logical spaces called vaults, allowing a clearer and more secure structuring of information. To strengthen trust and access control, the application also includes the registration of trusted devices, meaning authorized devices associated with user sessions or credentials.
In addition, Kryptos provides administrative and auditing functionalities, enabling different access levels through role-based access control. The system supports at least three main user roles: Administrator, Common User, and Auditor, thus ensuring a proper separation of responsibilities and privileges.
One of the most important and sensitive functionalities of the application is the import and export of credentials, which requires direct interaction with operating system functionalities on the server. For this purpose, the system creates directories and writes temporary files in a specific format, ensuring their subsequent reading and secure deletion from disk through secure wipe mechanisms. These operations are further complemented by the generation of audit logs, allowing the tracing of critical actions and reinforcing accountability and system monitoring.

## Main features
- **User Management:** management of user accounts, including registration, authentication, and role-based access control.
- **Vault Management:** creation and organization of logical vaults where credentials are grouped and managed.
- **Credential Management:** storage, retrieval, update, and removal of credentials associated with different services.
- **Trusted Device Management:** registration and monitoring of trusted devices authorized to access the system or associated with specific credentials.
- **Import and Export Operations:** secure import and export of credentials through temporary files managed on the server.
- **Secure File Handling and Audit Logging:** directory creation, file reading and writing, secure deletion after use, and auditable logging of performed operations.

The system architecture is based on a **REST API** connected to a **relational database**, ensuring data persistence, organization, and scalability. As a backend-only application, Kryptos was designed to function as a service provider and may later be integrated with external clients or frontend interfaces. Its structure follows the principles of Domain-Driven Design (DDD) and is organized around four main aggregates: User, Vault, Credential, and TrustedDevice.

## Documentation

| Document | Description |
|----------|-------------|
| [SystemOverview.md](./SystemOverview.md) | Functional and non-functional requirements, security requirements, domain model, use case diagram, and architectural views (Logic, Implementation, Deployment) |
| [ThreatIdentification.md](./ThreatIdentification.md) | Threat model information, entry/exit points, assets, trust levels, data flow diagrams, risk assessment, and mitigations |
| [STRIDE.md](./STRIDE.md) | STRIDE threat analysis per DFD element, abuse case diagrams, threat tree analysis, and threat ranking (DREAD) |
| [SecurityTestPlan.md](./SecurityTestPlan.md) | Security testing methodology, test categories, and traceability matrix linking security requirements to tests |
| [ASVS_5.0_Tracker_Kryptos.xlsx](./ASVS_5.0_Tracker_Kryptos.xlsx) | OWASP ASVS 5.0 compliance tracker mapping security controls to project requirements, verification status, and test evidence |