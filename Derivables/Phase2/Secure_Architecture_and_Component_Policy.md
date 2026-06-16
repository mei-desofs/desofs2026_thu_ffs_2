# Secure Architecture and Component Policy

This document outlines the security policies and architectural defenses for the Kryptos application, specifically addressing ASVS V15 requirements concerning component management, resource utilization, and high-risk functionalities.

---

## 1. Third-Party Component Remediation Policy (ASVS V15.1.1)

To minimize the risk from third-party components, the following risk-based remediation time frames are enforced for any vulnerability identified (e.g., via OWASP Dependency-Check or GitHub Dependabot):

| Severity (CVSS) | Description | Remediation SLA | Action Required |
| :--- | :--- | :--- | :--- |
| **Critical (9.0 - 10.0)** | Exploitable vulnerabilities with severe impact (e.g., RCE). | **24 Hours** | Immediate patching and out-of-band release. Build fails (`failBuildOnCVSS=9`). |
| **High (7.0 - 8.9)** | Vulnerabilities that compromise confidentiality or integrity. | **7 Days** | Prioritized in the current sprint backlog. |
| **Medium (4.0 - 6.9)** | Vulnerabilities with limited impact or requiring high privilege. | **30 Days** | Addressed in the next scheduled release cycle. |
| **Low (0.1 - 3.9)** | Minor issues with complex exploit vectors. | **90 Days** | Addressed during routine maintenance. |

**Update Strategy:** Libraries are actively monitored and updated to the latest stable minor/patch versions quarterly to prevent technical debt and reduce the attack surface.

---

## 2. Software Bill of Materials (SBOM) (ASVS V15.1.2)

Kryptos maintains a verifiable inventory of all third-party libraries:
* **Generation:** An SBOM is automatically generated during the CI pipeline build process (`mvn verify`) using the `cyclonedx-maven-plugin`.
* **Format:** The SBOM is published in the industry-standard **CycloneDX** format (`bom.json` / `bom.xml`).
* **Artifacts:** The resulting SBOM is attached to every GitHub Actions pipeline run as a build artifact for auditing and compliance tracking.
* **Repositories:** Dependencies are strictly sourced from trusted and continually maintained repositories (Maven Central).

---

## 3. Resource-Demanding Functionality Defenses (ASVS V15.1.3)

Kryptos identifies specific functionalities that are computationally expensive or resource-demanding and implements safeguards to prevent Denial of Service (DoS) attacks and ensure availability:

1. **Authentication (Login Lockout):**
   * *Risk:* Brute-force attacks consume database connections and compute cycles evaluating passwords/TOTP.
   * *Defense:* The `AuthService` implements an automatic IP-based lockout window after consecutive failed attempts, shielding the system from resource exhaustion.
2. **Cryptographic Operations (AES-GCM):**
   * *Risk:* High CPU usage during the encryption and decryption of credentials.
   * *Defense:* Cryptographic operations are scoped per-credential rather than in bulk payloads, ensuring individual HTTP requests do not block server threads excessively.
3. **Data Import/Export (File Processing):**
   * *Risk:* Processing large CSV/JSON files requires significant memory allocation and database I/O.
   * *Defense:* The `ImportExportRateLimiter` enforces strict limits on how frequently a user can invoke these operations (e.g., maximum 5 exports per hour), preventing overlapping memory-intensive processes.
4. **Secure Data Wipe (Shredding):**
   * *Risk:* 3-pass cryptographic wipe of files is highly disk-I/O intensive.
   * *Defense:* Limited to authorized users and constrained by the asynchronous processing nature of the OS scheduler.

---

## 4. High-Risk Third-Party Components (ASVS V15.1.4)

The following external libraries are critical to the security posture of Kryptos and are classified as "risky components". They require elevated scrutiny during updates and audits:

* **`io.jsonwebtoken:jjwt-*`:** Handles all JWT creation and validation. A flaw here could lead to complete authentication bypass.
* **`org.bouncycastle:bcpkix-jdk18on`:** Provides the cryptographic primitives (AES-GCM, SecureRandom). Essential for data confidentiality.
* **`org.springframework.security:spring-security-*`:** The core framework enforcing authorization, CSRF protection, and security headers.
* **`org.postgresql:postgresql`:** The JDBC driver. Responsible for securely transporting (via mTLS) sensitive credentials to the database.

---

## 5. Dangerous Functionality Inventory (ASVS V15.1.5)

Kryptos implements several application features categorized as "dangerous functionality" due to their interaction with the host operating system. These are heavily monitored and restricted:

* **Temporary File Handling:** During the Import/Export process, Kryptos reads and writes files directly to the host OS (`/tmp/kryptos`).
  * *Safeguard:* Directory traversal protections are strictly enforced. Files are securely wiped immediately after use.
* **Secure File Shredding (`SecureFileWiper`):** Executes physical overwrites (3-pass random data) on the host disk.
  * *Safeguard:* Bypasses standard logical file deletion to prevent forensic recovery. Restricted exclusively to temporary files managed by the application.
* **OS Command Execution:** Kryptos avoids executing arbitrary shell commands (no `Runtime.exec()`), relying entirely on native Java APIs for file and system manipulation to prevent Command Injection.
