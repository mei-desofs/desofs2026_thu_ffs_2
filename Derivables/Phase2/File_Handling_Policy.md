# File Handling & Upload Policy (ASVS V5.1.1)

This document serves as the formal documentation matrix for file handling, uploading, and processing within the **Kryptos** application. It complies with the OWASP Application Security Verification Standard (ASVS) requirement **V5.1.1**, ensuring strict rules and boundaries are applied and documented for all file-related operations.

## 1. Import/Upload Restrictions Matrix

| Feature | Permitted Types / Extensions | Max File Size | Max Content Limit |
| :--- | :--- | :--- | :--- |
| **Credential Vault Import** | `.kvault`, `.csv`, `.json`, `.txt` <br>*(Strict Regex enforcement: `^[A-Za-z0-9]{1,8}$`)* | **5 MiB** (5,242,880 bytes) | **50,000** records (lines) |

### 1.1 Extension Handling & Sanitization
* During upload, the system extracts the extension from the original file name.
* The extension is strictly validated against an allowlist pattern (`[A-Za-z0-9]{1,8}`). No special characters, path traversal sequences (`../`), or hidden bytes are permitted.
* If a file does not have a valid extension, it is stored temporarily without one to prevent arbitrary code execution attacks.

## 2. Storage and Access Protections

Files processed by the application (during import or export flows) are subject to rigorous storage and permission boundaries:

* **Temporary Storage Isolation**: All uploads are strictly routed to the system's temporary directory (`${kryptos.storage.temp-dir}`). The application actively blocks (`IllegalArgumentException`) any attempt to read, write, or wipe files outside of this isolated directory (Directory Traversal prevention).
* **Strict POSIX Permissions (0600)**: Any file created by the application is instantly hardened with `rw-------` permissions. This guarantees that only the user executing the Spring Boot server process can read or write to the file.

## 3. Threat Mitigation and Malicious File Handling

To protect end-users and the server from malicious files (e.g., zip bombs, oversize payloads, logic bombs), the application enforces the following behaviors when an anomaly is detected:

### A. Oversize Payload Detection
* If the uploaded file exceeds **5 MiB**, the backend throws an `IOException("Uploaded file is too large")` and immediately rejects the processing.
* The anomaly is logged to the Audit system: `Rejected oversize import file: <size> bytes`.

### B. "Zip Bomb" / Excessive Line Detection
* To prevent Denial of Service (DoS) via millions of blank lines or small records, the importer counts records in real-time.
* If the number of lines exceeds **50,000**, the parsing terminates immediately, the file is rejected, and an Audit Event is triggered (`Rejected import: line count exceeds limit`).

### C. Processing Failures & Cleanup
* If a file is malformed, contains illegal line breaks, or causes a crash during parsing, the file is **immediately deleted** from the filesystem. No half-processed or corrupted files are left lingering on the disk.

### D. Secure Data Wiping (Defense in Depth)
When an import/export operation concludes (successfully or unsuccessfully), files are not merely deleted; they are *securely wiped* to prevent data recovery:
* The `FileHandlingService` performs a **3-pass secure wipe**.
* Pass 1 and 2: The file is overwritten with Cryptographically Secure Pseudo-Random Numbers (`SecureRandom`).
* Pass 3: The file is overwritten entirely with zeros.
* Finally, the file link is deleted (`Files.deleteIfExists()`).
