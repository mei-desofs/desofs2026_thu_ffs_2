# Cryptographic Architecture and Inventory

This document outlines the cryptographic policies, inventory, discovery mechanisms, and migration strategies employed by the Kryptos application, in accordance with the ASVS V11 (Cryptography) requirements.

---

## 1. Cryptographic Key Management Policy (V11.1.1)

Kryptos follows a formal cryptographic key lifecycle policy aligned with **NIST SP 800-57 Part 1** guidelines.

### 1.1 Key Generation
- All symmetric keys, Initialization Vectors (IVs), and salts are generated using cryptographically secure pseudorandom number generators (CSPRNG), specifically `java.security.SecureRandom`.

### 1.2 Key Storage and Sharing
- **No Oversharing:** Keys are strictly scoped. There are no shared secrets distributed to more than two entities (the backend and the authorized client, or just the backend internal services).
- **Master Key (KEK):** The Key Encryption Key (KEK) is injected securely via environment variables (`ENCRYPTION_KEY`) and is never hardcoded in the source code.
- **Data Encryption Keys (DEKs):** If envelope encryption is adopted, DEKs are uniquely generated per vault/credential.

### 1.3 Key Usage
- Cryptographic keys are restricted to single purposes. For example, the `jwt.secret` is used exclusively for HMAC token signing and cannot be repurposed for data encryption.
- Keys are kept in memory only for the duration of the cryptographic operation.

### 1.4 Key Destruction
- When a credential or vault is deleted, the corresponding ciphertext is permanently destroyed from the database (Crypto-shredding).
- Revoked JWTs are hashed (SHA-256) rather than storing the token plain text.

---

## 2. Cryptographic Inventory (V11.1.2)

The following cryptographic primitives and keys are actively used within the Kryptos application. This inventory is maintained continuously.

| Algorithm / Standard | Purpose | Component / Class | Data Protected | Usage Restrictions |
|----------------------|---------|-------------------|----------------|--------------------|
| **AES-256/GCM/NoPadding** | Authenticated symmetric encryption at rest. | `EncryptionService.java` | User vault credentials (passwords, usernames, URLs). | Used strictly for encrypting user-owned credential data. Cannot be used for signatures. |
| **Argon2id** | Secure password hashing. | `SecurityConfig.java` | User account login passwords. | Only applied to user master passwords. |
| **HS256 (HMAC SHA-256)** | JWT session signing and verification. | `JwtService.java` | Authentication session claims (Role, IP, User-Agent). | Exclusively for token generation/validation. |
| **SHA-256** | Cryptographic hashing for integrity and immutability. | `AuditService.java`, `JwtService.java`, `EncryptionService.java` | Audit logs (blockchain-style linking), revoked JWTs. | Non-reversible hashing. Cannot be used for password storage (Argon2id is used instead). |
| **SecureRandom** | CSPRNG for nonces, IVs, and 2FA codes. | `EncryptionService.java`, `AuthService.java` | IVs for AES-GCM, 2FA OTP codes. | Must be seeded by the OS entropy pool. |

---

## 3. Cryptographic Discovery Mechanisms (V11.1.3)

To ensure no unauthorized or weak cryptography is introduced into the system:
- **Centralized Abstraction:** All encryption and decryption operations are forced through a single interface (`EncryptionService`). This prevents developers from scattering raw `javax.crypto.Cipher` instantiations throughout the codebase.
- **Code Scanning (SAST):** Automated Static Application Security Testing tools (e.g., SonarQube) are configured to flag any usage of weak hashing algorithms (MD5, SHA-1) or deprecated ciphers (DES, RC4).
- **Dependency Analysis:** Supply chain checks (OWASP Dependency-Check) verify that external libraries bringing in cryptographic implementations (like BouncyCastle or JJWT) are free of known CVEs.

---

## 4. Post-Quantum Cryptography (PQC) Migration Plan (V11.1.4)

Kryptos actively monitors the threat landscape regarding Quantum Computing (e.g., Shor's and Grover's algorithms) and aligns with NIST's Post-Quantum Cryptography standardization.

### 4.1 Current Quantum Resistance
- **Symmetric Encryption (AES-256):** Grover's algorithm effectively halves the bit strength of symmetric keys. AES-256 will be reduced to an effective strength of 128 bits, which is widely considered to remain computationally secure against quantum attacks. **No immediate migration is required.**
- **Hashing (SHA-256, Argon2id):** Collision attacks against hash functions are also impacted by quantum computing, but SHA-256 and Argon2id provide sufficient bit-lengths to resist near-term quantum threats.
- **Asymmetric Cryptography:** Currently, Kryptos does **not** rely on RSA or Elliptic Curve Cryptography (ECC) for internal signatures or key exchange (JWTs use symmetric HMAC). Therefore, the system is inherently protected against Shor's algorithm vulnerabilities.

### 4.2 Future Migration Strategy
If end-to-end client-side encryption (E2EE) is introduced requiring public-key cryptography (key encapsulation or digital signatures):
1. **Key Encapsulation Mechanism (KEM):** The system will adopt **ML-KEM (FIPS 203)** (formerly Kyber) for secure key exchange.
2. **Digital Signatures:** The system will adopt **ML-DSA (FIPS 204)** (formerly Dilithium) for non-repudiation and document signing.
3. **Agility:** The `EncryptionService` interface is designed to be algorithm-agnostic, ensuring that swapping underlying providers (e.g., updating BouncyCastle to PQC variants) requires minimal refactoring.
