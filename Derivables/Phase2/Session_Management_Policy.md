# Session Management Policy (ASVS V7.1.1)

This document serves as the formal documentation for the session lifecycle, expiration, and timeouts within the **Kryptos** application, fulfilling the requirements of **OWASP ASVS V7.1.1** and justifying decisions in accordance with **NIST SP 800-63B**.

## 1. Session Lifecycle Parameters

Kryptos uses stateless JSON Web Tokens (JWT) for session management. The parameters are defined as follows:

* **Absolute Maximum Session Lifetime:** 1 Hour (`3600000` milliseconds).
* **Session Inactivity Timeout:** Since Kryptos uses a strict 1-hour absolute expiration, the session is naturally bounded. Inactivity timeouts are enforced at the client-side (frontend application) by automatically clearing the stored token and state after a set period of user inactivity (e.g., 15 minutes), requiring the user to re-authenticate.
* **Configuration:** This parameter is globally configured via the `JWT_EXPIRATION` environment variable (documented in `backend/.env.example` and applied in `application.properties`).

## 2. Rationale and NIST SP 800-63B Alignment

NIST SP 800-63B (Section 4.2) requires that for AAL2 (Authenticator Assurance Level 2) and higher, re-authentication of the subscriber shall be repeated at least once per 12 hours during an extended usage session, and after 30 minutes of inactivity.

### Deviations and Justification
Our design **exceeds** the strictness of the NIST baseline for maximum lifetime:
* **Absolute Lifetime:** We limit the absolute session lifetime to **1 hour** (rather than the maximum permitted 12 hours). This is a deliberate security decision given the highly sensitive nature of a password manager (Kryptos). A shorter absolute lifetime dramatically reduces the window of opportunity for token theft or replay attacks.
* **Inactivity Timeout:** In a purely stateless JWT architecture without a token revocation list (blacklist) or refresh token rotation, enforcing server-side inactivity is architecturally challenging. Therefore, we mitigate this by combining a short absolute lifetime (1 hour) with client-side inactivity monitoring. 

## 3. Appropriateness with Combined Controls

The 1-hour session limit is highly appropriate when evaluated in the context of Kryptos's defense-in-depth architecture:

1. **HMAC Request Signing:** Even if a session token (JWT) is stolen, the attacker cannot forge requests because every mutable request requires an HMAC signature generated using a secret key, providing proof-of-possession.
2. **TLS / HTTPS:** All sessions are transmitted over encrypted channels, preventing MITM (Man-In-The-Middle) token interception.
3. **Stateless Nature:** By avoiding server-side sessions, Kryptos remains resilient to session-based DoS attacks, while the short 1-hour window ensures automatic invalidation without requiring complex state management.
4. **Secure Wipe (Memory Management):** Short sessions ensure that cryptographic keys and sensitive vault data are frequently purged from memory, reducing the risk of memory scraping.

## Conclusion
The Kryptos session management strategy intentionally uses a short (1-hour) absolute lifetime as a mitigating control for stateless JWTs. This approach not only meets but exceeds the maximum timeframe limits proposed by NIST SP 800-63B for secure re-authentication, providing a highly secure environment for credential management.
