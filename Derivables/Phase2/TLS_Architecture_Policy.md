# TLS Security Architecture Policy

This document outlines the TLS Security Architecture for the Kryptos application, detailing how the system complies with ASVS V12.1.1, V12.1.2, and V12.1.4 requirements regarding secure transport.

## Architecture Overview

Kryptos delegates TLS termination to a **Reverse Proxy (NGINX)**. The Spring Boot backend (`app` service) operates over HTTP (port 8080) exclusively within the isolated, private Docker container network. The NGINX reverse proxy (`proxy` service) is the only entry point exposed to the outside world (ports 80/443).

This architectural decision allows Kryptos to leverage NGINX's robust, enterprise-grade SSL/TLS capabilities, including optimized OCSP Stapling, which is not natively supported by standard Spring Boot embedded servers without complex integrations.

## ASVS Compliance Controls

### V12.1.1: TLS Protocol Versions
**Requirement:** Verify that only the latest recommended versions of the TLS protocol are enabled (TLS 1.2 and TLS 1.3).
**Implementation:** NGINX is explicitly configured to reject all connections using TLS 1.0, TLS 1.1, or older SSL versions.
**NGINX Configuration:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
```

### V12.1.2: Cipher Suites & Forward Secrecy
**Requirement:** Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy.
**Implementation:** The server enforces a strict list of modern cipher suites (`ECDHE`, `DHE`, `CHACHA20`), ensuring Perfect Forward Secrecy (PFS). Any cipher suite that does not provide PFS (like static RSA key exchange) is disabled, protecting past traffic from being decrypted even if the server's private key is compromised in the future.
**NGINX Configuration:**
```nginx
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
```

### V12.1.4: OCSP Stapling & Revocation
**Requirement:** Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured.
**Implementation:** OCSP Stapling is enabled on the NGINX proxy. Instead of forcing every client to independently contact the Certificate Authority (CA) to check if the certificate is revoked (which leaks privacy and slows down handshakes), the proxy queries the CA itself, caches the cryptographically signed response, and "staples" it to the initial TLS handshake.
**NGINX Configuration:**
```nginx
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### Additional Protections: HSTS (Strict-Transport-Security)
To actively prevent protocol downgrade attacks and ensure clients never attempt to connect over unencrypted HTTP, HTTP Strict Transport Security (HSTS) is enforced.
**Implementation:** All port 80 traffic is permanently redirected (301) to 443. Port 443 responses include the HSTS header.
**NGINX Configuration:**
```nginx
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```
