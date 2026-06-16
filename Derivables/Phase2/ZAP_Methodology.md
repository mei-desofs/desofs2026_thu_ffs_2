### OWASP ZAP DAST Scan Methodology & Rule Configuration

The application is a stateless REST API secured by JWTs. Because it does not rely on traditional session management (e.g., session cookies) nor does it render HTML interfaces directly, several conventional DAST checks (such as HTML-centric CSP, CSRF tokens, and Cookie flags) are not applicable as direct vulnerabilities.

To prevent false positives from failing the CI/CD pipeline, the OWASP ZAP Baseline rules have been tuned (configured in `.zap/rules.tsv`). Critical rules involving injection, transport layer security, and severe information disclosure remain set to `FAIL`.

#### Rules Downgraded to WARN
These rules have been downgraded from `FAIL` to `WARN`. They are acknowledged but do not block the pipeline.

| Rule ID | Name | Justification |
| :--- | :--- | :--- |
| **10015** | Incomplete or No Cache-control Header Set | Considered acceptable for stateless JSON 401/403 API responses. |
| **10020** | X-Frame-Options | Not applicable to a pure REST API as there are no views to embed in iframes. |
| **10021** | X-Content-Type-Options | Handled appropriately on specific file download endpoints; the core API strictly serves `application/json`. |
| **10038** | Content Security Policy (CSP) | The REST API serves JSON and does not render HTML content; CSP headers are mostly irrelevant here. |
| **10054** | Cookie Without SameSite | The system uses JWTs transmitted via the `Authorization` header, completely avoiding reliance on cookies. |
| **10055** | CSP Scanner | Alerts from the CSP scanner are not relevant for a JSON API surface. |
| **10063** | Permissions-Policy Header Not Set | Not relevant for a JSON-only API backend. |
| **10096** | Timestamp Disclosure | The exposure of timestamps is intentional and required by business logic (e.g., JWT expiration, audit logs). |
| **10202** | Absence of Anti-CSRF Tokens | As a stateless JWT API that does not use cookies, the traditional CSRF attack vector does not exist. |
| **90004** | Insufficient Site Isolation | Downgraded because the application is strictly a REST API and does not load multi-origin cross-site resources like a traditional webapp. |

#### Rules Set to IGNORE
These rules have been completely ignored as they represent clear false positives or bugged ZAP behaviors for this specific architecture.

| Rule ID | Name | Justification |
| :--- | :--- | :--- |
| **10049** | Non-Storable Content | Irrelevant/False Positive: 403 responses on typical static paths (e.g., `/favicon.ico`, `/robots.txt`) are expected stateless API rejections. There is nothing to cache. |
| **90005** | Sec-Fetch-Dest | ZAP Flag Error: This is a request header sent *by* the browser, not a response header from the backend. The ZAP alert is structurally incorrect for any backend assessment. |

#### Documented Findings & Resolutions
Based on the provided DAST scan (`docs/zap-report`), the ZAP Baseline Scan completed without any High or Medium severity alerts. The following minor findings were identified and documented below:

| Risk Level | Alert Name | Resolution / Remediation Plan |
| :--- | :--- | :--- |
| **Low** | Server Leaks Version Information via "Server" HTTP Response Header Field | The Nginx proxy returns `nginx/1.31.1` in the `Server` header. This is a low-risk information disclosure. As an accepted risk for this environment, no immediate action is required. It can be mitigated in the future by setting `server_tokens off;` in the Nginx configuration if desired. |
| **Informational** | Content-Type Header Missing | Identified on default/empty Nginx responses. Does not pose a security threat as the application correctly sets `application/json` on all functional REST API endpoints. |
| **Informational** | Non-Storable Content | False positive regarding 403 responses on static paths (`/favicon.ico`, `/robots.txt`). Already explicitly ignored via ZAP Rule Override `10049`. |
| **Informational** | Sec-Fetch-* Header Missing | ZAP incorrectly flags the absence of browser-sent `Sec-Fetch-*` headers as a vulnerability in the backend response. Already explicitly ignored via ZAP Rule Override `90005` (and equivalents). |

**Conclusion**: The automated DAST scan completes successfully with zero blocking issues. All identified items are low or informational, predominantly representing false positives for a stateless REST API, and are properly acknowledged or overridden.
