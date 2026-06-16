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
