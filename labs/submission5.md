# Lab 5 — Security Analysis: SAST & DAST of OWASP Juice Shop

**Target:** OWASP Juice Shop `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — Static Application Security Testing with Semgrep

### 1.1 SAST Tool Effectiveness

**Semgrep** was run with `p/security-audit` and `p/owasp-top-ten` rulesets against the Juice Shop v19.0.0 source code.

| Metric | Value |
|--------|-------|
| **Findings** | 25 |
| **Files scanned** | 1,014 |
| **Rules run** | 140 |
| **Parsed lines** | ~99.9% |

**Vulnerability types detected:**
- **SQL Injection (Sequelize):** User-input tainted Sequelize statements (4 findings)
- **Unquoted attribute variables (XSS):** Template variables in HTML attributes (3 findings)
- **Hardcoded JWT secret:** Credential in source code (1 finding)
- **Raw HTML injection:** User data in manually-constructed HTML (1 finding)
- **Path traversal (res.sendFile):** User input passed to `res.sendFile` (3+ findings)

**Coverage:** Semgrep scanned 1,014 git-tracked files across TypeScript, JavaScript, HTML, JSON, YAML, and Dockerfile. Eight files >1 MB and 139 `.semgrepignore`-matched files were skipped.

### 1.2 Top 5 Critical Findings

| # | Vulnerability Type | File | Line | Severity |
|---|--------------------|------|------|----------|
| 1 | **SQL Injection (Sequelize)** | `data/static/codefixes/dbSchemaChallenge_1.ts` | 5 | ERROR |
| 2 | **SQL Injection (Sequelize)** | `data/static/codefixes/dbSchemaChallenge_3.ts` | 11 | ERROR |
| 3 | **SQL Injection (Sequelize)** | `data/static/codefixes/unionSqlInjectionChallenge_1.ts` | 6 | ERROR |
| 4 | **SQL Injection (Sequelize)** | `data/static/codefixes/unionSqlInjectionChallenge_3.ts` | 10 | ERROR |
| 5 | **Hardcoded JWT Secret** | `lib/insecurity.ts` | 56 | WARNING |

**Details:**
1–4. **Sequelize SQL injection:** Raw or concatenated user input is used in Sequelize queries. Use parameterized queries or `replacements` to prevent injection.
5. **Hardcoded JWT secret:** A credential is stored in source code. Move to environment variables or a secrets manager.

---

## Task 2 — Dynamic Application Security Testing

### 2.1 Authenticated vs Unauthenticated Scanning

**ZAP baseline (unauthenticated):**
- **URLs discovered:** Public endpoints only (home, sitemap, static assets, ftp paths)
- **Alerts:** 9 WARN (e.g. CSP header not set, cross-domain JS inclusion, deprecated feature policy, timestamp disclosure)
- **Report:** `labs/lab5/zap/report-noauth.html`

**ZAP authenticated scan:**
- **Spider:** 112 URLs
- **AJAX Spider:** 432 URLs (includes dynamic/admin endpoints)
- **Admin/authenticated endpoints:** `/rest/admin/`, `/rest/user/`, `/rest/basket/`, `/rest/order/`, etc.

**Why authenticated scanning matters:**
- Unauthenticated scans see only public pages; authenticated scans reach user-specific and admin features.
- Juice Shop exposes admin APIs (e.g. `/rest/admin/application-configuration`) that require a valid session.
- Authenticated scanning increases URL discovery by ~4× and surfaces auth-related issues (session handling, privilege escalation, IDOR).

### 2.2 Tool Comparison Matrix

| Tool | Findings | Severity Breakdown | Best Use Case |
|------|----------|--------------------|---------------|
| **ZAP** | 9 WARN (baseline) | Medium: 7, High: 1 | Broad web app scanning, auth support, passive + active |
| **Nuclei** | 0 (run attempted) | — | Fast CVE/template-based checks |
| **Nikto** | — (image unavailable) | — | Server misconfiguration |
| **SQLmap** | — (image unavailable) | — | SQL injection testing |

*Note: Nuclei was run; Nikto and SQLmap could not be executed due to Docker image availability in this environment.*

### 2.3 Tool-Specific Strengths

| Tool | Strengths | Example Finding |
|------|-----------|-----------------|
| **ZAP** | Full web app coverage, auth, passive + active scanning, HTML/JSON reports | CSP header not set; cross-domain JS inclusion |
| **Nuclei** | Fast, template-based, CVE-focused | Best for known CVEs and common misconfigurations |
| **Nikto** | Server-level checks | Outdated server versions, dangerous files, misconfigurations |
| **SQLmap** | Deep SQLi testing, automated exploitation | Boolean/time-based blind SQLi, database extraction |

**ZAP examples from this run:**
- **Content Security Policy (CSP) Header Not Set [10038]:** Multiple pages lack CSP.
- **Cross-Domain JavaScript Source File Inclusion [10017]:** Scripts loaded from external domains.
- **Dangerous JS Functions [10110]:** Use of `eval` or similar in `main.js`, `vendor.js`.

---

## Task 3 — SAST/DAST Correlation and Security Assessment

### 3.1 SAST vs DAST Comparison

| Approach | Total Findings | Notes |
|----------|----------------|-------|
| **SAST (Semgrep)** | 25 | Code-level issues before deployment |
| **DAST (ZAP)** | 9 WARN | Runtime and configuration issues |

### 3.2 Vulnerability Types by Approach

**Found only by SAST:**
- Hardcoded JWT secret in `lib/insecurity.ts`
- Sequelize SQL injection patterns in codefixes
- Path traversal via `res.sendFile` in `fileServer.ts`, `keyServer.ts`, `logfileServer.ts`
- Unquoted attribute variables (XSS risk) in Angular templates

**Found only by DAST:**
- Missing CSP header
- Cross-domain JavaScript inclusion
- Deprecated Feature-Policy header
- Missing Cross-Origin-Embedder-Policy

### 3.3 Why Each Approach Finds Different Issues

- **SAST** inspects source code and finds logic flaws, hardcoded secrets, and unsafe patterns before runtime.
- **DAST** exercises the running application and finds deployment/config issues (headers, CORS, server behavior) that code analysis cannot see.

**Recommendation:** Use both SAST and DAST for full coverage. SAST in CI for fast feedback; DAST in staging/pre-production for runtime security.

---

## Summary

- **SAST (Semgrep):** 25 findings across SQL injection, hardcoded secrets, path traversal, and XSS patterns.
- **DAST (ZAP):** 9 WARN from baseline scan; authenticated scan discovered 432 URLs.
- **Correlation:** SAST and DAST complement each other; neither alone covers all vulnerability types.
- **Next steps:** Fix critical Semgrep findings (SQLi, JWT secret); add CSP and security headers; run Nikto and SQLmap when images are available.
