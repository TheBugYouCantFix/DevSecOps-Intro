# Lab 4 — SBOM Generation & Software Composition Analysis

**Target:** OWASP Juice Shop `bkimminich/juice-shop:v19.0.0`

---

## Task 1 — SBOM Generation with Syft and Trivy

### 1.1 Package Type Distribution Comparison

| Package Type | Syft Count | Trivy Count |
|--------------|------------|-------------|
| **npm**      | 1,128      | 1,125 (Node.js) |
| **deb**      | 10         | 10 (debian OS)  |
| **binary**   | 1          | —               |
| **Total**    | **1,139**  | **1,135**       |

**Observations:**
- Syft detected 1,128 npm packages and 10 deb packages; Trivy reported 1,125 Node.js packages and 10 Debian OS packages.
- Syft found 1 binary artifact; Trivy does not report binaries in the same way.
- Both tools agree on the OS layer (Debian 12.11) and the Node.js application layer.

### 1.2 Dependency Discovery Analysis

- **Syft** produced a native JSON SBOM with 1,139 artifacts, including `name`, `version`, `type`, `licenses`, and `locations`. It uses multiple catalogers (npm, deb, binary) and captures dependency metadata.
- **Trivy** with `--list-all-pkgs` produced 1,135 packages across OS and language layers. It groups by `Target` (image layers) and `Class` (os-pkgs, lang-pkgs).
- **Overlap:** 1,126 packages were detected by both tools. Syft found 13 unique packages; Trivy found 9 unique packages. The small differences likely come from cataloger behavior and version normalization.
- **Conclusion:** Syft provides slightly richer metadata (licenses per artifact, locations). Trivy integrates SBOM with vulnerability scanning in one run.

### 1.3 License Discovery Analysis

| Metric | Syft | Trivy |
|--------|------|-------|
| **Unique license types** | 32 | 28 |
| **Dominant licenses** | MIT (890), ISC (143), BSD-3-Clause (16), Apache-2.0 (15) | MIT (878), ISC (143), BSD-3-Clause (14), Apache-2.0 (12) |
| **OS package licenses** | Included in artifact list | Separate (GPL, LGPL, Artistic, etc.) |
| **Node.js licenses** | Per-package in artifacts | Per-package in Results |

**Observations:**
- Syft found more distinct license labels (32 vs 28), partly due to variant naming (e.g. `GPL-2` vs `GPL-2.0-only`).
- Both report MIT as the most common license (~88% of npm packages).
- Trivy separates OS and language packages; Syft unifies them in one artifact list.
- **Conclusion:** Syft offers slightly broader license discovery; Trivy’s license output is well-structured for compliance workflows.

---

## Task 2 — Software Composition Analysis with Grype and Trivy

### 2.1 SCA Tool Comparison

| Severity | Grype | Trivy |
|----------|-------|-------|
| **Critical** | 11 | 10 |
| **High** | 86 | 81 |
| **Medium** | 32 | 34 |
| **Low** | 3 | 18 |
| **Negligible** | 12 | — |
| **Total CVEs** | 93 unique | 91 unique |
| **Common CVEs** | — | 26 |

**Observations:**
- Grype and Trivy both detect critical and high-severity issues; Grype reports a few more critical findings.
- Only 26 CVEs overlap; each tool surfaces different issues from its vulnerability databases (Grype: Anchore DB; Trivy: multiple sources).
- **Recommendation:** Use both tools for broader coverage; cross-reference critical findings before remediation.

### 2.2 Top 5 Critical Findings with Remediation

1. **vm2 Sandbox Escape (CVE-2023-32314, CVE-2023-37466, GHSA-whpj-8f3w-67p5, GHSA-cchq-frgv-rjh5)**  
   - **Package:** vm2@3.9.17  
   - **Impact:** Sandbox escape can lead to arbitrary code execution on the host.  
   - **Remediation:** Upgrade to vm2 ≥3.9.19 or remove vm2 if sandboxing is not required; consider alternatives (e.g. isolated-worker, vm2 replacement).

2. **jsonwebtoken Verification Bypass (CVE-2015-9235, GHSA-c7hr-j4mj-j2w6)**  
   - **Package:** jsonwebtoken@0.1.0, 0.4.0  
   - **Impact:** Attackers can bypass JWT verification and forge tokens.  
   - **Remediation:** Upgrade to jsonwebtoken ≥9.0.0; ensure proper algorithm validation and secret management.

3. **lodash Prototype Pollution (GHSA-jf85-cpcp-j695, CVE-2019-10744)**  
   - **Package:** lodash@2.4.2  
   - **Impact:** Prototype pollution can enable injection and privilege escalation.  
   - **Remediation:** Upgrade to lodash ≥4.17.21.

4. **crypto-js Weak PBKDF2 (GHSA-xwcq-pm8m-c4vf, CVE-2023-46233)**  
   - **Package:** crypto-js@3.3.0  
   - **Impact:** PBKDF2 is far weaker than specified; weakens password hashing.  
   - **Remediation:** Replace with a modern library (e.g. Node.js `crypto.pbkdf2` or `argon2`); avoid crypto-js for password hashing.

5. **OpenSSL RCE/DoS (CVE-2025-15467)**  
   - **Package:** libssl3@3.0.17-1~deb12u2 (OS layer)  
   - **Impact:** Remote code execution or denial of service.  
   - **Remediation:** Rebuild the image on an updated base (e.g. Debian with patched OpenSSL); run `apt update && apt upgrade` in the image build.

### 2.3 License Compliance Assessment

- **Dominant licenses:** MIT (most packages), ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0. These are generally permissive and low risk.
- **Higher-attention licenses:** GPL, LGPL, GFDL. Ensure compliance with copyleft obligations (source distribution, license notices).
- **Recommendations:**
  - Maintain a license policy (allowlist/blocklist).
  - Use Trivy `--scanners license` or Syft license extraction for automated checks.
  - Review GPL/LGPL packages for distribution and linking requirements.

### 2.4 Additional Security Features — Secrets Scanning

- **Trivy secrets scan:** Attempted with `--scanners secret`; output file creation failed due to permissions in the container environment. Trivy supports secret scanning for embedded credentials, API keys, and private keys in image layers.
- **Recommendation:** Run Trivy secret scanning in CI with proper volume mounts; integrate with secret management and rotation workflows.

---

## Task 3 — Toolchain Comparison: Syft+Grype vs Trivy All-in-One

### 3.1 Accuracy Analysis

| Metric | Value |
|--------|-------|
| Packages detected by both tools | 1,126 |
| Packages only in Syft | 13 |
| Packages only in Trivy | 9 |
| CVEs found by Grype | 93 |
| CVEs found by Trivy | 91 |
| Common CVEs (Grype ∩ Trivy) | 26 |

**Observations:**
- Package detection is highly aligned; small differences reflect cataloger and version handling.
- CVE overlap is low (26/93–91); different databases and update cycles lead to complementary findings.
- Running both toolchains improves coverage for both SBOM and vulnerabilities.

### 3.2 Tool Strengths and Weaknesses

| Aspect | Syft + Grype | Trivy |
|--------|--------------|-------|
| **SBOM quality** | Rich metadata, licenses, locations | Good; integrated with vuln scan |
| **Vulnerability coverage** | Anchore DB; good npm coverage | Multi-source; OS + language |
| **Operational model** | Two-step (SBOM → Grype) | Single command |
| **License scanning** | In SBOM | Dedicated `--scanners license` |
| **Secrets** | Not included | Built-in secret scanner |
| **CI/CD** | Two containers/steps | One container |
| **Maintenance** | Two tools to update | Single tool |

### 3.3 Use Case Recommendations

- **Syft + Grype:** Use when you need detailed SBOM metadata, license extraction, and policy-as-code (e.g. In-Toto, SPDX). Fits supply chain and compliance workflows.
- **Trivy:** Use for fast, all-in-one SBOM + vulnerability + license + secret scanning in CI. Good for blocking builds on critical findings.
- **Combined:** Run Syft for SBOM and license audit; run Trivy for vulnerability and secret scanning. Use both for critical images and compliance-sensitive projects.

### 3.4 Integration Considerations

- **CI/CD:** Trivy is easier to integrate (one step). Syft+Grype requires SBOM generation then Grype scan; SBOM can be cached and reused.
- **Automation:** Both support JSON output for parsing and policy enforcement. Trivy supports `--exit-code` for fail-on-findings.
- **Operational overhead:** Trivy: one image, one process. Syft+Grype: two images, two steps; SBOM storage and retention needed.

---

## Summary

- **SBOM:** Syft and Trivy both produced SBOMs with 1,135+ packages. Syft provides slightly richer metadata and license data; Trivy integrates SBOM with vulnerability scanning.
- **SCA:** Grype (93 CVEs) and Trivy (91 CVEs) found similar critical/high issues with limited overlap (26 common). Both should be used for critical images.
- **Critical issues:** vm2 sandbox escape, jsonwebtoken bypass, lodash prototype pollution, crypto-js weak PBKDF2, and OpenSSL RCE/DoS require priority remediation.
- **Toolchain:** Syft+Grype for SBOM and compliance; Trivy for fast, all-in-one scanning. Use both for high-assurance and compliance workflows.
