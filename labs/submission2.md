# Lab 2 Submission — Threat Modeling with Threagile

## Task 1 — Threagile Baseline Model

### 1.1: Baseline Threat Model Generation

The baseline threat model was successfully generated using Threagile with the following command:

```bash
docker run --rm -v "/home/alex/courses/DevSecOps-Intro":/app/work:Z threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 1.2: Generated Outputs Verification

The following files were generated in `labs/lab2/baseline/`:
- ✅ `report.pdf` — Full PDF report (includes diagrams)
- ✅ `data-flow-diagram.png` — Data flow diagram
- ✅ `data-asset-diagram.png` — Data asset diagram
- ✅ `risks.json` — Risk export in JSON format
- ✅ `stats.json` — Statistics export
- ✅ `technical-assets.json` — Technical assets export

### 1.3: Risk Analysis and Documentation

#### Risk Ranking Methodology

Composite scores were calculated using the following weights:
- **Severity**: critical (5) > elevated (4) > high (3) > medium (2) > low (1)
- **Likelihood**: very-likely (4) > likely (3) > possible (2) > unlikely (1)
- **Impact**: high (3) > medium (2) > low (1)
- **Composite Score Formula**: `Severity × 100 + Likelihood × 10 + Impact`

#### Top 5 Risks

| Rank | Severity | Category | Asset | Likelihood | Impact | Composite Score |
|------|----------|----------|-------|------------|--------|-----------------|
| 1 | Elevated | Unencrypted Communication | user-browser | likely | high | 433 |
| 2 | Elevated | Unencrypted Communication | reverse-proxy | likely | medium | 432 |
| 3 | Elevated | Missing Authentication | juice-shop | likely | medium | 432 |
| 4 | Elevated | Cross-Site Scripting (XSS) | juice-shop | likely | medium | 432 |
| 5 | Medium | Cross-Site Request Forgery (CSRF) | juice-shop | very-likely | low | 241 |

#### Detailed Risk Descriptions

1. **Unencrypted Communication (Direct to App)**: The direct HTTP connection between User Browser and Juice Shop Application transfers authentication data (credentials, tokens, session IDs) without encryption, making it vulnerable to man-in-the-middle attacks.

2. **Unencrypted Communication (Reverse Proxy to App)**: The HTTP connection between Reverse Proxy and Juice Shop Application lacks encryption, exposing data in transit on the internal network.

3. **Missing Authentication (Reverse Proxy to App)**: The communication link from Reverse Proxy to Juice Shop Application lacks authentication, allowing potential unauthorized access if the proxy is compromised.

4. **Cross-Site Scripting (XSS)**: The Juice Shop Application is vulnerable to XSS attacks, which could allow attackers to execute malicious scripts in users' browsers, potentially stealing session tokens or performing unauthorized actions.

5. **Cross-Site Request Forgery (CSRF)**: The application is vulnerable to CSRF attacks via the direct connection, where malicious websites could trigger unauthorized actions on behalf of authenticated users.

#### Critical Security Concerns

The baseline model reveals several critical security concerns:

1. **Encryption Gaps**: Two unencrypted communication channels expose sensitive authentication data and application traffic to interception.

2. **Authentication Weaknesses**: Missing authentication between the reverse proxy and application creates a trust boundary vulnerability.

3. **Web Application Vulnerabilities**: XSS and CSRF vulnerabilities indicate insufficient input validation and security controls in the application layer.

4. **Overall Risk Profile**: 
   - **Elevated risks**: 4
   - **Medium risks**: 14
   - **Low risks**: 5
   - **Total risks**: 23

#### Diagram References

The generated diagrams (`data-flow-diagram.png` and `data-asset-diagram.png`) illustrate:
- Data flow between User Browser, Reverse Proxy, Juice Shop Application, Persistent Storage, and Webhook Endpoint
- Trust boundaries (Internet, Host, Container Network)
- Data assets and their relationships to technical assets

---

## Task 2 — HTTPS Variant & Risk Comparison

### 2.1: Secure Model Variant Creation

The secure model variant (`threagile-model.secure.yaml`) was created with the following specific changes:

1. **User Browser → Direct to App**: Changed `protocol: http` to `protocol: https`
2. **Reverse Proxy → To App**: Changed `protocol: http` to `protocol: https`
3. **Persistent Storage**: Changed `encryption: none` to `encryption: transparent`

### 2.2: Secure Variant Analysis Generation

The secure variant analysis was generated using:

```bash
docker run --rm -v "/home/alex/courses/DevSecOps-Intro":/app/work:Z threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```

### 2.3: Risk Comparison

#### Risk Category Delta Table

| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| container-baseimage-backdooring | 1 | 1 | 0 |
| cross-site-request-forgery | 2 | 2 | 0 |
| cross-site-scripting | 1 | 1 | 0 |
| missing-authentication | 1 | 1 | 0 |
| missing-authentication-second-factor | 2 | 2 | 0 |
| missing-build-infrastructure | 1 | 1 | 0 |
| missing-hardening | 2 | 2 | 0 |
| missing-identity-store | 1 | 1 | 0 |
| missing-vault | 1 | 1 | 0 |
| missing-waf | 1 | 1 | 0 |
| server-side-request-forgery | 2 | 2 | 0 |
| unencrypted-asset | 2 | 1 | -1 |
| unencrypted-communication | 2 | 0 | -2 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

#### Delta Run Explanation

**Specific Changes Made:**
1. Enabled HTTPS for direct browser-to-application communication
2. Enabled HTTPS for reverse proxy-to-application communication
3. Enabled transparent encryption for persistent storage

**Observed Results in Risk Categories:**

1. **Unencrypted Communication**: Reduced from 2 to 0 risks (-2)
   - The "Direct to App" link risk was eliminated by enabling HTTPS
   - The "Reverse Proxy to App" link risk was eliminated by enabling HTTPS

2. **Unencrypted Asset**: Reduced from 2 to 1 risk (-1)
   - The Persistent Storage encryption risk was eliminated by enabling transparent encryption
   - The Juice Shop Application itself remains unencrypted (application-level encryption not addressed)

**Analysis of Risk Reduction:**

The security improvements had a significant impact on the threat landscape:

1. **Communication Security**: By encrypting both communication links, we eliminated the two highest-scoring risks (composite scores 433 and 432). This prevents:
   - Man-in-the-middle attacks on user-to-application traffic
   - Eavesdropping on internal proxy-to-application traffic
   - Session hijacking through intercepted tokens

2. **Storage Security**: Enabling transparent encryption on persistent storage reduces the risk of data exposure if the storage is compromised, protecting sensitive data at rest (user accounts, orders, logs).

3. **Overall Impact**: 
   - **Baseline**: 4 elevated, 14 medium, 5 low risks (23 total)
   - **Secure**: 2 elevated, 13 medium, 5 low risks (20 total)
   - **Net reduction**: 2 elevated risks, 1 medium risk (3 total risks eliminated)

The changes demonstrate that implementing encryption controls (both in transit and at rest) directly addresses the most critical vulnerabilities identified in the threat model. However, application-level vulnerabilities (XSS, CSRF) and architectural concerns (missing authentication, hardening) remain and require additional security controls.

#### Diagram Comparison

The diagrams between baseline and secure variants show:
- **Data Flow Diagram**: The communication links now show HTTPS protocols instead of HTTP, visually representing the encryption improvements
- **Data Asset Diagram**: The Persistent Storage asset now shows encryption status, reflecting the transparent encryption configuration

The structural architecture remains the same, but the security posture is improved through the encryption controls.

---

## Summary

This lab successfully demonstrated:
1. **Threat modeling as code**: Using Threagile YAML models to generate comprehensive threat analysis
2. **Risk quantification**: Calculating composite risk scores to prioritize security concerns
3. **Security control impact**: Demonstrating how encryption controls directly reduce identified risks
4. **Automated analysis**: Leveraging Threagile's automated risk detection to identify security gaps

The baseline model identified 23 risks, with unencrypted communications being the highest priority. The secure variant reduced this to 20 risks by eliminating 2 unencrypted communication risks and 1 unencrypted asset risk, demonstrating the effectiveness of encryption controls in reducing the threat landscape.

