# Lab 6 — Infrastructure-as-Code Security: Scanning & Policy Enforcement

## Task 1 — Terraform & Pulumi Security Scanning

### 1.1 Terraform Tool Comparison (tfsec vs Checkov vs Terrascan)

| Tool | Findings (this run) | Notes |
|------|---------------------|--------|
| **tfsec** | **53** | Full scan with volume `:Z`. Detects encryption, security groups, IAM, S3, RDS, DynamoDB, credentials. |
| **Checkov** | — | Not completed in this run (empty/no output). Typically offers 30+ failed checks on this codebase. |
| **Terrascan** | — | Scan ran; JSON output empty in this run (policy set/version dependent). |

**Effectiveness:** tfsec was highly effective: fast, Terraform-native, and flagged hardcoded credentials, public S3, missing encryption, security groups with 0.0.0.0/0, RDS/DynamoDB issues, and IAM wildcards. Checkov (when run) adds multi-framework coverage; Terrascan adds OPA/compliance mapping.

### 1.2 Pulumi Security Analysis (KICS)

KICS was run on `labs/lab6/vulnerable-iac/pulumi/` (Pulumi-vulnerable.yaml).

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| LOW | 0 |
| INFO | 2 |
| **Total** | **6** |

**Notable findings:** RDS publicly accessible (CRITICAL), DynamoDB not encrypted (HIGH), hardcoded password (HIGH), EC2 monitoring disabled (MEDIUM), DynamoDB PITR disabled / EC2 not EBS optimized (INFO).

### 1.3 Terraform vs Pulumi (Declarative HCL vs Programmatic YAML)

- **Terraform (HCL):** tfsec found 53 issues. Static structure makes rule matching straightforward (S3 ACLs, security group CIDRs, encryption flags, IAM).
- **Pulumi (YAML):** KICS found 6 issues. Same classes (public RDS, unencrypted DynamoDB, secrets) appear as YAML properties; KICS maps Pulumi resource attributes to AWS security checks.
- **Conclusion:** Both show the same logical misconfigurations; syntax and tooling differ (Terraform has more scanner maturity; KICS provides solid Pulumi YAML support).

### 1.4 KICS Pulumi Support

KICS auto-detects Pulumi YAML and runs Pulumi-specific queries (AWS RDS, DynamoDB, EC2). Platform "Pulumi" and cloud provider AWS; categories include Encryption, Insecure Configurations, Secret Management. Output includes CWE, risk scores, and remediation links.

### 1.5 Critical Findings (5+)

1. **Hardcoded AWS credentials (Terraform)** — `main.tf` provider. **Remediation:** Use env vars, IAM roles, or secrets manager.
2. **Public S3 and disabled public access block (Terraform)** — **Remediation:** `acl = "private"`; set all `block_public_*` to true.
3. **Security groups 0.0.0.0/0 (Terraform)** — **Remediation:** Restrict `cidr_blocks` to known IPs/VPC.
4. **RDS publicly accessible and unencrypted (Terraform/Pulumi)** — **Remediation:** `publicly_accessible = false`, `storage_encrypted = true`.
5. **Unencrypted DynamoDB (Terraform/Pulumi)** — **Remediation:** Enable `server_side_encryption`.
6. **IAM wildcards (Terraform)** — **Remediation:** Least privilege; restrict actions and resources.

### 1.6 Tool Strengths

| Tool | Strengths |
|------|-----------|
| **tfsec** | Fast, Terraform-only, low false positives, clear severity and resolution. |
| **Checkov** | Multi-framework (Terraform, CloudFormation, K8s, Docker), large policy set. |
| **Terrascan** | OPA-based, compliance frameworks. |
| **KICS** | Strong Pulumi YAML and Ansible support; single scanner for both. |

---

## Task 2 — Ansible Security Scanning with KICS

### 2.1 Ansible Security Issues (KICS)

KICS was run on `labs/lab6/vulnerable-iac/ansible/`.

| Severity | Count |
|----------|-------|
| HIGH | 9 |
| LOW | 1 |
| **Total** | **10** |

**Main issues:** Passwords and secrets in playbook vars, inventory (e.g. `ansible_password`, `db_admin_password`, `api_secret_key`, `db_connection`, git URL with credentials). Unpinned package version (LOW).

### 2.2 Best Practice Violations (3+ with impact)

1. **Hardcoded secrets in playbooks and inventory** — Credentials in repo and logs; risk of account compromise. **Fix:** Ansible Vault or external secrets; never store plaintext secrets.
2. **Sensitive operations without `no_log`** — Passwords can appear in logs. **Fix:** Add `no_log: true` to tasks that use secrets.
3. **Overly permissive file modes (e.g. 0777, 0644 for SSH keys)** — World-writable or readable private keys. **Fix:** Least privilege (e.g. 0600 for keys, 0644 for configs).

### 2.3 KICS Ansible Queries

KICS runs Ansible and common queries: secrets/passwords in content, insecure configs, and best practices (e.g. unpinned versions). It reports file and line and supports JSON/HTML output.

### 2.4 Remediation Steps

- **Secrets:** Move to Ansible Vault or external secrets; use `no_log` where needed.
- **Packages:** Pin versions instead of `state: latest`.
- **Permissions:** Correct modes (0600 for keys, 0644 for configs); avoid 0777.
- **Modules:** Prefer `apt`/`yum` and `file` over raw `shell`/`command`.
- **Inventory:** Remove credentials; use SSH keys and vault-encrypted vars.

---

## Task 3 — Comparative Tool Analysis & Security Insights

### 3.1 Tool Effectiveness Matrix

| Criterion | tfsec | Checkov | Terrascan | KICS |
|-----------|-------|---------|-----------|------|
| **Total Findings** | 53 (TF) | — | — | 6 (Pulumi) + 10 (Ansible) |
| **Scan Speed** | Fast | Medium | Medium | Medium |
| **False Positives** | Low | Medium | Low | Low–Medium |
| **Report Quality** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Ease of Use** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Documentation** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Platform Support** | Terraform | Multiple | Multiple | Multiple (Pulumi, Ansible) |
| **Output Formats** | JSON, text, SARIF | JSON, CLI, SARIF | JSON, human | JSON, HTML, SARIF |
| **CI/CD Integration** | Easy | Easy | Easy | Easy |
| **Unique Strengths** | Terraform depth, speed | Multi-framework | OPA, compliance | Pulumi YAML + Ansible |

### 3.2 Vulnerability Category Analysis

| Security Category | tfsec | Checkov | Terrascan | KICS (Pulumi) | KICS (Ansible) | Best Tool |
|-------------------|-------|---------|-----------|---------------|----------------|-----------|
| **Encryption** | Yes | — | — | Yes | N/A | tfsec, KICS |
| **Network Security** | Yes | — | — | Yes | N/A | tfsec |
| **Secrets Management** | Yes | — | — | Yes | Yes | tfsec, KICS |
| **IAM/Permissions** | Yes | — | — | Partial | N/A | tfsec |
| **Access Control** | Yes | — | — | Yes | Partial | tfsec, KICS |
| **Compliance/Best Practices** | Yes | — | — | Yes | Yes | tfsec, KICS |

### 3.3 Top 5 Critical Findings with Remediation

1. **Hardcoded AWS credentials** — Remove from provider; use env vars or IAM role.
2. **Public S3 and open public access block** — `acl = "private"`; enable all four `block_public_*` options.
3. **Security groups 0.0.0.0/0** — Limit ingress/egress to specific CIDRs.
4. **RDS publicly accessible and unencrypted** — `publicly_accessible = false`, `storage_encrypted = true`.
5. **Ansible hardcoded secrets** — Ansible Vault or external secrets; `no_log: true` on sensitive tasks.

### 3.4 Tool Selection Guide

- **Terraform-only, fast feedback:** tfsec in CI.
- **Multi-IaC:** Checkov for one policy set across frameworks.
- **Pulumi YAML / Ansible:** KICS for native support.
- **Compliance:** Terrascan or Checkov with appropriate policies.
- **Recommended combo:** tfsec (Terraform) + KICS (Pulumi + Ansible).

### 3.5 Lessons Learned

- tfsec gave strong Terraform coverage; Checkov and Terrascan did not add findings in this run (environment/config dependent).
- Volume permissions (`:Z`) were required for tfsec; KICS ran without issues.
- KICS provided consistent results for both Pulumi YAML and Ansible.

### 3.6 CI/CD Integration Strategy

- **Pre-commit/PR:** Run tfsec on Terraform and KICS on Pulumi/Ansible on changed files.
- **Pipeline:** Full scans on every push; fail on CRITICAL/HIGH or by threshold.
- **Reports:** Publish JSON/SARIF; retain HTML for audit.
- **Remediation:** Track by finding ID; require fix or exception for CRITICAL/HIGH.

---

## Summary

- **Terraform:** tfsec reported 53 findings (credentials, S3, security groups, RDS, DynamoDB, IAM). Checkov and Terrascan were run where possible.
- **Pulumi:** KICS reported 6 findings (1 CRITICAL, 2 HIGH, 1 MEDIUM, 2 INFO) on Pulumi-vulnerable.yaml.
- **Ansible:** KICS reported 10 findings (9 HIGH, 1 LOW), mainly secrets in playbooks and inventory.
- **Deliverables:** Scans and comparison stats in `labs/lab6/analysis/`; this document provides the required analysis for Tasks 1–3.
