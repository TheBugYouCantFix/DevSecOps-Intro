# Pull Request — Lab 2: Threat Modeling with Threagile

## Goal
Complete Lab 2 threat modeling exercise using Threagile to model OWASP Juice Shop deployment, generate baseline and secure variant threat models, and perform comprehensive risk analysis comparing the two configurations.

## Changes
- ✅ Created baseline threat model analysis using `threagile-model.yaml`
- ✅ Generated secure model variant `threagile-model.secure.yaml` with HTTPS and encryption improvements
- ✅ Produced baseline threat model outputs in `labs/lab2/baseline/`:
  - PDF report with diagrams
  - Data flow and data asset diagrams (PNG)
  - Risk exports (risks.json, stats.json, technical-assets.json)
- ✅ Produced secure variant outputs in `labs/lab2/secure/`:
  - PDF report with diagrams
  - Data flow and data asset diagrams (PNG)
  - Risk exports (risks.json, stats.json, technical-assets.json)
- ✅ Created comprehensive submission document `labs/submission2.md` with:
  - Top 5 risks analysis with composite scoring
  - Risk ranking methodology documentation
  - Critical security concerns analysis
  - Risk category delta comparison (baseline vs secure)
  - Delta run explanation and impact analysis

## Testing

### Baseline Model Generation
```bash
docker run --rm -v "/home/alex/courses/DevSecOps-Intro":/app/work:Z threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.yaml \
  -output /app/work/labs/lab2/baseline \
  -generate-risks-excel=false -generate-tags-excel=false
```
**Result**: ✅ Successfully generated all required outputs (PDF, diagrams, JSON exports)

### Secure Variant Generation
```bash
docker run --rm -v "/home/alex/courses/DevSecOps-Intro":/app/work:Z threagile/threagile \
  -model /app/work/labs/lab2/threagile-model.secure.yaml \
  -output /app/work/labs/lab2/secure \
  -generate-risks-excel=false -generate-tags-excel=false
```
**Result**: ✅ Successfully generated all required outputs with reduced risk count

### Risk Comparison Analysis
```bash
jq -n --slurpfile b labs/lab2/baseline/risks.json --slurpfile s labs/lab2/secure/risks.json \
  'def tally(x): (x | group_by(.category) | map({ (.[0].category): length }) | add) // {}; 
   (tally($b[0])) as $B | (tally($s[0])) as $S | ...'
```
**Result**: ✅ Generated risk category delta table showing:
- Unencrypted Communication: 2 → 0 risks (-2)
- Unencrypted Asset: 2 → 1 risk (-1)
- Total risks: 23 → 20 (3 eliminated)

### Model Changes Verification
**Secure Model Changes**:
1. ✅ User Browser → Direct to App: `protocol: http` → `protocol: https`
2. ✅ Reverse Proxy → To App: `protocol: http` → `protocol: https`
3. ✅ Persistent Storage: `encryption: none` → `encryption: transparent`

## Artifacts & Screenshots

### Generated Artifacts

#### Baseline Model Outputs (`labs/lab2/baseline/`)
- `report.pdf` (1.3 MB) — Complete threat model report with diagrams
- `data-flow-diagram.png` (232 KB) — Visual representation of data flows
- `data-asset-diagram.png` (112 KB) — Data asset relationships diagram
- `risks.json` (15.8 KB) — 23 identified risks in JSON format
- `stats.json` (536 B) — Risk statistics summary
- `technical-assets.json` (5.7 KB) — Technical asset definitions

#### Secure Variant Outputs (`labs/lab2/secure/`)
- `report.pdf` (1.3 MB) — Secure variant threat model report
- `data-flow-diagram.png` (233 KB) — Updated data flow diagram with HTTPS
- `data-asset-diagram.png` (113 KB) — Updated data asset diagram
- `risks.json` (13.6 KB) — 20 identified risks (3 fewer than baseline)
- `stats.json` (536 B) — Updated risk statistics
- `technical-assets.json` (5.7 KB) — Technical asset definitions

### Risk Analysis Results

#### Top 5 Risks (Baseline Model)
| Rank | Severity | Category | Asset | Likelihood | Impact | Composite Score |
|------|----------|----------|-------|------------|--------|-----------------|
| 1 | Elevated | Unencrypted Communication | user-browser | likely | high | 433 |
| 2 | Elevated | Unencrypted Communication | reverse-proxy | likely | medium | 432 |
| 3 | Elevated | Missing Authentication | juice-shop | likely | medium | 432 |
| 4 | Elevated | Cross-Site Scripting (XSS) | juice-shop | likely | medium | 432 |
| 5 | Medium | Cross-Site Request Forgery (CSRF) | juice-shop | very-likely | low | 241 |

#### Risk Category Comparison
| Category | Baseline | Secure | Δ |
|---|---:|---:|---:|
| unencrypted-communication | 2 | 0 | **-2** |
| unencrypted-asset | 2 | 1 | **-1** |
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
| container-baseimage-backdooring | 1 | 1 | 0 |
| unnecessary-data-transfer | 2 | 2 | 0 |
| unnecessary-technical-asset | 2 | 2 | 0 |

**Key Findings**:
- **Total Risk Reduction**: 23 → 20 risks (13% reduction)
- **Elevated Risk Reduction**: 4 → 2 risks (50% reduction)
- **Medium Risk Reduction**: 14 → 13 risks
- **Low Risks**: 5 (unchanged)

### Security Improvements Demonstrated

1. **Encryption in Transit**: 
   - Eliminated 2 unencrypted communication risks by enabling HTTPS
   - Protected authentication data (credentials, tokens, session IDs) from interception
   - Secured internal proxy-to-application communication

2. **Encryption at Rest**:
   - Reduced unencrypted asset risks by enabling transparent encryption on persistent storage
   - Protected sensitive data (user accounts, orders, logs) if storage is compromised

3. **Overall Security Posture**:
   - Reduced highest-scoring risks (composite scores 433 and 432)
   - Maintained application-level security concerns (XSS, CSRF) requiring additional controls

## Checklist
- [x] Clear, descriptive PR title
- [x] Documentation updated (`labs/submission2.md` created)
- [x] No secrets or large temporary files committed
- [x] Task 1 completed — Threagile baseline model + risk analysis
- [x] Task 2 completed — HTTPS variant + risk comparison
- [x] All required artifacts generated and verified
- [x] Risk analysis methodology documented
- [x] Delta comparison table generated and analyzed

---

## Summary

This PR completes Lab 2 requirements by:
1. **Modeling** the OWASP Juice Shop deployment with Threagile
2. **Generating** comprehensive threat model reports and diagrams
3. **Analyzing** baseline risks with composite scoring methodology
4. **Creating** a secure variant with HTTPS and encryption controls
5. **Comparing** risk landscapes to demonstrate security control effectiveness
6. **Documenting** findings in a structured submission document

The analysis demonstrates that implementing encryption controls (HTTPS for communication and transparent encryption for storage) directly addresses the highest-priority risks identified in the threat model, reducing total risks by 13% and elevated risks by 50%.


