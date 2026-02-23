## Lab 3 — Secure Git Submission

### Task 1 — SSH Commit Signature Verification

#### 1.1 Benefits of Signing Commits

Signing commits with SSH keys provides cryptographic verification that:
- **Authenticity**: Commits really came from the expected developer identity, not an impersonator.
- **Integrity**: The commit contents have not been modified since they were signed.
- **Non-repudiation (practical)**: It is much harder for someone to deny authorship of a signed commit associated with their key.

In DevSecOps workflows, this reduces the risk of:
- Malicious actors injecting backdoors into the repository.
- Accidental or unauthorized changes being trusted as if they were legitimate.
- Supply-chain attacks where attackers try to spoof trusted contributors.

#### 1.2 SSH Key Generation and Setup

SSH signing key generated for GitHub usage:

```bash
ssh-keygen -t ed25519 -C "github-devsecops" -f "$HOME/.ssh/github-devsecops" -N ""
```

Resulting public key (to be added to GitHub as a **signing** key):

```text
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZoVFmVwvJqr51SopxKUG97umITbzhsG2+whjZjfD96 github-devsecops
```

**Next steps for GitHub (manual):**
- Add this public key in GitHub under `Settings → SSH and GPG keys → New SSH key` as an **SSH signing key**.
- Ensure the email on commits matches the GitHub account for the \"Verified\" badge to appear.

**Git configuration (to be run manually by the user):**

```bash
git config --global user.signingkey "$HOME/.ssh/github-devsecops.pub"
git config --global gpg.format ssh
git config --global commit.gpgSign true
```

After configuration, a signed commit can be created with:

```bash
git commit -S -m "docs: add commit signing summary"
```

On GitHub, this commit should display the **\"Verified\"** badge once the SSH signing key is correctly registered.

#### 1.3 Why Commit Signing is Critical in DevSecOps

In DevSecOps, code moves quickly from development to production through automated pipelines. If commit authorship and integrity are not verifiable:
- CI/CD pipelines might build and deploy malicious or tampered code.
- Audits and incident investigations become unreliable because commit history cannot be trusted.
- Attackers can exploit weak identity guarantees to perform supply-chain attacks.

SSH commit signing ensures that:
- Only holders of authorized SSH signing keys can produce verified commits.
- Build systems and reviewers can **trust the provenance** of code changes.
- Security policies can require verified commits before merging or deploying.

This creates a cryptographic trust layer over the entire Git-based workflow, aligning with DevSecOps principles of shifting security left and enforcing security by default.

---

### Task 2 — Pre-commit Secret Scanning

#### 2.1 Pre-commit Hook Setup

Pre-commit hook file created at `.git/hooks/pre-commit` with the following behavior:
- Collects **staged** files (added/changed, not deleted).
- Splits files into:
  - `lectures/*` (educational content, allowed to contain example secrets).
  - All other files (must be free of secrets).
- Runs **TruffleHog** against non-lectures files using Docker.
- Runs **Gitleaks** against each staged file using Docker.
- **Blocks the commit** if:
  - TruffleHog finds potential secrets in non-lectures files, or
  - Gitleaks finds leaks in non-lectures files.
- **Allows the commit with a warning** if:
  - Gitleaks finds leaks only in `lectures/*`.

Hook installed and made executable:

```bash
cat > .git/hooks/pre-commit << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[pre-commit] scanning staged files for secrets…"

# Collect staged files (added/changed)
mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACM)
if [ ${#STAGED[@]} -eq 0 ]; then
   echo "[pre-commit] no staged files; skipping scans"
   exit 0
fi

FILES=()
for f in "${STAGED[@]}"; do
   [ -f "$f" ] && FILES+=("$f")
done
if [ ${#FILES[@]} -eq 0 ]; then
   echo "[pre-commit] no regular files to scan; skipping"
   exit 0
fi

echo "[pre-commit] Files to scan: ${FILES[*]}"

NON_LECTURES_FILES=()
LECTURES_FILES=()
for f in "${FILES[@]}"; do
   if [[ "$f" == lectures/* ]]; then
      LECTURES_FILES+=("$f")
   else
      NON_LECTURES_FILES+=("$f")
   fi
done

echo "[pre-commit] Non-lectures files: ${NON_LECTURES_FILES[*]:-none}"
echo "[pre-commit] Lectures files: ${LECTURES_FILES[*]:-none}"

TRUFFLEHOG_FOUND_SECRETS=false
if [ ${#NON_LECTURES_FILES[@]} -gt 0 ]; then
   echo "[pre-commit] TruffleHog scan on non-lectures files…"
   
   set +e
   TRUFFLEHOG_OUTPUT=$(docker run --rm -v "$(pwd):/repo" -w /repo \
      trufflesecurity/trufflehog:latest \
      filesystem "${NON_LECTURES_FILES[@]}" 2>&1)
   TRUFFLEHOG_EXIT_CODE=$?
   set -e    
   echo "$TRUFFLEHOG_OUTPUT"
   
   if [ $TRUFFLEHOG_EXIT_CODE -ne 0 ]; then
      echo "[pre-commit] ✖ TruffleHog detected potential secrets in non-lectures files"
      TRUFFLEHOG_FOUND_SECRETS=true
   else
      echo "[pre-commit] ✓ TruffleHog found no secrets in non-lectures files"
   fi
else
   echo "[pre-commit] Skipping TruffleHog (only lectures files staged)"
fi

echo "[pre-commit] Gitleaks scan on staged files…"
GITLEAKS_FOUND_SECRETS=false
GITLEAKS_FOUND_IN_LECTURES=false

for file in "${FILES[@]}"; do
   echo "[pre-commit] Scanning $file with Gitleaks..."
   
   GITLEAKS_RESULT=$(docker run --rm -v "$(pwd):/repo" -w /repo \
      zricethezav/gitleaks:latest \
      detect --source="$file" --no-git --verbose --exit-code=0 --no-banner 2>&1 || true)
   
   if [ -n "$GITLEAKS_RESULT" ] && echo "$GITLEAKS_RESULT" | grep -q -E "(Finding:|WRN leaks found)"; then
      echo "Gitleaks found secrets in $file:"
      echo "$GITLEAKS_RESULT"
      echo "---"
      
      if [[ "$file" == lectures/* ]]; then
            echo "⚠️ Secrets found in lectures directory - allowing as educational content"
            GITLEAKS_FOUND_IN_LECTURES=true
      else
            echo "✖ Secrets found in non-excluded file: $file"
            GITLEAKS_FOUND_SECRETS=true
      fi
   else
      echo "[pre-commit] No secrets found in $file"
   fi
done

echo ""
echo "[pre-commit] === SCAN SUMMARY ==="
echo "TruffleHog found secrets in non-lectures files: $TRUFFLEHOG_FOUND_SECRETS"
echo "Gitleaks found secrets in non-lectures files: $GITLEAKS_FOUND_SECRETS"
echo "Gitleaks found secrets in lectures files: $GITLEAKS_FOUND_IN_LECTURES"
echo ""

if [ "$TRUFFLEHOG_FOUND_SECRETS" = true ] || [ "$GITLEAKS_FOUND_SECRETS" = true ]; then
   echo -e "✖ COMMIT BLOCKED: Secrets detected in non-excluded files." >&2
   echo "Fix or unstage the offending files and try again." >&2
   exit 1
elif [ "$GITLEAKS_FOUND_IN_LECTURES" = true ]; then
   echo "⚠️ Secrets found only in lectures directory (educational content) - allowing commit."
fi

echo "✓ No secrets detected in non-excluded files; proceeding with commit."
exit 0
EOF

chmod +x .git/hooks/pre-commit
```

#### 2.2 Secret Detection Testing (to perform locally)

**Test 1 — Block commit with fake secret:**
1. Add a fake AWS key to a non-lectures file, for example:
   ```bash
   echo 'AWS_SECRET_ACCESS_KEY=FAKEKEY1234567890' >> labs/test-secrets.txt
   git add labs/test-secrets.txt
   git commit -m "test: add fake secret"
   ```
2. Expected behavior:
   - TruffleHog and/or Gitleaks detect the secret.
   - Commit is **blocked** with a clear error message.

**Test 2 — Allow commit after fixing secret:**
1. Remove/redact the secret:
   ```bash
   sed -i 's/AWS_SECRET_ACCESS_KEY=FAKEKEY1234567890/AWS_SECRET_ACCESS_KEY=<redacted>/' labs/test-secrets.txt
   git add labs/test-secrets.txt
   git commit -m "test: remove fake secret"
   ```
2. Expected behavior:
   - Scans run and find no secrets in non-lectures files.
   - Commit **succeeds**.

#### 2.3 How Automated Secret Scanning Prevents Incidents

Automated secret scanning in pre-commit hooks:
- **Prevents accidental credential leaks** before they enter Git history (much harder to fully remove later).
- **Shifts security left** by enforcing checks at the earliest point in the workflow (developer laptop).
- **Reduces incident response burden**: fewer leaked secrets to rotate, fewer emergency security incidents.
- **Standardizes security controls** across the team by embedding them into Git workflows rather than relying on ad-hoc manual checks.

In DevSecOps pipelines, this means:
- Repositories are less likely to contain real API keys, tokens, or passwords.
- Downstream systems (CI, artifact repositories, production) are less likely to be compromised through leaked credentials.
- Security becomes an always-on, automated gate instead of an afterthought.

