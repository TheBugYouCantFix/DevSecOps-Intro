# Lab 7 Submission - Container Security

## Environment and Notes

- Target image: `bkimminich/juice-shop:v19.0.0`
- Docker Hub username used: `tbyf217`
- Docker Scout authentication was blocked. `docker login -u tbyf217` failed because the provided token appears to be a GitHub PAT, not a Docker Hub PAT.
- Snyk scan was not executed because no `SNYK_TOKEN` was provided.

## Task 1 - Image Vulnerability and Configuration Analysis

### 1.1 Scan artifacts generated

- `labs/lab7/scanning/scout-cves.txt` (auth blocker note recorded)
- `labs/lab7/scanning/snyk-results.txt` (missing token note recorded)
- `labs/lab7/scanning/dockle-results.txt`

### 1.2 Top 5 Critical/High Vulnerabilities

Docker Scout CVE output could not be collected due to authentication failure.  
The task is blocked until a valid Docker Hub PAT is provided and `docker login` succeeds.

### 1.3 Dockle Configuration Findings

From `dockle-results.txt`:

- `CIS-DI-0005` (INFO): Docker Content Trust not enabled.
  - Security concern: allows unsigned/unverified images to be pulled, increasing supply-chain risk.
- `CIS-DI-0006` (INFO): `HEALTHCHECK` missing in image.
  - Security concern: weak operational visibility; compromised or unhealthy containers can remain undetected.
- `DKL-LI-0003` (INFO): unnecessary files in image (`.DS_Store` files).
  - Security concern: bloated image and unnecessary artifacts that may expose build/process metadata.

No `FATAL` or `WARN` findings were returned in the successful Dockle run.

### 1.4 Security Posture Assessment

- The image likely runs with default/root behavior unless explicitly overridden at runtime.
- Recommended improvements:
  - enforce non-root user (`USER` in Dockerfile),
  - add `HEALTHCHECK`,
  - enable image signing/verification (`DOCKER_CONTENT_TRUST=1` or Sigstore/cosign),
  - reduce image contents and keep packages patched.

## Task 2 - Docker Host Security Benchmarking

### 2.1 Summary Statistics

Using `labs/lab7/hardening/docker-bench-results.txt`:

- PASS: 15
- WARN: 64
- FAIL: 0 (tool output in this run used WARN for non-compliant automated checks)
- INFO: 88

### 2.2 Analysis of Failures/Warnings and Remediation

Key warnings and impact:

- `1.1.x` audit-related warnings (daemon/files/runtime binary auditing not configured)
  - Impact: weak forensic visibility and incident detection.
  - Remediation: configure Linux auditd rules for Docker daemon, socket, and runtime files.
- `2.2` default bridge traffic restrictions missing
  - Impact: easier lateral movement between containers on default networking.
  - Remediation: use user-defined networks and restrict inter-container connectivity.
- `2.9` user namespace support not enabled
  - Impact: weaker host isolation if container escape occurs.
  - Remediation: enable user namespace remapping.
- `2.12` authorization for Docker client commands not enabled
  - Impact: broad Docker API access from daemon-controlling users.
  - Remediation: use authorization plugins / stricter RBAC around Docker socket access.
- `2.13` centralized remote logging not configured
  - Impact: loss of tamper-resistant logs and reduced observability.
  - Remediation: forward logs to centralized logging backend.
- `2.14` no daemon-wide no-new-privileges hardening
  - Impact: higher privilege escalation risk within containers.
  - Remediation: set secure defaults in daemon and enforce at orchestrator/runtime policy layer.
- `2.15` live-restore disabled
  - Impact: daemon restart can disrupt workloads.
  - Remediation: enable live-restore for resilience.
- `2.16` userland-proxy not disabled
  - Impact: unnecessary networking attack surface.
  - Remediation: set `"userland-proxy": false` in daemon config.

## Task 3 - Deployment Security Configuration Analysis

### 3.1 Configuration Comparison Table

| Profile | Capabilities | Security options | Memory | CPU | PIDs | Restart policy |
|---|---|---|---|---|---|---|
| Default | none dropped/added | none | unlimited (`0`) | unlimited | default | `no` |
| Hardened | `CapDrop=[ALL]` | `no-new-privileges` | `512MiB` (`536870912`) | `--cpus=1.0` | default | `no` |
| Production | `CapDrop=[ALL]`, `CapAdd=[NET_BIND_SERVICE]` | `no-new-privileges` | `512MiB` and swap limited (`512MiB`) | `--cpus=1.0` | `100` | `on-failure` |

Evidence source: `labs/lab7/analysis/deployment-comparison.txt`.

### 3.2 Security Measure Analysis

#### a) `--cap-drop=ALL` and `--cap-add=NET_BIND_SERVICE`

- Linux capabilities split root privileges into smaller units.
- Dropping all capabilities reduces post-exploit privilege (limits kernel-level dangerous operations).
- `NET_BIND_SERVICE` is added only when binding privileged ports (<1024) is required.
- Trade-off: better security but may break apps requiring specific capabilities.

#### b) `--security-opt=no-new-privileges`

- Prevents processes from gaining additional privileges (e.g., via setuid binaries).
- Mitigates privilege escalation paths after compromise.
- Downside: some legacy apps depending on setuid/setgid behavior may fail.

#### c) `--memory=512m` and `--cpus=1.0`

- Without limits, a single compromised/buggy container can starve host resources.
- Memory limits reduce impact of memory exhaustion/DoS attacks.
- Limits set too low can cause OOM kills and degraded application performance.

#### d) `--pids-limit=100`

- A fork bomb rapidly creates processes until host resources are exhausted.
- PID limit constrains process explosion to protect the host and neighboring workloads.
- Correct limit depends on normal application process/thread behavior plus safe headroom.

#### e) `--restart=on-failure:3`

- Restarts container only on non-zero exit, up to 3 retries.
- Useful for transient failures; risky if it masks recurring crash-loop root causes.
- `on-failure` is safer than `always` for unstable/broken images because retries are bounded.

### 3.3 Critical Thinking Answers

1. **Best profile for development:** Default or Hardened.  
   Default is easiest for rapid debugging; Hardened is better when teams want secure-by-default dev parity.

2. **Best profile for production:** Production profile.  
   It applies privilege reduction, resource limits, PID limits, and controlled restart behavior.

3. **Real-world problem solved by resource limits:**  
   Noisy-neighbor and denial-of-service conditions where one container consumes excessive CPU/RAM and degrades service for all workloads on the host.

4. **If attacker exploits Default vs Production, what is blocked in Production:**  
   Process explosion is constrained (`--pids-limit`), memory abuse is constrained (`--memory`), privilege escalation vectors are reduced (`no-new-privileges`, dropped capabilities), and runtime permissions are narrower.

5. **Additional hardening to add:**  
   Read-only root filesystem, explicit non-root UID/GID, seccomp profile enforcement, AppArmor/SELinux profile, minimal base image, image signature verification, network policy segmentation, and secret management via runtime secret stores.

## Task Completion Checklist

- [x] Task 1 directory structure and scans attempted
- [x] Dockle analysis completed and documented
- [x] Task 2 benchmark run captured and analyzed
- [x] Task 3 three deployment profiles tested and compared
- [x] Required output files committed under `labs/lab7/`
- [ ] Docker Scout CVE report pending valid Docker Hub PAT
- [ ] Snyk comparison pending valid Snyk token
