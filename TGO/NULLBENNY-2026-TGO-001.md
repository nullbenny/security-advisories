# Security Advisory: Server-Side Request Forgery via Missing Authorization in tgo Workflow API Node

**Advisory ID:** NULLBENNY-2026-TGO-001
**CVE:** Pending assignment
**Date:** 28 September 2026
**Researcher:** nullbenny
**Vendor:** tgoai (github.com/tgoai/tgo)
**Vendor notified:** 28 June 2026 (GitHub issue #43)
**Follow-up sent:** 1 July 2026
**Public disclosure date:** 26 September 2026

---

## Summary

The `tgo-workflow` service in tgoai/tgo v0.5.0 (commit `995da45`) exposes a
Server-Side Request Forgery (SSRF, CWE-918) that is reachable by the lowest-privilege
authenticated user due to a Missing Authorization flaw (CWE-862). The workflow "api"
node type passes user-supplied `url`, `method`, `headers`, and `body` fields directly to
`httpx.AsyncClient.request()` with no destination validation, scheme restriction, or
private-range blocklist, and returns the full response body as node output.

Because the node supports arbitrary HTTP methods and custom request headers, the complete
AWS IMDSv2 token handshake (a `PUT` to mint a token followed by a `GET` carrying the token
header) can be performed natively using the product's own workflow automation feature.
The same mechanism reaches the metadata services of Azure, GCP, Alibaba Cloud, and Tencent
Cloud. On EC2 instances with IMDSv1 enabled, a single `GET` node retrieves IAM credentials
directly.

Although outbound HTTP from a workflow node is an intended feature, the workflow create and
execute endpoints are gated only by a login check with no role filter. The same codebase
applies a role-based permission check to other administrative functions. Workflow
management received no equivalent gate, making the SSRF exploitable by the `agent` role
with no administrator involvement.

---

## Affected Versions

| Component | Confirmed vulnerable | Confirmed fixed |
|---|---|---|
| `tgoai/tgo` (`tgo-workflow` service) | v0.5.0 (commit `995da45`, tested) | None — present in tested release |

v0.5.0 is the tested version. Earlier and later versions sharing the same `api` node
implementation and endpoint authorization model are presumed affected but were not
individually tested.

---

## Vulnerability Details

### CWE
- **CWE-918:** Server-Side Request Forgery (the `api` node makes unvalidated outbound requests)
- **CWE-862:** Missing Authorization (the endpoints that reach the node lack a role check)

The two weaknesses compound: the SSRF is the technical primitive, and the missing
authorization is what lowers the barrier from "administrator-only feature" to
"any authenticated user."

### CVSS v3.1
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N` — Base score 8.5 (High)

Notes on the metrics:
- `PR:L` reflects that a valid low-privilege account (`agent` role) is required. No
  administrator access and no user interaction are needed.
- `S:C` (scope changed) reflects the SSRF crossing a trust boundary — the workflow
  service's network position is used to obtain the credentials or internal responses of a
  separate security authority (the cloud instance / internal services).
- `C:H` reflects IAM credential disclosure (IMDSv1 directly, or IMDSv2 via the full
  handshake) and retrieval of arbitrary internal response bodies.
- `I:L` is conservative. Arbitrary method and body control (`PUT`/`POST`/`DELETE` to
  internal services) can support integrity impact on reachable internal systems; assessors
  who weight that capability may score integrity higher.

### Root Cause — SSRF (CWE-918)
The `api` node handler forwards the caller-controlled `url`, `method`, `headers`, and
`body` fields to `httpx.AsyncClient.request()` without:

- validating or restricting the destination URL,
- restricting the URL scheme,
- blocking link-local (169.254.0.0/16, 100.100.100.200) or RFC 1918 ranges,
- validating the resolved IP after DNS resolution.

The full HTTP response body is returned to the caller as the node's output, making the
SSRF a direct read primitive rather than a blind one. Combined with arbitrary method and
header control, this is a maximally capable SSRF: it can perform multi-step authenticated
handshakes against metadata endpoints, not only simple `GET` retrieval.

### Root Cause — Missing Authorization (CWE-862)
The workflow create and execute endpoints (`ai_workflows.py`, lines 69 and 296 at commit
`995da45`) depend only on `get_current_active_user` — a check that the request carries a
valid session for an active account. No role or permission filter is applied.

By contrast, the same codebase applies `require_permission()` to staff management
(`staff.py`, lines 146 and 201) and to AI agent configuration. Workflow management, which
grants outbound network capability, was left without an equivalent gate. This is an
inconsistency within the product's own access-control model rather than a deliberate design
choice: the project already has and uses a role-based permission primitive, and simply did
not apply it here.

The practical consequence is that the SSRF is reachable by the lowest-privilege staff role
(`agent`), verified with an `agent`-role JWT (`role: agent`).

### Confirmed Exploitation Chain (IMDSv2)
Executed end-to-end against a local listener with synthetic tokens:

1. An `api` node issued a `PUT` to the token endpoint with the required custom header.
2. The synthetic token was returned in the node output (the response body is exposed).
3. A follow-up `api` node issued a `GET` carrying the captured token in a request header.
4. The full response body was returned as node output.

The request chain was executed under an `agent`-role JWT. Outbound requests originated from
the workflow worker container (`172.22.0.9`) with engine `python-httpx/0.27.2`.

Because the `api` node performs all three IMDSv2 prerequisites natively — `PUT`, custom
request headers, and response read-back — IMDSv2 does not mitigate this vector. (This is the
key contrast with resource-loader SSRFs constrained to `GET`-style fetches, where IMDSv2
enforcement blocks credential retrieval.)

---

## Impact (Tiered by Deployment)

| Deployment | Impact |
|---|---|
| AWS, IMDSv1 enabled | IAM credential disclosure via a single `GET` node. |
| AWS, IMDSv2 enforced | IAM credential disclosure via the full `PUT`/`GET` handshake, executed natively by the node. IMDSv2 does not mitigate. |
| Azure / GCP / Alibaba / Tencent | Cloud metadata retrieval using the provider's required header (`Metadata: true`, `Metadata-Flavor: Google`, etc.) or endpoint (`100.100.100.200`). |
| Any cloud or on-premises | SSRF to internal/loopback services with arbitrary method, headers, and body; full response bodies returned to a low-privilege authenticated user. |

The missing-authorization flaw applies to every tier: in each case the attacker needs only
an `agent`-role account, not administrator access.

---

## Proof of Concept

The following describes the workflow node configuration that demonstrates the issue. It is
illustrative of the vulnerability class; values below target a local listener with synthetic
tokens rather than a live metadata endpoint.

**Node 1 — mint token (arbitrary `PUT` with custom header):**

```
type:    api
method:  PUT
url:     http://<listener>/latest/api/token
headers: { "<token-ttl-header>": "21600" }
```

The response body (the token) is returned as this node's output.

**Node 2 — retrieve with token (arbitrary `GET` with custom header):**

```
type:    api
method:  GET
url:     http://<listener>/latest/meta-data/iam/security-credentials/<role>
headers: { "<token-header>": "<token from node 1 output>" }
```

The full response body is returned as node output. On a live IMDSv1 instance, Node 2 alone
(no token) returns IAM credentials.

Both nodes were created and executed under an `agent`-role JWT via the workflow endpoints,
with no administrator action.

> Credential hygiene: any test that returns live IAM credentials into a workflow node output
> should treat that output as a secret. Rotate credentials immediately and use only redacted
> evidence in any report. All evidence for this advisory was captured against a local
> listener with synthetic tokens.

---

## Remediation

1. **Apply role-based authorization to workflow endpoints.** Gate the workflow create and
   execute endpoints (`ai_workflows.py` lines 69, 296) with the same `require_permission()`
   primitive already used for staff management and agent configuration. This closes the
   privilege-escalation path (CWE-862) even before the SSRF is addressed.

2. **Validate and restrict `api` node destinations.** Enforce a scheme allowlist (`https`,
   optionally `http`) and block link-local and RFC 1918 ranges by default, including
   169.254.0.0/16 and 100.100.100.200. Resolve the hostname first and validate the resolved
   IP — not the URL string — and re-validate on every redirect hop to prevent DNS rebinding.

3. **Offer destination allowlisting.** Provide an administrator-configured allowlist of
   permitted hosts/origins for `api` nodes, defaulting to deny for private ranges.

4. **Consider restricting arbitrary methods/headers on outbound nodes,** or at least gating
   that capability behind a higher-privilege role, since arbitrary `PUT`/custom-header
   requests are what enable the IMDSv2 handshake and internal writes.

5. **Document the risk.** State clearly in the workflow documentation that `api` nodes make
   outbound requests from the server's network position and must be treated as a
   privileged capability.

---

## Evidence Summary

| Claim | Evidence |
|---|---|
| SSRF fires from `api` node | Listener hit from workflow worker container `172.22.0.9`, engine `python-httpx/0.27.2` |
| Arbitrary `PUT` with custom header | Listener recorded `PUT` with the custom header set |
| Response body returned as node output | Synthetic token captured in node output |
| Full IMDSv2 handshake works natively | Token from node 1 injected into node 2 header; full body returned |
| Reachable by lowest-privilege role | Chain executed under `agent`-role JWT (`role: agent`) |
| Missing authorization on endpoints | `ai_workflows.py` lines 69, 296 use only `get_current_active_user` |
| Role check exists elsewhere in codebase | `staff.py` lines 146, 201 use `require_permission()` |

All network evidence was captured against a local listener with synthetic tokens. No live
metadata endpoint or real credentials appear in the evidence.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 28 Jun 2026 | Initial disclosure to vendor via GitHub issue #43 |
| 1 Jul 2026 | Follow-up email sent to the maintainer |
| 26 Sep 2026 | Public disclosure date (90 days from initial vendor contact); no vendor response received |

---

## References

- CWE-918: Server-Side Request Forgery
- CWE-862: Missing Authorization
- Vendor repository: https://github.com/tgoai/tgo
- Vendor issue: https://github.com/tgoai/tgo/issues/43
