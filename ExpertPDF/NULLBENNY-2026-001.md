# Security Advisory: Server-Side Request Forgery in ExpertPDF HtmlToPdf Converter

**Advisory ID:** NULLBENNY-2026-001
**CVE:** Pending assignment
**Date:** 18 July 2026
**Researcher:** nullbenny
**Vendor:** ExpertPDF (html-to-pdf.net)
**Vendor notified:** 25 June 2026
**Supplement sent:** 28 June 2026
**Public disclosure date:** 23 September 2026

---

## Summary

Server-Side Request Forgery (SSRF) in the HTML rendering component of ExpertPDF
HtmlToPdf Converter (NuGet: `ExpertPdfHtmlToPdf` / `ExpertPdf.HtmlToPdf.NetCore`)
versions 12.2.0 through 21.1.0 allows a remote attacker who controls HTML input
passed to `PdfConverter.GetPdfBytesFromHtmlString()` to induce outbound HTTP requests
to arbitrary attacker-specified URLs via resource-loading tags such as `<iframe>` and
`<img>`. Responses to `<iframe>` requests are rendered into the generated PDF, enabling
retrieval of internal and link-local resources, including AWS IMDSv1 instance metadata,
which can disclose temporary IAM credentials.

This issue is distinct from CVE-2020-35340 (CWE-552, local file inclusion via
`file://`, fixed in 15.0.0). The vendor's `AllowLocalAccess` control introduced in
15.0.0 does not mitigate this SSRF — outbound HTTP requests fire regardless of the
flag's value.

---

## Affected Versions

| Package | Confirmed vulnerable | Confirmed fixed |
|---|---|---|
| `ExpertPdf.HtmlToPdf.NetCore` | 12.2.0, 21.1.0 (tested) | None — present in latest |
| `ExpertPdfHtmlToPdf` | Presumed same range | None — present in latest |

All versions between 12.2.0 and 21.1.0 are presumed affected (same conversion engine;
not individually tested). 12.2.0 is the tested lower bound, not the introduction point.

---

## Vulnerability Details

### CWE
CWE-918: Server-Side Request Forgery

### CVSS v3.1
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N`

Note: `PR` is context-dependent — the PDF generation feature is often authenticated,
which raises this metric. `C:H` reflects IMDSv1 credential disclosure where applicable;
confidentiality impact is lower where IMDSv2 is enforced. Reasonable assessors may land
between High and Critical depending on deployment context.

### Root Cause
`PdfConverter.GetPdfBytesFromHtmlString()` passes caller-supplied HTML to the default
WebKit rendering engine (`AppleWebKit/538.1`, UA: `Mozilla/5.0 (Windows NT 6.2; WOW64)
AppleWebKit/538.1 (KHTML, like Gecko) ExpertPdf/21.1.0 Safari/538.1`). The engine
resolves and fetches resources referenced in HTML tags without validating or restricting
the destination URL. No blocklist for private ranges or link-local addresses is applied.

### Primitives

**`<iframe>` — exfiltration primitive.**
The fetched HTTP response body is rendered into the output PDF. The recipient of the
generated PDF can read the response content directly from the file. Demonstrated against
the AWS IMDSv1 credential endpoint: the rendered PDF contained `AccessKeyId`,
`SecretAccessKey`, `Token`, and `Expiration` fields in plaintext.

**`<img>`, `<object>`, `<embed>` — reach primitives (blind).**
Requests are issued but non-image responses are not rendered into the PDF. Sufficient
for internal host/port enumeration and reaching internal-only endpoints.

### JavaScript Execution (Default WebKit Engine)
The default WebKit engine ships with scripting enabled (`ScriptsEnabled = True`,
`ScriptsEnabledInImage = True`, `PluginsEnabled = True`). ES5 scripts execute during
rendering. An injected `<script>` can:

- Fire outbound `XMLHttpRequest` GET requests (confirmed: listener hit on `/js-xhr-fired`)
- Loop requests across a port range, turning the blind SSRF into scriptable internal
  port/host enumeration (confirmed: listener hit on `/scan-8080`)

Script-initiated network capability is partially constrained on the default WebKit engine:

- **Response read-back is blocked.** Synchronous XHR throws `NETWORK_ERR: XMLHttpRequest
  Exception 101`; asynchronous XHR returns `readyState 4` with status 0 and empty body
  (`ASYNC_RS4_status0_body[]`).
- **`PUT` with custom headers is blocked.** No listener hit on `/js-put-fired`.
- **ES6 is not available.** `fetch()` is undefined; ES6 probes were false negatives.

**IMDSv2 is not reachable via this vector on the default WebKit engine.** The v2 token
handshake requires `PUT` (blocked), a custom token header (blocked), and response
read-back (blocked, sync and async). All three prerequisites are independently blocked.
This conclusion is evidenced by tested results, not inferred from absence of scripting.

### XXE: Tested, Negative
The SVG/XML parser was probed for external entity resolution via reflected general
entities and OOB parameter entities across `<img>`, `<object>`, `<embed>`, and
`<iframe>`. No external DTD fetch occurred; no entity content was reflected in output.
XXE (CWE-611) is not exploitable in the default engine.

---

## Distinctness from CVE-2020-35340

| | CVE-2020-35340 | This advisory |
|---|---|---|
| Weakness | CWE-552 (local file inclusion, `file://`) | CWE-918 (SSRF, outbound `http://`) |
| Impact | Local file read | Internal network access; IAM credential disclosure |
| Affected versions | 9.5.0–14.1.0 | 12.2.0–21.1.0 |
| Mitigated by `AllowLocalAccess`? | Yes (fixed in 15.0.0) | **No — confirmed: SSRF fires with flag set to `false`** |

The `AllowLocalAccess` flag was tested with matched-pair runs (`GET /run-allow-true`
and `GET /run-allow-false` both hit the listener). The control gates local file access
only. The vendor's own fix for the sibling vulnerability does not mitigate this one.

The vendor's decision to patch `file://` fetching in 15.0.0 demonstrates they consider
attacker-controlled resource fetching to be a vulnerability class. The `http://` half of
the same subsystem was not addressed and remains open through the current release.

---

## Impact (Tiered by Deployment)

| Deployment | Impact |
|---|---|
| AWS, IMDSv1 enabled | Temporary IAM credential disclosure via `<iframe>` render into PDF. Confirmed end-to-end. |
| AWS, IMDSv2 enforced | Credential disclosure not achievable (PUT/custom-header/read-back all blocked on default WebKit). Reduces to blind SSRF. |
| Any cloud or on-premises | SSRF to internal/loopback services; scriptable internal port/host enumeration. |

---

## Proof of Concept

Passed to `PdfConverter.GetPdfBytesFromHtmlString()` with default settings:

```html
<!-- IMDSv1 credential disclosure (AWS) -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>"
        width="800" height="600"></iframe>

<!-- General SSRF to internal service -->
<iframe src="http://127.0.0.1:8080/internal-service"
        width="800" height="600"></iframe>
```

```csharp
var converter = new PdfConverter();
// default settings: ScriptsEnabled=True, AllowLocalAccess=True, RenderingEngine=WebKit
byte[] pdf = converter.GetPdfBytesFromHtmlString(html, null);
File.WriteAllBytes("out.pdf", pdf);
// open out.pdf — response content is rendered into the document
```

**Verified on:** `ExpertPdf.HtmlToPdf.NetCore` 12.2.0 and 21.1.0, .NET 8.0,
Windows Server 2022, Windows Server 2025, default WebKit engine.

> Credential hygiene: any test that renders live IAM credentials into a PDF should
> treat that file as a secret. Rotate credentials immediately and use only redacted
> screenshots in any disclosure or report.

---

## Remediation

1. **Provide a secure-by-default option to disable external URL fetching entirely.**
   The current `AllowLocalAccess` property mitigates only `file://` access. An
   equivalent control for outbound HTTP should default to `false` (deny), requiring
   callers to explicitly opt in.

2. **Block link-local and RFC 1918 ranges by default.** The 169.254.0.0/16 and RFC 1918
   address ranges should be blocked in the resource loader. Validate by resolving the
   hostname first, then checking the resolved IP — not just the URL string — to prevent
   DNS rebinding. Re-validate on every redirect hop.

3. **Offer URL allowlisting.** Provide a mechanism for callers to specify an explicit
   list of permitted origins/hosts.

4. **Default scripting and plugins to off.** `ScriptsEnabled`, `ScriptsEnabledInImage`,
   and `PluginsEnabled` all default to `True`. Script execution on attacker-controlled
   HTML amplifies the SSRF reach. These should default to `False` when rendering
   untrusted input.

5. **Document the risk.** The API documentation should clearly state that passing
   unsanitized user-controlled HTML to the converter exposes the server to SSRF and
   internal resource access.

---

## Evidence Summary

| Claim | Evidence |
|---|---|
| SSRF fires on 21.1.0 (default settings) | Listener `GET /internal-service`; UA `AppleWebKit/538.1 … ExpertPdf/21.1.0` |
| SSRF fires on 12.2.0 | Per-version listener hit |
| `<iframe>` renders response into PDF | IMDSv1 credential JSON rendered into PDF output (redacted screenshot) |
| `AllowLocalAccess=false` does not mitigate | Matched-pair listener hits: `GET /run-allow-true` and `GET /run-allow-false` |
| LFI (CVE-2020-35340) fixed at default | `file://` default-settings run produced no response |
| Default config: scripting on | Property dump: `ScriptsEnabled=True`, `ScriptsEnabledInImage=True`, `PluginsEnabled=True`, `RenderingEngine=WebKit` |
| ES5 script executes | `js_es5_dom.pdf` → `EXECUTED_2` |
| Script fires outbound GET | Listener `GET /js-xhr-fired` |
| Scriptable port scan | Listener `GET /scan-8080` (scripted loop) |
| Sync read-back blocked | `js_es5_xhr.pdf` → `NETWORK_ERR: XMLHttpRequest Exception 101` |
| Async read-back blocked | `js_async_readback.pdf` → `ASYNC_RS4_status0_body[]` |
| PUT + custom header blocked | No `/js-put-fired` listener hit |
| ES6 unavailable | `js_es6_fetch.pdf` (fetch undefined) |
| XXE negative | No `/evil.dtd` fetch; no entity reflection |

All network evidence was captured against a local listener with synthetic tokens.
No real metadata endpoint or live credentials appear in the scripting evidence.
The IMDSv1 iframe result is a redacted screenshot with credentials rotated.

---

## Disclosure Timeline

| Date | Event |
|---|---|
| 25 Jun 2026 | Initial disclosure to vendor (office@html-to-pdf.net) |
| 28 Jun 2026 | Supplement sent — corrected JS findings, confirmed AllowLocalAccess result |
| 12 Jul 2026 | Final chase email sent; 16 Jul deadline stated for CVE filing |
| 18 Jul 2026 | No vendor response after 23 days. CVE requested via MITRE CNA-LR. |
| 12 Jul 2026 | Advisory finalised |
| 23 Sep 2026 | Public disclosure date (90 days from initial vendor contact) |

---

## References

- CVE-2020-35340 — prior local file inclusion in ExpertPDF HtmlToPdf Converter
- CWE-918: Server-Side Request Forgery
- ExpertPDF NuGet: https://www.nuget.org/packages/ExpertPdf.HtmlToPdf.NetCore
- Vendor: https://www.html-to-pdf.net
