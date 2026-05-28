**Task 1 — Triage And Rank**

1. **CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS stack overflow**

   Most exploitable in this set based on the details given. The bug is a straightforward kernel-context stack overflow with a large attacker-controlled copy: 400-byte credential body into 96 bytes of remaining stack buffer, yielding up to 304 bytes of overwrite. The affected path is reachable through NFS/RPCSEC_GSS handling, and the target environment is unusually favorable because FreeBSD reportedly lacks KASLR and stack canaries by default. Compared with browser bugs, this has fewer modern mitigation layers between corruption and kernel control, assuming the service is exposed/reachable.

2. **CVE-2024-4947 — Chromium V8 type confusion**

   Very exploitable in practice because it is a V8 type confusion reachable by a crafted HTML page and is listed in CISA KEV, meaning real-world exploitation occurred or was credibly observed. The main reason it ranks below the FreeBSD issue is mitigation depth: exploitation must generally survive V8 hardening and then remains inside the V8 sandbox unless paired with an additional escape. Still, browser drive-by reachability and known exploitation make it highly practical.

3. **CVE-2024-7965 — Chromium V8 heap corruption**

   Also highly exploitable because it is a remote crafted-page V8 heap corruption and was exploited in the wild. The description is less specific than CVE-2024-4947, so the corruption primitive is less clear from the prompt, but in-wild exploitation is strong evidence that practical exploit paths exist. Sandbox containment still reduces post-exploitation impact relative to kernel memory corruption.

4. **CVE-2023-6702 — Chromium V8 Promise.all type confusion**

   A public proof of concept materially increases exploitability: researchers and attackers can study trigger conditions and adapt the bug. It is still a V8 object-corruption issue reachable from web content, which is a favorable attack vector. I rank it below the two 2024 V8 issues because the prompt does not say it was exploited in the wild or KEV-listed.

5. **CVE-2024-2887 — Chromium V8 WebAssembly type confusion**

   Demonstrated at Pwn2Own, so it is practically exploitable under contest conditions by skilled researchers. WebAssembly JIT/compiler bugs often provide strong primitives, but they also sit behind substantial engine-specific mitigations and require careful version/architecture targeting. It ranks slightly below CVE-2023-6702 because the prompt gives no public PoC or in-wild exploitation signal.

6. **GHSA-f26g-jm89-4g65 — Gitoxide malicious submodule RCE**

   The impact is severe: code execution during clone or submodule update. The limiting factor is attack delivery. The victim must interact with a malicious repository and perform a submodule operation using the affected Gitoxide behavior. That is very plausible in developer supply-chain scenarios, but less universally reachable than a browser drive-by or exposed kernel network service.

7. **GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 unspecified address**

   Likely easy to trigger if Mastodon accepts attacker-supplied URLs in the affected path. SSRF bypasses are often practically exploitable because they abuse parser/validator discrepancies rather than delicate memory layout. I rank it below RCE-class issues because the outcome depends heavily on internal network exposure, metadata services, loopback-only admin panels, and egress controls.

8. **GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass**

   This is a serious trust-boundary failure in federated message verification. It may allow accepting a message whose signed semantic content differs from what Mastodon later processes. Practical exploitation depends on JSON-LD canonicalization behavior, ActivityPub processing semantics, and whether the attacker can craft a document that both verifies and produces a harmful interpreted object. That makes it more constrained than the SSRF bypass.

9. **GHSA-9f49-8x56-jmjc — libyang heap use-after-free write**

   Memory corruption from attacker-controlled XML is significant, but exploitability is application-dependent. The attacker needs a target application that parses untrusted XML through the vulnerable metadata list path. Heap use-after-free writes can be exploitable, but they often require allocator grooming, repeatability, and a useful overwrite target. Medium severity aligns with lower practical exploitability than the browser and kernel cases here.

10. **CVE-2026-5194 — wolfSSL signature verification digest/OID checks**

   This is cryptographically serious, but practical exploitation is less direct from the provided facts. The attacker must exploit a signature-verification trust violation: for example, getting a verifier to accept a certificate/signature using an undersized digest or mismatched OID in a way that violates the intended security policy. Unlike memory corruption, this does not automatically provide a corruption primitive. Exploitability depends on whether the attacker can obtain or construct signatures/certificates that pass the flawed checks while failing the intended ones.

**Task 2 — Hypotheses For Top Three**

1. **FreeBSD NFS / RPCSEC_GSS**

   Hypothesis: A remote client that can reach the vulnerable NFS/RPCSEC_GSS service can send an RPCSEC_GSS credential whose body exceeds 96 bytes, causing `svc_rpc_gss_validate()` to overwrite adjacent stack data after the fixed 128-byte reconstruction buffer.

   Primitive: attacker-controlled kernel stack overwrite.

   Attack vector: network RPC/NFS request using RPCSEC_GSS credentials.

   Attacker control: credential body length and contents, within the XDR-accepted maximum.

   Falsifiable claim: on a vulnerable FreeBSD build with instrumentation, an oversized but syntactically valid credential will corrupt stack memory immediately adjacent to the reconstruction buffer in `svc_rpc_gss_validate()`; a patched build will reject or safely bound the same input without adjacent stack corruption.

2. **Chromium V8 CVE-2024-4947**

   Hypothesis: A crafted JavaScript program can induce V8 to treat an object as a different internal type than it actually is, producing object layout confusion sufficient to corrupt object fields inside the V8 sandbox.

   Primitive: type confusion leading to object corruption, likely an out-of-bounds or invalid field access/write within V8-managed heap objects.

   Attack vector: crafted HTML/JavaScript page.

   Attacker control: JavaScript object shapes, optimization state, execution order, and values flowing into the confused operation.

   Falsifiable claim: on a vulnerable Chrome/V8 build, a reduced JavaScript test case will produce inconsistent internal object type/layout assumptions and observable heap/object corruption; the patched build will either preserve type correctness or deoptimize/reject the unsafe state.

3. **Chromium V8 CVE-2024-7965**

   Hypothesis: A crafted HTML/JavaScript page can exercise an inappropriate V8 implementation path that permits heap object metadata or backing storage to be corrupted by script-controlled values.

   Primitive: V8 heap corruption.

   Attack vector: crafted web page.

   Attacker control: JavaScript-visible inputs that steer the vulnerable implementation path, such as object layout, array contents, JIT/compiler state, or API-specific values.

   Falsifiable claim: on a vulnerable V8 build with heap sanitizers or debug checks enabled, a reduced page will trigger a reproducible heap integrity violation in the affected implementation path; the patched build will not produce the same violation.

**Task 3 — Directed Testing Plan For Top-Ranked Vulnerability**

Target: **CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS**

1. **Prepare an isolated lab**

   Use a non-production network with no external routing. Build or obtain a vulnerable FreeBSD version and a patched FreeBSD version. Enable kernel debugging, crash dumps, and memory diagnostics where available.

2. **Identify the affected code path**

   Confirm that the vulnerable build contains the described `svc_rpc_gss_validate()` behavior: a 128-byte stack buffer, an initial fixed 32-byte header write, and an unchecked credential-body copy into the remaining space.

3. **Instrument the vulnerable function**

   Add non-exploit diagnostic instrumentation around the reconstruction buffer, such as stack red zones, assertions, tracing, or kernel sanitizers if available. The goal is only to detect whether bytes beyond the intended buffer are modified.

4. **Configure reachable NFS/RPCSEC_GSS service**

   Start the vulnerable kernel/service configuration in the lab and confirm that normal RPCSEC_GSS validation traffic reaches `svc_rpc_gss_validate()`.

5. **Generate benign boundary-case requests**

   Send valid requests with credential body sizes at or below the safe boundary. Evidence expected: no red-zone modification, no assertion failure, no kernel crash.

6. **Generate oversized validation requests**

   Send syntactically valid RPCSEC_GSS requests with credential bodies above 96 bytes but within the XDR-permitted maximum. Do not attempt control-flow hijacking; use recognizable diagnostic byte patterns only to observe memory effects.

7. **Collect evidence on the vulnerable build**

   Confirming evidence would include one or more of: sanitizer report, assertion failure, red-zone modification, kernel panic at the copy site, or debugger evidence that stack memory past the 128-byte buffer changed according to the credential body.

8. **Repeat on the patched build**

   Run the same boundary and oversized cases against the patched system. Refuting or patch-confirming evidence would be rejection of oversized credentials, truncation-safe handling, or no modification beyond the intended buffer.

9. **Minimize and document**

   Reduce the oversized request to the smallest credential length that crosses the boundary and triggers detection. Record exact build versions, configuration flags, request sizes, and observed behavior.

10. **Decision criteria**

   The hypothesis is confirmed if oversized credential bodies reproducibly corrupt stack memory adjacent to the reconstruction buffer on the vulnerable build and do not do so on the patched build.

   The hypothesis is refuted if oversized credential bodies never reach the vulnerable copy path, are rejected before the copy, or cannot modify adjacent stack memory despite instrumentation showing the path executed.