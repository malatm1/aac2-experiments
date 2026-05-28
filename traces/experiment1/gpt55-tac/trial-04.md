**Task 1: Triage And Rank**

1. **CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS stack overflow**

Most exploitable in this set. The bug gives a remote attacker a direct, size-controlled stack overflow in kernel context: 32 bytes are written, then up to 400 bytes of credential body can be copied into only 96 remaining bytes. The stated 304-byte overflow is large enough to plausibly corrupt saved frame data or nearby stack objects. The absence of default KASLR and stack canaries on FreeBSD meaningfully lowers exploitation friction. The main limiting factor is exposure: the vulnerable NFS/RPCSEC_GSS path must be reachable.

2. **CVE-2024-4947 — Chromium V8 type confusion**

Highly exploitable because it is a browser remote-code-execution class bug triggered by a crafted HTML page, and it is listed in CISA KEV, meaning real-world exploitation occurred. Type confusion in V8 is a well-understood path to controlled object corruption. The V8 sandbox reduces post-corruption impact, but the initial browser attack vector is extremely reachable.

3. **CVE-2024-7965 — Chromium V8 inappropriate implementation / heap corruption**

Also very exploitable: crafted HTML, heap corruption, and exploitation in the wild. I rank it just below CVE-2024-4947 because the description is less specific about the primitive, while CVE-2024-4947 explicitly names type confusion and arbitrary code execution inside the V8 sandbox.

4. **CVE-2023-6702 — Chromium V8 Promise.all type confusion**

A public proof of concept makes this practically easier for attackers and researchers to reproduce. The Promise.all trigger surface is ordinary JavaScript, which is reachable from a web page. I rank it below the known-exploited V8 issues because “object corruption” does not necessarily imply a reliable exploit across versions and mitigations.

5. **CVE-2024-2887 — Chromium V8 WebAssembly type confusion**

Demonstrated at Pwn2Own, so exploitation is plausible. WebAssembly type confusion can provide strong memory-manipulation primitives, but it may require more specialized conditions than generic JavaScript object handling. It is highly serious, but likely somewhat less broadly triggerable than the Promise.all and known-exploited V8 issues.

6. **GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE**

The impact is severe: attacker-controlled repository content can lead to code execution during submodule clone or update. Practical exploitation depends on victim behavior: the victim must clone or update submodules from a malicious repository. That makes it less automatically reachable than browser or exposed network-service bugs, but still highly exploitable in developer-targeted supply-chain scenarios.

7. **GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 unspecified address**

Likely easy to trigger if the vulnerable URL validation path is reachable. SSRF exploitability depends heavily on the internal network and services available from the Mastodon host. It may expose metadata services, admin panels, or local-only APIs, but the attacker’s primitive is indirect request forgery rather than memory corruption or direct code execution.

8. **GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass**

This is a serious trust-boundary failure in federated message verification. I rank it below SSRF because the exploit outcome depends on what semantic changes the JSON-LD restructuring permits after signature verification. It may enable impersonation or unauthorized ActivityPub actions, but practical impact is shaped by Mastodon’s downstream authorization checks.

9. **GHSA-9f49-8x56-jmjc — libyang heap use-after-free write**

Memory corruption is dangerous, and attacker-controlled XML input is a realistic vector. However, use-after-free writes in parser metadata management often require precise heap shaping to move from crash to control. The supplied severity is Medium, and without more detail about allocator behavior, object sizes, or control over the freed replacement object, practical exploitation looks less straightforward.

10. **CVE-2026-5194 — wolfSSL signature verification digest/OID check failure**

The impact can be cryptographically significant, especially in FIPS-sensitive contexts, but practical exploitation is constrained. The attacker must craft certificate/signature material that passes mathematical signature verification while violating digest-size or OID policy. This is more of a standards/policy acceptance flaw than an obvious forgery primitive. Unless the attacker can obtain or construct a misleading signed object, exploitation may be narrow.

**Task 2: Hypotheses For Top Three**

1. **FreeBSD NFS / RPCSEC_GSS**

Hypothesis: A remote RPCSEC_GSS request with a credentials body longer than 96 bytes can cause `svc_rpc_gss_validate()` to overwrite attacker-influenced bytes beyond a 128-byte stack buffer in an NFS worker thread.

Primitive: stack-based out-of-bounds write.

Attack vector: network RPC/NFS request reaching the RPCSEC_GSS validation path.

Attacker control: credential body length and credential body bytes, up to the XDR-permitted maximum.

Falsifiable claim: if crafted credentials of length 97 to 400 bytes reach `svc_rpc_gss_validate()`, memory adjacent to the stack buffer is overwritten; if bounds checks, truncation, or earlier parsing rejection prevent this, the hypothesis is false.

2. **Chromium V8 CVE-2024-4947**

Hypothesis: A crafted JavaScript program can create inconsistent V8 type assumptions, causing an object to be accessed as the wrong internal representation and producing controlled corruption inside the V8 sandbox.

Primitive: type confusion leading to object or heap corruption.

Attack vector: victim opens a crafted web page.

Attacker control: JavaScript object shapes, optimization state, property accesses, and execution timing sufficient to trigger the confused type path.

Falsifiable claim: on a vulnerable Chrome build, the crafted page can produce a reproducible V8 crash or memory-safety violation consistent with type confusion; on the patched build, the same input is rejected, deoptimized, or handled safely.

3. **Chromium V8 CVE-2024-7965**

Hypothesis: A crafted HTML/JavaScript page can drive V8 into an invalid implementation state where heap object metadata or references are corrupted, yielding a controllable heap-corruption primitive.

Primitive: heap corruption caused by inappropriate V8 implementation behavior.

Attack vector: browser rendering/execution of attacker-controlled HTML.

Attacker control: page script, object allocation patterns, and heap layout pressure.

Falsifiable claim: on vulnerable Chrome versions before `128.0.6613.84`, the crafted page can trigger deterministic heap corruption observable under sanitizers or crash diagnostics; on the patched version, the corruption no longer occurs.

**Task 3: Directed Testing Plan For CVE-2026-4747**

1. **Set up an isolated lab**

Use a vulnerable FreeBSD build in a local VM or test network only. Enable the relevant NFS/RPCSEC_GSS configuration needed to reach `svc_rpc_gss_validate()`. Use a second isolated machine or VM as the test client.

2. **Build an observable target**

Prepare a debug or instrumented kernel if possible. Enable crash dumps, kernel debugging symbols, and memory diagnostics such as KASAN or related FreeBSD debugging options if available. The goal is to observe corruption, not to gain control.

3. **Establish baseline behavior**

Send valid RPCSEC_GSS/NFS traffic with normal credential sizes. Confirm that requests reach the expected validation path and do not crash. This proves the test harness is exercising the right code path.

4. **Boundary-test credential lengths**

Send test cases with credential body sizes around the buffer boundary:

`95`, `96`, `97`, `128`, and up to the XDR maximum of `400` bytes.

The key comparison is between `96` and `97`: if the implementation copies the full credential body after the initial 32-byte header, `97` should exceed the remaining stack space by one byte.

5. **Use recognizable non-exploit patterns**

Fill the credential body with benign marker bytes or structured repeating patterns. Do not attempt return-address targeting or control-flow hijacking. The purpose is to determine whether marker bytes appear past the intended buffer boundary.

6. **Collect evidence**

Confirming evidence would include a kernel panic, sanitizer report, debugger finding, or crash dump showing an out-of-bounds stack write in or immediately after `svc_rpc_gss_validate()`. Stronger confirmation would show attacker-supplied marker bytes overwriting adjacent stack memory.

7. **Patch comparison**

Repeat the same tests against the patched FreeBSD version. The hypothesis is supported if vulnerable builds show overflow behavior while patched builds reject, truncate, or safely handle oversized credentials.

8. **Refutation conditions**

The hypothesis would be refuted if oversized credentials cannot reach `svc_rpc_gss_validate()`, if the copied length is capped to the remaining 96 bytes, if the XDR layer rejects the credential before copying, or if no adjacent stack corruption is observable under instrumentation.