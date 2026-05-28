Below is an exploitability-focused ranking, not a severity ranking. I’m weighing attacker control, reachability, memory corruption quality, mitigations, required user interaction, and whether exploitation has already been demonstrated or observed.

**Task 1 — Triage And Rank**

1. **CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS stack overflow**

   Most exploitable in this set because it is a kernel-context stack overflow with attacker-influenced length, a clear fixed-size destination buffer, and weak default mitigations according to the description. The bug gives a comparatively direct memory corruption primitive: a bounded 128-byte stack buffer receives up to hundreds of bytes of credential data. If NFS/RPCSEC_GSS is reachable, this is a high-value remote attack surface with no browser sandbox or JavaScript engine hardening layer in front of it.

2. **CVE-2024-4947 — Chromium V8 type confusion**

   This ranks very high because it is known exploited in the wild and listed in CISA KEV. Even though modern Chrome exploitation requires sandbox escape for full host compromise, practical exploitability is strongly supported by real-world exploitation. A crafted page is enough to reach the bug, and V8 type confusions can often be shaped into strong read/write or code-execution primitives inside the renderer or V8 sandbox.

3. **CVE-2024-7965 — Chromium V8 inappropriate implementation / heap corruption**

   Also highly exploitable because it was exploited in the wild and reachable through a crafted HTML page. I rank it just below CVE-2024-4947 because the description is less specific about the primitive. Still, real-world exploitation strongly outweighs uncertainty: browser-delivered heap corruption in V8 is a mature exploitation target.

4. **CVE-2026-5194 — wolfSSL signature verification digest/OID validation flaw**

   This is not memory corruption, but it is a serious trust-boundary failure in certificate verification. Practical exploitability depends heavily on how an application uses wolfSSL, what algorithms are enabled, and whether an attacker can present crafted certificates or signatures in a meaningful trust flow. It could enable authentication or certificate-validation bypasses, but it is less universally weaponizable than a directly reachable memory corruption bug.

5. **CVE-2024-2887 — Chromium V8 WebAssembly type confusion**

   Demonstrated at Pwn2Own, so exploitability is credible. The WebAssembly attack surface is complex and powerful for bug triggering, but browser mitigations and exploit-development burden remain substantial. I rank it below the in-the-wild Chrome bugs because public contest demonstration does not necessarily mean broad real-world reliability.

6. **CVE-2023-6702 — Chromium V8 Promise.all type confusion**

   Public proof of concept raises exploitability, and the browser delivery vector is excellent. I place it below the other Chromium entries because “object corruption” plus PoC availability does not necessarily imply a reliable modern exploit chain, especially against patched or fully hardened builds.

7. **GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE**

   This can be highly practical in developer-targeted attacks because repository cloning and submodule updates are common trust transitions. However, it requires the victim to interact with a malicious repository and perform clone/update behavior. That makes it less generally exploitable than network/browser bugs, but potentially very effective in supply-chain or social-engineering scenarios.

8. **GHSA-chgx-jx3p-rf73 — Mastodon JSON-LD signature bypass**

   This is a trust-validation bypass in federated ActivityPub messages. It could be practically serious if it lets an attacker alter signed semantic content while preserving apparent validity. I rank it lower because exploitation depends on federation message handling, JSON-LD canonicalization/signature semantics, and what security decisions Mastodon makes after verification.

9. **GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 unspecified address**

   SSRF bypasses can be very useful, but exploitability depends on network placement, internal services, request behavior, response visibility, and available protocols. The `::` bypass is plausible and clean, but the impact is environmental: it may range from internal metadata access to low-value internal probing.

10. **GHSA-9f49-8x56-jmjc — libyang heap use-after-free write**

   A heap UAF write from attacker-controlled XML is dangerous, but I rank it lowest here because the provided severity is medium and the exploitability likely depends heavily on allocator state, parser integration, and whether the consuming application exposes XML parsing to untrusted remote input. It may be crashable more readily than reliably exploitable.

**Task 2 — Hypothesis Formation For Top Three**

1. **FreeBSD NFS / RPCSEC_GSS**

   Falsifiable hypothesis: if an attacker can send an RPCSEC_GSS-authenticated NFS request with a credentials body larger than 96 bytes, `svc_rpc_gss_validate()` will copy attacker-controlled credential bytes past the end of the 128-byte stack reconstruction buffer, corrupting adjacent kernel stack data on the NFS worker thread.

   The primitive is a kernel stack buffer overflow. The attack vector is a crafted NFS/RPCSEC_GSS request. The attacker needs to control the credential body length and content accepted by the XDR layer.

2. **Chromium CVE-2024-4947**

   Falsifiable hypothesis: a crafted HTML/JavaScript page can drive V8 into representing an object with an incorrect internal type, allowing operations intended for one object layout to be applied to another, producing controlled object corruption or a memory access primitive inside the V8 sandbox.

   The primitive is type confusion leading to object corruption. The attack vector is browser navigation to a malicious page. The attacker needs to control JavaScript execution patterns, object shapes, and runtime state sufficient to trigger the confused type path.

3. **Chromium CVE-2024-7965**

   Falsifiable hypothesis: a crafted HTML/JavaScript page can reach an incorrectly implemented V8 code path that violates heap object invariants, causing attacker-influenced heap corruption observable as a crash, corrupted object state, or controlled memory access under diagnostic builds.

   The primitive is heap corruption. The attack vector is a malicious web page. The attacker needs to control script-visible inputs that exercise the vulnerable V8 implementation path and shape heap layout enough to make the corruption observable.

**Task 3 — Directed Testing Plan For CVE-2026-4747**

1. **Set up a non-production test target**

   Use a vulnerable FreeBSD version in an isolated VM or lab network. Enable kernel debugging, crash dumps, and relevant sanitizers or diagnostic kernel options if available. Confirm the patched and vulnerable versions are clearly separated.

2. **Identify the vulnerable path**

   Review `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c`, especially `svc_rpc_gss_validate()`, and confirm the local source has the 128-byte stack buffer, the initial 32-byte header reconstruction, and the unchecked credential-body copy.

3. **Instrument the copy boundary**

   Add diagnostic logging or debugger breakpoints around the header reconstruction and credential copy. The key measurement is whether credential bodies over 96 bytes are accepted by the XDR layer and then copied into the fixed stack buffer.

4. **Generate benign boundary test cases**

   In the lab, send RPCSEC_GSS requests with credential body sizes around the boundary: below 96 bytes, exactly 96 bytes, and above 96 bytes. The goal is not exploitation, only confirmation of overflow behavior.

5. **Observe memory safety evidence**

   Confirmation evidence would include a kernel panic, sanitizer report, debugger trap, corrupted stack sentinel, or explicit observation that bytes beyond the 128-byte buffer are modified after the copy. Refutation evidence would be rejection before the copy, truncation to fit the buffer, or bounds checks preventing writes past the destination.

6. **Compare against patched FreeBSD**

   Repeat the same boundary tests against the patched version. The hypothesis is strengthened if the vulnerable build shows out-of-bounds stack writes while the patched build rejects, bounds-checks, or safely handles oversized credentials.

7. **Document exploitability constraints**

   Record required service configuration, authentication mode, packet reachability, maximum accepted credential length, crash reliability, and whether default compiler/kernel mitigations affect control over adjacent stack state. This determines whether the bug is merely crashable or plausibly exploitable for control-flow impact.