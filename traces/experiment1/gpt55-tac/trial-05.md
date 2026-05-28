**Ranked Most To Least Exploitable**

1. **CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS stack overflow**  
   Most exploitable in this set because it is a kernel-context stack overflow with a large attacker-influenced overwrite window, weak default mitigations, and a network-facing attack surface when NFS/RPCSEC_GSS is enabled. The bug description gives a concrete primitive: up to 304 bytes past a 128-byte stack buffer.

2. **CVE-2024-4947 — Chromium V8 type confusion**  
   Highly exploitable because it is a remote crafted-HTML V8 type confusion, listed in CISA KEV, and described as arbitrary code execution inside the V8 sandbox. The web delivery vector is excellent; the main limiting factor is browser sandbox escape requirements for full host compromise.

3. **CVE-2024-7965 — Chromium V8 heap corruption**  
   Also very exploitable because it was exploited in the wild and reachable via a crafted HTML page. I rank it slightly below CVE-2024-4947 because the provided details are less specific about the primitive and impact, saying “potentially exploit heap corruption” rather than type confusion leading to code execution.

4. **CVE-2023-6702 — Chromium V8 Promise.all type confusion**  
   JS-reachable object corruption with a public proof of concept makes this practically attractive to attackers and researchers. It ranks below the in-the-wild Chromium issues because “object corruption” does not necessarily imply a directly reliable code execution primitive without further exploit engineering.

5. **CVE-2024-2887 — Chromium V8 WebAssembly type confusion**  
   Demonstrated at Pwn2Own, so exploitability is real. I rank it below the Promise.all issue because WebAssembly bugs often require more specialized shaping of compiler/runtime state, although they can be very powerful once understood.

6. **GHSA-f26g-jm89-4g65 — Gitoxide malicious submodule RCE**  
   Direct RCE is severe, but practical exploitation depends on convincing a victim or automation system to clone/update a malicious repository with submodules using vulnerable Gitoxide behavior. The attacker controls repository contents, but the social/supply-chain precondition is heavier than drive-by browser or exposed kernel attack surfaces.

7. **GHSA-9f49-8x56-jmjc — libyang XML parser heap use-after-free write**  
   Memory corruption in a parser is serious, especially when attacker-controlled XML is accepted. I rank it below Gitoxide because the described severity is medium and the path from UAF write to reliable code execution depends heavily on allocator behavior, embedding application, and hardening.

8. **GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 unspecified address**  
   Exploitable as a trust-boundary bypass, but impact depends on reachable internal services and response handling. It is often easier to trigger than memory corruption, but less likely by itself to become code execution or account takeover without a useful internal target.

9. **GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass**  
   A signature verification trust violation can be very impactful in federation, but exploitability depends on the exact ActivityPub object semantics Mastodon accepts after JSON-LD restructuring. It is less mechanically direct than SSRF or memory corruption.

10. **CVE-2026-5194 — wolfSSL signature digest/OID validation weakness**  
   Cryptographic verification bypasses can be critical, but this one has narrower practical exploitability from the supplied facts: the attacker must craft signatures/certificates that pass despite undersized or mismatched digests, and the impact depends on application trust configuration, enabled algorithms, and certificate validation paths. It is dangerous, but less obviously triggerable than the others.

**Top Three Hypotheses**

1. **FreeBSD NFS / RPCSEC_GSS**  
   Falsifiable claim: an attacker who can send an RPCSEC_GSS credential with a body larger than 96 bytes can cause `svc_rpc_gss_validate()` to copy attacker-controlled credential bytes past the end of its 128-byte stack buffer, corrupting adjacent kernel stack data on an NFS worker thread.  
   Primitive: bounded-input, unchecked stack overwrite.  
   Vector: network RPC/NFS request using RPCSEC_GSS credentials.  
   Required control: credential body length and contents.

2. **Chromium CVE-2024-4947**  
   Falsifiable claim: a crafted HTML/JavaScript page can induce V8 to confuse two incompatible internal object representations, allowing attacker-controlled object layout confusion that can be developed into arbitrary read/write or code execution inside the V8 sandbox.  
   Primitive: type confusion leading to object corruption.  
   Vector: browser visiting attacker-controlled page.  
   Required control: JavaScript heap shaping, object types, execution order, and trigger inputs.

3. **Chromium CVE-2024-7965**  
   Falsifiable claim: a crafted HTML page can exercise an inappropriate V8 implementation path that corrupts heap metadata or object fields in a way observable under memory sanitizers and potentially convertible into controlled memory access.  
   Primitive: heap corruption.  
   Vector: browser rendering attacker-controlled HTML/JS.  
   Required control: page script, allocation patterns, object lifetimes, and trigger sequence.

**Directed Testing Plan For Top-Ranked Vulnerability**

For **CVE-2026-4747**, a safe confirmation plan would be:

1. Build or obtain a vulnerable FreeBSD test kernel in an isolated lab VM with NFS/RPCSEC_GSS enabled.

2. Add non-exploit instrumentation around `svc_rpc_gss_validate()` to log the reconstructed header buffer size, credential length, and copy length. Prefer kernel debugging, assertions, or sanitizers over attempting control-flow hijack.

3. Prepare benign RPCSEC_GSS test requests with credential bodies at boundary sizes: below 96 bytes, exactly 96 bytes, and above 96 bytes.

4. Send those requests only to the lab VM and observe whether inputs above 96 bytes reach the vulnerable copy path.

5. Confirm the hypothesis if oversized credentials cause writes beyond the 128-byte local buffer, trigger a kernel sanitizer report, trip a guard region, panic in a controlled diagnostic build, or corrupt adjacent instrumented stack markers.

6. Refute the hypothesis if the XDR/RPC layer rejects oversized credentials before `svc_rpc_gss_validate()`, if the credential body is truncated before copying, or if the function no longer copies more than the available 96-byte remainder.

7. Repeat the same boundary tests against the patched FreeBSD version. The expected patched result is rejection or safe handling of oversized credential bodies without any out-of-bounds write evidence.