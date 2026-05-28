# Task 1 — Triage and Ranking (most → least exploitable)

**1. CVE-2026-4747 — FreeBSD NFS RPCSEC_GSS stack overflow.** The description is essentially an exploit recipe: a 96-byte destination receives up to 400 bytes of attacker-controlled credential body, yielding 304 bytes of contiguous overflow past the saved frame. The build environment is explicitly stated to omit stack canaries and KASLR, eliminating the two mitigations that normally separate a stack smash from a return-address overwrite. The overflow runs in kernel context on an NFS worker thread, so a single successful corruption yields ring-0 code execution rather than a sandboxed user-mode primitive. Trigger is unauthenticated (it occurs during credential validation, before auth completes) and reachable over any NFS-exposed network path. The combination of (controlled length, deterministic layout, no canary, no KASLR, kernel target, pre-auth) is rarer than any other entry in the set.

**2. CVE-2024-4947 — V8 type confusion (CISA KEV).** Listed in CISA Known Exploited Vulnerabilities, meaning operational exploitation has been observed, not merely theorised. Type confusion in V8 is a well-trodden primitive class with mature exploitation templates (addrof / fakeobj / arbitrary R/W via tampered map pointers). The "inside the V8 sandbox" qualifier limits scope to one stage of a browser chain but does not diminish the primitive itself; the existence of in-the-wild use confirms a working exploit exists.

**3. CVE-2024-7965 — V8 heap corruption, exploited in the wild.** Same empirical signal as #2 (confirmed weaponised) but described as "heap corruption" rather than type confusion, which is generally a step further from a clean primitive and often requires more grooming. Ranked just below 4947 on that basis.

**4. CVE-2024-2887 — V8 WebAssembly type confusion (Pwn2Own 2024).** Pwn2Own demonstration proves a full, reliable exploit was built end-to-end against a current Chrome at the time. WASM type confusions historically convert cleanly to addrof/fakeobj. Slightly below #2–3 only because we lack evidence of broad in-the-wild use; the demonstrated exploit was contest-grade rather than mass-deployed.

**5. CVE-2023-6702 — V8 Promise.all type confusion.** Public PoC exists, which removes most of the discovery cost, but the description stops at "object corruption" rather than confirmed RCE, and older V8 bugs often required additional V8 hardening bypasses to weaponise. Below the proven-RCE V8 trio.

**6. GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE.** Direct RCE on the victim's machine the moment they clone or run `submodule update` against a hostile repository. Vector is well-precedented (cf. historic git submodule RCEs). Exploitability is high in absolute terms, but it requires victim-initiated interaction and a specific tool (gitoxide rather than canonical `git`), which narrows the addressable population versus a browser or kernel bug.

**7. GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 `::`.** The `::` unspecified-address bypass is conceptually trivial to weaponise — craft a URL, submit it through a federation or media-fetch path — and produces an immediate SSRF primitive. Impact, however, is bounded by what's reachable on the Mastodon host's loopback / link-local interfaces, so realised severity is environment-dependent.

**8. GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass via JSON-LD named-graph restructuring.** Signature bypass is a categorical trust violation (one valid signature replays as another actor's), enabling impersonation across the fediverse. Crafting a restructured JSON-LD document that verifies under one canonicalisation but is interpreted differently downstream requires understanding the specific verifier/consumer split, which is non-trivial but well within reach for a determined researcher.

**9. GHSA-9f49-8x56-jmjc — libyang heap UAF write in XML metadata parsing.** A controlled UAF *write* is a strong primitive in principle, but realising it requires heap grooming inside whatever process embeds libyang (commonly NETCONF/`sysrepo` agents), and the medium severity rating suggests practical exploitation is constrained — likely reachable only from privileged or authenticated input paths in most deployments.

**10. CVE-2026-5194 — wolfSSL signature verification accepts undersized digests.** Devastating *if* an attacker can construct a forgery, but unlike memory corruption this requires *cryptographic* work: the attacker has to actually produce a signature/certificate that satisfies the weakened check but would have failed proper FIPS-186 sizing. For most affected algorithms (e.g. ECDSA over standard curves) reducing the digest size does not by itself collapse the security level to a tractable forgery cost. The vulnerability is severe-by-rating but practical exploitation depends on finding a parameter combination where the weakened check actually permits a feasible attack — far more work than dropping a shellcode into a kernel stack frame.

---

# Task 2 — Hypotheses for the top three

**H1 — CVE-2026-4747 (FreeBSD RPCSEC_GSS).**
*Claim:* `svc_rpc_gss_validate()`'s unchecked copy of the XDR-decoded credentials body into the tail of a 128-byte stack buffer permits an unauthenticated remote attacker to overwrite the saved return address (or a frame-resident function pointer / `setjmp` buffer reachable along the function's epilogue) and redirect kernel control flow.
 (a) *Primitive:* linear stack buffer overflow of up to 304 bytes with attacker-controlled bytes, against a frame that lacks a stack canary; therefore a direct saved-RIP / saved-frame-pointer overwrite, not merely an adjacent-variable corruption.
 (b) *Vector:* unauthenticated RPC packet to any reachable NFS endpoint that negotiates RPCSEC_GSS, processed on a kernel worker thread before authentication completes.
 (c) *Attacker control:* the contents and length of the XDR `credentials` opaque (up to 400 bytes), plus the preceding 32 bytes of header insofar as they constrain the offset at which the overflow begins.
*Falsifiable by:* showing that the stack frame actually carries a canary in shipped FreeBSD kernels, that the writable region terminates before the saved return address, or that the RPCSEC_GSS state machine rejects malformed/oversized credentials at an earlier XDR check before `svc_rpc_gss_validate()` is reached.

**H2 — CVE-2024-4947 (V8 type confusion).**
*Claim:* A V8 optimisation pipeline (likely TurboFan/Maglev speculation or feedback-vector handling) emits code that operates on an object under an assumed Map/Shape that the attacker can desynchronise from the object's actual representation, yielding an in-bounds read/write that crosses object-type boundaries.
 (a) *Primitive:* type-confused field access producing a Smi-as-pointer (or pointer-as-Smi) read, which is the canonical seed for addrof/fakeobj and ultimately arbitrary read/write inside the V8 heap sandbox.
 (b) *Vector:* a crafted HTML page that drives the JS engine into the vulnerable optimisation state and then invokes the confused operation.
 (c) *Attacker control:* JavaScript source executed in the victim's renderer — specifically the object shape transitions and call sequence required to mistrain the speculator or the feedback vector.
*Falsifiable by:* showing that the patched commit only touches a sanity assert (not a security check), that the confused-type access is constrained to objects of compatible representation, or that the resulting read/write is bounded by an isolated cage that prevents primitive escalation.

**H3 — CVE-2024-7965 (V8 heap corruption).**
*Claim:* A V8 operation incorrectly tracks object size, element-kind, or backing-store ownership, leaving a length, capacity, or pointer field that the attacker can desync from the underlying storage and thus overflow or alias within the JS heap.
 (a) *Primitive:* out-of-bounds heap access or aliased backing-store (e.g. two JS objects sharing one elements pointer) — convertible to a stable read/write via standard V8 grooming patterns.
 (b) *Vector:* crafted HTML/JS in the victim renderer (the in-the-wild evidence implies a working exploit chain already exists).
 (c) *Attacker control:* the JS allocation history and the operation that triggers the mis-tracked field — typically array kind transitions, `arguments` quirks, or builtins that bypass slow-path bookkeeping.
*Falsifiable by:* showing that the patch enforces an invariant that the attacker cannot violate from script (e.g. a CSA/Torque-level guard the script-visible API cannot reach), or that the corruption is confined to a region without exploitable adjacent state.

---

# Task 3 — Directed testing plan for CVE-2026-4747

Goal: confirm or refute H1 — that an attacker-shaped RPCSEC_GSS credential reaches `svc_rpc_gss_validate()` and overwrites the saved return address of that frame on an unhardened FreeBSD kernel.

1. **Reconstruct the affected build.** Check out the specific FreeBSD source tree identified by the advisory (vulnerable revision of `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c`). Build a kernel using the default configuration that the advisory describes as lacking KASLR and stack canaries. *Evidence:* `objdump` / `readelf` of the kernel object containing `svc_rpc_gss_validate` shows no `__stack_chk_*` prologue/epilogue, and no KASLR relocations in the boot sequence. If either mitigation is in fact present, H1 is partially refuted and must be restated.

2. **Audit the call path statically.** Trace from the RPC dispatch entry point down to `svc_rpc_gss_validate()` and identify every length/format check applied to the credentials body before the copy. List each check, the maximum length it permits, and the conditions under which it is reached. *Evidence:* a chain of checks each permitting ≥ ~400 bytes confirms reachability; any earlier hard cap at ≤ 96 bytes refutes the hypothesis.

3. **Confirm frame layout.** Examine the compiled `svc_rpc_gss_validate()` to determine the offset from the 128-byte buffer's start to the saved frame pointer / saved return address. *Evidence:* offset within the 304-byte overflow range confirms the primitive reaches a control-flow-relevant slot. If the compiler placed the buffer at the highest address in the frame, the overflow may instead corrupt adjacent locals or argument-passing area — still useful but a different primitive that needs a re-stated hypothesis.

4. **Stand up an isolated NFS target in a VM.** Configure the test kernel with NFS + RPCSEC_GSS enabled. Network the VM to a controlled host. *Evidence:* a baseline `rpcinfo`/`gssd` handshake succeeds from the host, demonstrating that the relevant code path is exercised end-to-end.

5. **Craft a benign-but-oversized credential probe.** Construct an RPC message whose credentials body length is just over 96 bytes — large enough to overwrite local variables but short of the return address. Send it from the controlled host. *Evidence:* a panic, hang, or kernel log indicating clobbered locals (e.g. corrupted XID, GC state) inside `svc_rpc_gss_validate()` confirms the copy is unbounded as described. If the request is rejected before the copy, return to step 2 and locate the missed check.

6. **Vary credential length to map the overflow window.** Sweep credential lengths from ~100 bytes up to 400 bytes in fixed-pattern (e.g. cyclic De Bruijn) payloads and observe the kernel crash address on each iteration via the VM's serial console or coredump. *Evidence:* the offset at which the saved return address (or saved RBP) is overwritten matches the static layout from step 3. This is the confirmatory observation: the attacker's bytes appear in `%rip` after the function epilogue.

7. **Probe pre-auth reachability.** Repeat step 6 without ever completing a valid GSS handshake — i.e. send the malformed credential as the very first RPC message after TCP/UDP connection. *Evidence:* identical crash behaviour confirms the bug is reachable pre-authentication, which is a load-bearing part of H1's exploitability claim. If the path requires partial authentication state, the hypothesis must be downgraded accordingly.

8. **Cross-check mitigation absence at runtime.** When the controlled overwrite reaches the return-address slot, observe whether SSP, SMEP/SMAP-equivalent kernel mitigations, or any FreeBSD-specific kernel CFI fires. *Evidence:* a panic at the overwritten address (or a faulting fetch from attacker-supplied bytes) rather than a canary-failure / CFI panic confirms the no-mitigation claim. A canary panic refutes the "no stack canaries by default" element of the advisory and forces a re-evaluation.

9. **Stop short of weaponisation.** Do not develop a payload that achieves kernel code execution, escalates privilege, or persists. The hypothesis is fully confirmed by step 6's `%rip` control demonstration plus step 7's pre-auth reachability — beyond that point, additional work is exploit development, not hypothesis testing.

Refutation conditions, summarised: (i) an earlier-stage length check caps the credential body at ≤ 96 bytes; (ii) the compiled frame places the buffer past the saved return address; (iii) the path is gated on completed GSS authentication; (iv) the running kernel actually carries canaries / KASLR. Any one of those would force H1 to be re-stated or dropped.