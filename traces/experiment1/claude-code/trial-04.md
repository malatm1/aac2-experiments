# Task 1 — Triage and Ranking (Most → Least Exploitable)

I am ranking on *practical exploitability today*: evidence of weaponization, quality of the primitive, reachable attack surface, authentication requirements, and the mitigations the attacker must defeat. Severity scores are deliberately not used as inputs.

**1. CVE-2024-4947 — Chromium V8 type confusion**
Listed in CISA's Known Exploited Vulnerabilities catalogue, which means a working in-the-wild exploit demonstrably exists against a default Chrome configuration. Type confusion in V8 is a well-understood primitive (read/write into adjacent JS objects → addrof/fakeobj → arbitrary R/W) and the attack vector — a crafted HTML page — is the most reachable surface in modern computing. The exploit is bounded by the V8 sandbox, but the bug itself is proven reliable. Highest because exploitation is *historically attested*, not hypothesized.

**2. CVE-2024-7965 — Chromium V8 heap corruption**
Also exploited in the wild per the advisory. Heap corruption (as opposed to a constrained type confusion) tends to give broader shaping options. Slightly behind #1 only because "inappropriate implementation … heap corruption" is a more diffuse description than the precise type-confusion primitive of CVE-2024-4947, so generic reproduction is marginally harder, but in-the-wild status is the dominant signal.

**3. CVE-2026-4747 — FreeBSD `svc_rpc_gss_validate()` stack overflow**
Pre-authentication, network-reachable kernel stack buffer overflow with 304 bytes of controlled overflow, on a platform built without stack canaries or KASLR by default. This is a textbook "best-case" memory-corruption primitive: predictable kernel addresses, direct return-address overwrite, and an enormous spray budget. Not yet weaponized publicly, which is the only reason it sits below the two V8 KEV entries. If primitive quality alone decided the ranking, this would be #1.

**4. CVE-2024-2887 — Chromium V8 WebAssembly type confusion**
Demonstrated at Pwn2Own 2024, so a complete, polished exploit chain *exists* but is not necessarily public in full. Pwn2Own-grade chains historically generalize across closely related WebAssembly type-confusion bugs, so the path from advisory to working PoC is well-trodden. Behind #1–#2 because the public has the bug description, not the chain.

**5. CVE-2023-6702 — Chromium V8 `Promise.all` type confusion**
Public proof-of-concept available, but older — modern V8 has additional mitigations (V8 sandbox hardening, CFI improvements) that may have closed downstream steps even when the trigger still works. Drops below #4 because the PoC is older and the residual surface is narrower.

**6. CVE-2026-5194 — wolfSSL signature-verification digest checks**
A trust-violation bug in TLS/X.509 certificate verification: under-sized digests are accepted in ECDSA / DSA / ML-DSA / Ed25519 / Ed448 paths. Exploitability is real and dangerous (forged certificate chains, hash-truncation attacks reducing collision work to feasible bounds), but turning it into impact requires (a) the victim to use a vulnerable wolfSSL build with the relevant algorithm mix, and (b) the attacker to construct a chain that passes the other PKI checks. High-impact but more setup than the memory-corruption bugs above.

**7. GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass**
Unauthenticated, network-reachable trust-violation: an attacker on the fediverse can forge signed activities attributed to other actors. The primitive is reliable once understood (JSON-LD canonicalization quirks are deterministic), and the impact is impersonation across federation. Lower than the memory-corruption set because it grants identity forgery rather than code execution.

**8. GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE**
A pure RCE primitive on the victim, but it requires the victim to actively `git submodule update` (or clone with `--recurse-submodules`) a repository the attacker controls. Social-engineering or supply-chain delivery is needed; not a drive-by. Reliable once the victim engages, hence above the SSRF and UAF entries.

**9. GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 `::`**
Bypasses URL validation to reach internal services. SSRF is a stepping-stone primitive: usefulness depends entirely on what's listening behind the Mastodon host. Reliable trigger, limited intrinsic impact.

**10. GHSA-9f49-8x56-jmjc — libyang heap UAF write**
Lowest because (a) Medium severity, (b) libyang's reachable attack surface (NETCONF/YANG tooling) is narrower than browsers or NFS servers, (c) UAF *writes* are exploitable in principle but require heap-grooming primitives the advisory doesn't promise are present, and (d) the bug is in metadata-list head-pointer update logic — likely a single-shot corruption rather than a repeatable arbitrary write.

---

# Task 2 — Hypotheses (Top 3)

### Hypothesis 1 — CVE-2024-4947 (V8 type confusion)
**Falsifiable claim:** A specifically-shaped sequence of JavaScript object operations causes V8's optimizing compiler (TurboFan/Maglev) to emit code that treats an object as one map/shape while the heap holds another, yielding an out-of-bounds read/write inside the V8 heap that can be parlayed into `addrof`/`fakeobj` primitives — *without* needing any escape from the V8 sandbox to demonstrate the primitive itself.

- **(a) Corruption primitive:** Type confusion between two JS object representations (likely involving map transitions or speculative inlining assumptions that are not invalidated on a control-flow path).
- **(b) Attack vector:** Drive-by — a victim browses an attacker-controlled HTML page that loads the trigger JavaScript.
- **(c) Attacker control needed:** The ability to serve arbitrary JavaScript to the victim's Chrome instance running a version `< 125.0.6422.60`. No user interaction beyond visiting the page is required; no privileged origin is needed.

**How to falsify:** Build V8 at the vulnerable revision, run the constructed PoC under ASan/`--sandbox-testing`, and observe whether an inter-object out-of-bounds access occurs. If no confusion arises on the suspected path, the hypothesis fails.

### Hypothesis 2 — CVE-2024-7965 (V8 heap corruption)
**Falsifiable claim:** A crafted JavaScript page can drive V8 into a state where an object is freed or resized while a stale pointer/length is still in use by JIT-compiled code, yielding a heap-corruption write within the V8 sandbox heap; the write is sufficiently controlled to set up a sandboxed arbitrary R/W.

- **(a) Corruption primitive:** Heap corruption — most likely a sandboxed write through a stale element-store pointer or length mis-tracked across deoptimization, given the "inappropriate implementation" wording and observed ITW use against Chrome.
- **(b) Attack vector:** Same as #1 — crafted HTML/JS delivered to a vulnerable Chrome instance.
- **(c) Attacker control needed:** Arbitrary JavaScript execution in the victim's renderer (any web origin will do); no extension, no auth.

**How to falsify:** Reproduce on an unpatched build with `--expose-gc` + GC stress and heap-tracking. If the suspected operation never produces a pointer/length mismatch across GC or deopt, the hypothesis is wrong.

### Hypothesis 3 — CVE-2026-4747 (FreeBSD RPCSEC_GSS stack overflow)
**Falsifiable claim:** An unauthenticated remote client can send a single RPC with an oversized GSS credentials body to a FreeBSD NFS server such that `svc_rpc_gss_validate()` writes past its 128-byte stack buffer and overwrites the saved return address on a kernel worker thread, achieving kernel control-flow hijack without defeating stack canaries (absent) or KASLR (absent).

- **(a) Corruption primitive:** Linear kernel stack buffer overflow — 304 bytes of attacker-controlled bytes past a 128-byte buffer, in a function frame whose saved return address and adjacent callee-saved registers lie within the overflow's reach.
- **(b) Attack vector:** A single unauthenticated NFS RPC carrying a maximally-sized RPCSEC_GSS credential, sent to a network-reachable `nfsd`/`rpc.gssd` listener on a default FreeBSD installation.
- **(c) Attacker control needed:** TCP/UDP reachability to the FreeBSD RPC port; the ability to craft an XDR-encoded RPC header whose `credentials` field is up to 400 bytes; no authentication state on the target.

**How to falsify:** Send a crafted RPC and observe whether the NFS worker thread crashes with a faulting PC matching attacker bytes, or executes a planted gadget. If overflow occurs but does not reach the return address (e.g., the frame layout interposes uncontrollable data), the "kernel control-flow hijack" portion of the claim is falsified even though the overflow is confirmed.

---

# Task 3 — Directed Testing Plan for CVE-2024-4947

Goal: confirm or refute Hypothesis 1 — that a crafted JS sequence yields an in-sandbox type-confusion primitive in V8 `< 125.0.6422.60`. No live exploitation against third parties; all work in an isolated lab.

**1. Establish the patch boundary.**
   - Pull the Chromium / V8 source at the last vulnerable revision (immediately before the fix that landed in 125.0.6422.60) and at the fix revision.
   - Diff the V8 tree between the two revisions, filtering to files plausibly related to type confusion (compiler/, objects/, ic/, runtime/). The fix's narrow scope identifies the suspect call path.
   - **Evidence collected:** the exact function(s) touched and the precondition the patch adds. This is the seed for trigger construction.

**2. Build instrumented vulnerable and patched binaries.**
   - Build the vulnerable V8 with `is_debug=true`, `v8_enable_slow_dchecks=true`, ASan, and the V8 sandbox in *testing* mode (`v8_enable_sandbox=true`, `--sandbox-testing`).
   - Build the patched V8 with identical flags as a control.
   - **Evidence collected:** two `d8` binaries differing only by the fix.

**3. Reconstruct a minimal trigger from the patch.**
   - From the patch's added check, infer the invariant being protected (e.g., "this object's map must still be X after operation Y"). Write a JS snippet that *violates* that invariant by forcing the optimizer through the relevant speculative path: typically a warmup loop to trigger TurboFan/Maglev, then a control-flow trick (try/catch, deopt-on-callback, prototype mutation, indexed-store on a transitioned array) that invalidates the speculation without the IC noticing.
   - Run the snippet under both binaries.
   - **Confirms hypothesis:** vulnerable `d8` crashes or asserts inside the suspected function; patched `d8` runs cleanly. **Refutes:** both behave identically — the patch is for a different trigger, return to step 1 and broaden the diff window.

**4. Characterize the primitive.**
   - Once a crash is reproducible, replace the destructive payload with diagnostic JS that reads neighbour object headers (map pointer, length field) through the confused view. Print observed vs. expected values.
   - **Confirms:** the script can read a memory word it should not be able to address (e.g., the map pointer of an unrelated `Object`), proving the confusion is a real OOB primitive, not just a DCHECK trip.
   - **Refutes:** the DCHECK fires but no actual mis-typed access is reachable in release builds — the hypothesis (exploitable primitive) is wrong even though the bug is real.

**5. Demonstrate in-sandbox `addrof`/`fakeobj`.**
   - Extend the snippet to (a) leak the address of a controlled object (`addrof`) and (b) forge a fake object at an attacker-chosen address inside the V8 sandbox (`fakeobj`). Verify by reading back known sentinel bytes placed in an `ArrayBuffer`.
   - **Confirms hypothesis fully:** both primitives work on the vulnerable build, neither on the patched build.
   - **Refutes:** the OOB read works but cannot be shaped into `addrof`/`fakeobj` — the bug is confirmed but the *exploitability* portion of the hypothesis is downgraded; revise the ranking accordingly.

**6. Cross-check against public attestation.**
   - Compare the reproducer's behaviour against any indicators released alongside the CISA KEV listing (crash signatures, exploit telemetry summaries from vendor write-ups).
   - **Confirms:** behaviour matches public descriptions of the in-the-wild exploit's symptoms.
   - **Refutes:** symptoms diverge — possible the same CVE covers multiple sub-bugs and the reproducer is a sibling, not the in-the-wild trigger. Document and continue.

**7. Containment and scope verification.**
   - Repeat step 5 with V8 sandbox *enforced* (not testing mode). Verify the primitive remains confined inside the sandbox heap. This bounds the residual impact of the bug class and informs whether downstream sandbox-escape research is warranted.
   - **Evidence collected:** the boundary between "exploitable in-sandbox primitive" and "renderer RCE" — which determines whether the original CISA KEV listing implies an additional, chained sandbox-escape bug.

A successful run of steps 1–5 on the vulnerable build with a clean run on the patched build constitutes confirmation of the hypothesis. A failure at any step localizes the falsification: step 3 falsifies the trigger model, step 4 falsifies the primitive's existence, and step 5 falsifies the claim of practical exploitability while leaving the bug itself intact.