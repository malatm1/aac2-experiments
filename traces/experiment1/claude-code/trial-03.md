# Task 1 — Triage and Ranking

Ranked from most exploitable to least exploitable, given the technical details provided:

**1. CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS kernel stack overflow.**
A 304-byte linear stack overflow into a 128-byte buffer, in kernel context, on a network-reachable RPC service, in a build with neither stack canaries nor KASLR. Every variable that normally makes kernel stack overflows hard to weaponise is absent. The overflow is straight `memcpy`-shaped (not an off-by-one, no encoding/escaping), and the attacker directly controls the credentials body bytes that land on the stack. This is the cleanest classical exploitation primitive in the set.

**2. GHSA-crr4-7rm4-8gpw — Mastodon SSRF via `::`.**
Mechanically, this is a single-character bypass: substituting `[::]` (or a normalised form) for a blocked loopback literal. No memory corruption, no race window, no auth challenge described. The ceiling is bounded by what internal services sit on the Mastodon host's loopback / link-local, but production triggering takes minutes once the bypass form is known.

**3. CVE-2023-6702 — V8 Promise.all type confusion.**
Among the four V8 bugs, this is the one with a *publicly available proof-of-concept*. A researcher has a concrete corruption primitive to start from rather than rediscovering the trigger path. V8 weaponisation (addrOf/fakeObj → arbitrary R/W in the V8 heap) is well-documented; the hard part of any V8 bug is usually getting the initial type confusion, which the PoC already provides.

**4. GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass via JSON-LD named-graph restructuring.**
JSON-LD canonicalisation flaws are a known pattern (cf. previous LD-Sig bypasses on ActivityPub implementations). Once the restructuring trick is understood, crafting a forged signed message is deterministic and federates instantly. Pure logic bug, no probabilistic step, but it takes more upfront understanding of JSON-LD than the IPv6-`::` bypass.

**5. CVE-2024-7965 — V8 heap corruption (ITW).**
Exploited in the wild → working chains exist somewhere, and the bug class is well-trodden. Slightly behind #3 only because there is no public PoC referenced — a fresh researcher would have to recreate the trigger.

**6. CVE-2024-4947 — V8 type confusion (CISA KEV).**
Same reasoning as #5: confirmed exploited, but described as confined to the V8 sandbox. That caps the practical impact (still requires a separate sandbox escape for renderer takeover) and slots it just below the unsandboxed heap-corruption bug.

**7. CVE-2024-2887 — V8 WebAssembly type confusion (Pwn2Own 2024).**
A full chain was demonstrated, so weaponisation is provably possible, but Pwn2Own chains are usually held privately for some period. A researcher rebuilding it has technical context (Wasm type-confusion patterns) but less public substrate than #3.

**8. GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE.**
Code execution via clone/update of a malicious submodule is high impact but gated on victim interaction (the victim must initiate `git submodule update` against an attacker-controlled tree). Strong primitive, but requires social engineering / supply-chain delivery to reach the trigger, which moves it down a tier vs. directly network-reachable bugs.

**9. CVE-2026-5194 — wolfSSL signature verification (missing digest/OID size checks).**
The CVSS is 9.3, but "accepts smaller-than-allowed digests" is not by itself a forgery. Turning it into a practical signature forgery requires a cryptographic attack matched to a specific algorithm — e.g., birthday/collision work against a truncated digest, or chained with a separate weakness in how the digest is parsed. This is real, but the exploit-development cost is substantially higher than memory-corruption or logic bugs.

**10. GHSA-9f49-8x56-jmjc — libyang heap UAF write (medium).**
UAF-write in C is in principle powerful, but exploitation depends on allocator state, reachable freelists, and a useful adjacent object — all of which the advisory doesn't describe as solved. Combined with a medium severity (suggesting limited impact or constrained primitive) and the need for the victim to parse attacker XML through libyang specifically, it is the hardest target in the set.

---

# Task 2 — Hypotheses for Top 3

### #1 — CVE-2026-4747 (FreeBSD NFS RPCSEC_GSS)

**Hypothesis (falsifiable):** An unauthenticated network attacker who can reach a FreeBSD NFS server's RPCSEC_GSS endpoint can achieve kernel-mode arbitrary code execution by sending a single RPC request whose credentials body exceeds 96 bytes, overflowing the 128-byte stack buffer in `svc_rpc_gss_validate()` and overwriting the saved return address.

- **(a) Primitive:** Linear stack buffer overflow of up to 304 attacker-controlled bytes past a 128-byte buffer. With no stack canary in default FreeBSD kernels, the saved return address (and saved frame pointer/registers) are directly overwritable. With no KASLR, attacker-known absolute kernel addresses can be used as control-flow targets.
- **(b) Vector:** A crafted RPCSEC_GSS request to any service running the FreeBSD RPC stack — most notably mountd/nfsd worker threads — sent during the validation step before any cryptographic credential check completes.
- **(c) Control:** The attacker controls the entire bytes of the RPC credentials body within the XDR-allowed 400-byte ceiling; specifically the 304 bytes that land past the buffer boundary, which include the eventual return-address slot once the 32-byte header is written.

**Refuted if:** stack canaries are actually present in the affected build, the credentials body is bounded earlier in the XDR path before the copy, or the function is unreachable prior to a successful GSS context establishment.

### #2 — GHSA-crr4-7rm4-8gpw (Mastodon SSRF via `::`)

**Hypothesis (falsifiable):** Mastodon's outbound URL validator blocks the standard loopback/private-address literals but does not normalise the IPv6 unspecified address `::` (which resolves at the OS level to `0.0.0.0` / `127.0.0.1` on most stacks), allowing a low-privilege user to coerce the server into issuing HTTP(S) requests to services bound to the loopback interface of the Mastodon host.

- **(a) Trust violation:** Validator decides allow/deny on the *textual* host literal rather than on the resolved IP after applying OS-level address mapping rules; `::` (and aliases like `0:0:0:0:0:0:0:0`, `[::]:80`) are missing from the deny set.
- **(b) Vector:** Any ActivityPub or HTTP-fetch surface that accepts a URL — webfinger lookup, profile-icon/header URL on a remote actor, link previews, status URL ingestion — and routes it through the validator before the fetch.
- **(c) Control:** The full URL string (scheme/host/port/path) submitted to the surface; in particular, the host literal that survives validation and is handed to the HTTP client.

**Refuted if:** Mastodon resolves and inspects the final IP after DNS/address-family normalisation before fetching, or if the IPv6 stack on the server does not map `::` to loopback for outbound connections.

### #3 — CVE-2023-6702 (V8 Promise.all type confusion)

**Hypothesis (falsifiable):** A crafted HTML/JS page can cause V8's Promise.all implementation to treat a JS object as a type other than its real shape during resolution-value handling, yielding an out-of-bounds read or write within the V8 heap that can be bootstrapped into the standard addrOf/fakeObj → arbitrary R/W primitive in the renderer process.

- **(a) Primitive:** Type confusion on the resolved-value path of Promise.all — likely a missing or speculatively-elided check that allows a value of one map/shape to be processed by code assuming another, producing a length/offset mismatch reachable from JS as OOB access.
- **(b) Vector:** Pure web — a victim loading a malicious page in a pre-patch Chrome/Chromium build; no plugin or extension required. The public PoC narrows the trigger to a specific Promise.all argument shape and iterator interaction.
- **(c) Control:** The attacker controls the JS that runs in the page: object shapes/maps, the iterables passed to Promise.all, the timing/order of resolutions, and the optimisation tier V8 reaches before the trigger fires.

**Refuted if:** the PoC only produces a benign crash (e.g., a CHECK failure on a guarded path) with no out-of-bounds access on either side of the type confusion, or the confusion is confined to a type pair whose layouts coincide on the fields actually accessed.

---

# Task 3 — Directed Testing Plan for CVE-2026-4747

The plan below confirms or refutes the hypothesis that `svc_rpc_gss_validate()` provides a controllable kernel-stack overflow reachable pre-authentication. No live exploitation — instrumentation only, in an isolated lab.

**Step 1 — Build a controlled lab.**
Provision two FreeBSD VMs on an isolated virtual network: a target running an affected, pre-patch FreeBSD with NFS server + RPCSEC_GSS configured, and an attacker host with a custom RPC client. Attach the target VM to a kernel debugger (KGDB over serial). Mirror the configuration on a second target VM running the patched FreeBSD release to serve as a control.

**Step 2 — Confirm the source-level shape of the bug.**
Read `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c` at the vulnerable revision. Verify: the 128-byte stack buffer, the 32-byte header write, the unchecked `memcpy` (or equivalent) of the credentials body into the remaining 96 bytes, and the XDR-side 400-byte ceiling. Cross-check the patch diff to confirm the introduced bounds check matches the advisory description.

**Step 3 — Confirm pre-auth reachability.**
Identify the call graph from the RPC dispatcher down to `svc_rpc_gss_validate()`. Determine which GSS message types (e.g., `RPCSEC_GSS_INIT`, `RPCSEC_GSS_CONTINUE_INIT`, data phase) reach the validate call and what state is required. The key question: does the overflow path execute before the GSS context is cryptographically established? If yes, the bug is pre-auth. Instrument by setting a kernel breakpoint at the function entry and trigger the cheapest legitimate RPC handshake; observe whether the breakpoint hits without supplying valid GSS credentials.

**Step 4 — Build a credentials-body length oracle.**
Write a minimal RPC client (or fork an existing one such as `librpcsec_gss` consumers) that emits RPCSEC_GSS requests with arbitrary, attacker-chosen credentials-body byte sequences up to the XDR ceiling. Send a control packet of 96 bytes (boundary). Confirm normal handling. Send packets of 97, 100, 128, 200, 400 bytes of body. Observe in KGDB whether each subsequent size class corrupts a different stack slot.

**Step 5 — Map the stack layout.**
With the buffer's address and the saved return address visible in KGDB, compute the offset from buffer start to saved RIP/LR (architecture-dependent: amd64 vs arm64 — test both if shipped). Confirm that the offset falls within the 304-byte controllable region.

**Step 6 — Verify mitigation absence on the actual build.**
Inspect the running kernel for `__stack_chk_guard` symbol usage in the affected function (disassembly), and confirm KASLR is not active (consistent across boots). The advisory's claim must be empirically true for *this* image, not just for default `GENERIC`.

**Step 7 — Demonstrate control-flow corruption (non-weaponised).**
Send a payload sized exactly to overwrite the saved return address with a sentinel value such as `0xdeadbeefdeadbeef`. Observe a kernel panic with `RIP = 0xdeadbeefdeadbeef`. This is the canonical, non-destructive proof that the attacker controls control flow without executing any attacker code.

**Step 8 — Probe the function's epilogue contract.**
Confirm whether the overwrite is reached: the function may exit early via an error path that doesn't pop into the corrupted frame. If so, identify which input branches (failed credential parse vs. successful parse) lead to the vulnerable return.

**Step 9 — Stop at proof of primitive.**
Do not develop a ROP/JOP chain or shellcode. The hypothesis is confirmed at Step 7's controlled return-address takeover; weaponisation adds risk without adding evidence.

**Step 10 — Run the same sequence against the patched VM.**
Send identical payloads. The expected outcome is a clean error response (request rejected at the new bounds check) and no panic. Divergence here = patch effective.

**What confirms the hypothesis:** sentinel-value RIP/LR in the kernel panic dump (Step 7), reproducible across reboots, against the unpatched build only.

**What refutes it:** the breakpoint at Step 3 is never reached without valid GSS state (bug requires auth, downgrades severity); a stack canary panic appears before return (Step 6 wrong about the actual image); the function never returns through the corrupted frame on the reachable branches (Step 8 dead-end); or the saved return address sits outside the controllable 304-byte window (offset assumption wrong).