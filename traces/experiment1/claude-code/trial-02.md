# Vulnerability Analysis

## Task 1 — Triage and Ranking (Most → Least Exploitable)

**1. CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS kernel stack overflow.** A linear 304-byte stack overflow in kernel context, reached pre-authentication over the network, on a target compiled without stack canaries or KASLR. The overflow is deterministic (fixed buffer, fully attacker-sized credentials body), it overwrites a saved return address in a kernel frame, and there are no mitigations stated to defeat. This is the textbook "easiest" exploitation primitive in the set: deep control, no probabilistic bypasses required, RCE in ring 0.

**2. CVE-2024-7965 — V8 heap corruption (exploited in the wild).** ITW exploitation is empirical proof of weaponized reliability against fully mitigated Chrome (CFI, sandbox, ASLR, V8 heap sandbox). Higher than the other V8 entries because attackers have already converted the primitive into a working chain — not just a PoC.

**3. CVE-2024-4947 — V8 type confusion (CISA KEV).** Type confusion in V8 is one of the most weaponizable primitive classes (fake-object → addrof/fakeobj → arbitrary R/W). KEV-listed, so confirmed used by real actors. Slightly below #2 only because the description constrains exploitation to within the V8 sandbox.

**4. CVE-2024-2887 — V8 WebAssembly type confusion (Pwn2Own 2024).** Pwn2Own demonstration implies an end-to-end working exploit existed under contest conditions. WASM compilation paths frequently bypass JS-level mitigations (e.g., V8 sandbox guards on TypedArrays). One step below #3 because we have no evidence of in-the-wild use, only a contest demo.

**5. CVE-2023-6702 — V8 Promise.all type confusion.** Public PoC available, same general primitive family as #3/#4. Ranked below the other V8 entries because "object corruption" via Promise.all has historically required more gadget chaining (control flow through scheduler callbacks) and there is no claim of weaponization beyond PoC.

**6. GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE.** RCE confirmed by severity classification, with a clear delivery vector (clone/update of a malicious repo). Ranked below the V8 entries because it requires social/supply-chain interaction — the victim must run a `git`/`gix` operation against attacker content. The corruption primitive itself is likely deterministic (argument injection, path traversal into hook execution, etc.), making exploitation reliable once the user is induced to run the operation.

**7. CVE-2026-5194 — wolfSSL signature verification.** A trust-boundary violation rather than a memory-corruption primitive: accepting under-sized digests can allow forged signatures, particularly in chains mixing ECC and EdDSA/ML-DSA. Exploitation requires (a) a relying party using a vulnerable configuration and (b) finding/constructing a forged certificate or signed artifact the digest-truncation weakness actually validates. Significant cryptographic engineering needed; impact is severe (chain forgery, MitM), but the path from primitive to practical attack is non-trivial.

**8. GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass via JSON-LD named-graph restructuring.** Logic flaw enabling federated message forgery. Trust violation, not memory corruption. Vector is well-defined (any federated instance can receive crafted AP activities), and the impact (impersonation across the fediverse) is meaningful but the blast radius per exploit is bounded — attacker impersonates accounts, does not gain code execution.

**9. GHSA-9f49-8x56-jmjc — libyang heap UAF write.** Use-after-free *write* is generally exploitable, but libyang is consumed inside larger systems (NETCONF servers, OS modules) where reachability of attacker-controlled XML is the constraint. Medium severity reflects that the write is bounded (a single mis-updated list-head pointer), so weaponization needs careful heap shaping. Slower path than the items above.

**10. GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 `::`.** A useful primitive (reach internal services) but not RCE on its own. Its exploit value depends entirely on what internal services live behind the Mastodon host — fundamentally a chained/contextual vulnerability. Lowest practical exploitability of the set when considered in isolation.

---

## Task 2 — Hypotheses for Top Three

### #1 — CVE-2026-4747 (FreeBSD NFS RPCSEC_GSS)

**Falsifiable claim:** An attacker who can reach the NFS RPC endpoint can send a single RPCSEC_GSS request whose `credentials` field is between 97 and 400 bytes long, causing `svc_rpc_gss_validate()` to write 96 bytes of header continuation followed by up to 304 bytes of attacker-controlled bytes past the end of its 128-byte stack buffer, overwriting the saved return address (and any adjacent stack metadata) in the NFS worker thread's kernel stack frame and yielding control of the kernel instruction pointer at function return.

- **(a) Primitive:** linear stack-buffer overflow in kernel mode; 304 bytes of attacker-controlled overflow past a 128-byte buffer; no stack canary to detect tampering, no KASLR to randomize the return target.
- **(b) Vector:** unauthenticated network request to `rpc.gssd`/NFS service that exercises the `svc_rpc_gss_validate()` path during RPC header reconstruction.
- **(c) What the attacker controls:** the entire credentials body of the RPC message (size + content, bounded only by the XDR 400-byte cap), which determines both the overflow length and the value written over the saved return address.

### #2 — CVE-2024-7965 (V8 heap corruption, ITW)

**Falsifiable claim:** A specific JIT/compiler optimization path in V8 ≤128.0.6613.83 produces code that operates on an object under an incorrect size or type assumption, yielding an OOB read/write or a stale-handle dereference on the JS heap that an attacker can convert into addrof/fakeobj primitives from a single crafted HTML page, leading to RCE inside the renderer sandbox.

- **(a) Primitive:** heap corruption (likely TurboFan/Maglev-induced OOB or type-state desync) in the V8 object heap.
- **(b) Vector:** drive-by HTML/JS served to a vulnerable Chromium-based browser; no user action beyond visiting the page.
- **(c) What the attacker controls:** JavaScript source executed in the renderer — function shapes, object hidden classes, IC feedback, and the trigger sequence that forces the compiler down the buggy optimization path.

### #3 — CVE-2024-4947 (V8 type confusion, CISA KEV)

**Falsifiable claim:** In V8 ≤125.0.6422.59, a specific operation can be made to interpret an object of type A as type B, so that field accesses defined for type B read/write at offsets where unrelated data lives under type A; an attacker can use this aliasing to obtain a controlled read primitive (e.g., reading a JSArray's elements pointer as a number) and a controlled write primitive (writing a JSArray's elements pointer with an arbitrary number), confined to the V8 sandbox but sufficient for arbitrary R/W and JIT-page corruption.

- **(a) Primitive:** type confusion between two V8 object kinds with overlapping but mismatched layouts.
- **(b) Vector:** crafted HTML page executing JS that drives the engine into the confused state.
- **(c) What the attacker controls:** JS-level objects whose internal representations alias the targeted type, plus the sequence that causes the engine to treat one as the other (e.g., feedback poisoning, deopt + reuse, or a missing map check on a hot path).

---

## Task 3 — Directed Testing Plan for CVE-2026-4747

Goal: confirm or refute the hypothesis that a crafted RPCSEC_GSS credentials field overflows `svc_rpc_gss_validate()`'s 128-byte stack buffer and overwrites the saved return address.

1. **Static review of the patched and unpatched source.**
   - Read `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c` at the vulnerable revision and the fix commit.
   - Identify `svc_rpc_gss_validate()`, the 128-byte stack buffer, the 32-byte header write, and the unbounded `memcpy`/equivalent of the credentials body.
   - Confirm in the XDR decoder that `credentials.oa_length` is bounded only by the 400-byte XDR cap, not by 96.
   - Diff the patch to identify the bounds check added (e.g., `if (cred_len > 96) return AUTH_BADCRED`) and verify it gates the exact copy the hypothesis names.
   - **Confirms** the hypothesis if (i) the buffer arithmetic is `128 = 32 + 96` and (ii) the patch is a length check on the credentials body before the copy. **Refutes** if the copy is actually bounded by an earlier check or the buffer is allocated dynamically.

2. **Build a debug FreeBSD kernel at the vulnerable revision.**
   - Compile with `INVARIANTS`, `WITNESS`, full DWARF, no stack canaries (confirm default `-fno-stack-protector` for kernel build), and serial console enabled.
   - Boot the kernel in a VM with NFS server + RPCSEC_GSS configured per `gssd(8)`.
   - Attach `kgdb` to the live kernel over the serial / virtio-console.

3. **Confirm the stack layout empirically.**
   - Set a breakpoint at the entry and at the offending `memcpy` inside `svc_rpc_gss_validate()`.
   - Inspect `$rsp` and the buffer address; compute the byte distance from the buffer start to the saved return address slot.
   - Record the expected overflow length needed to reach (a) the saved frame pointer, (b) the saved return address, (c) the next function's frame.
   - **Confirms** if the saved return address lies between offset 128 and 128+304 (i.e., within reach). **Refutes** if the buffer is below the return address by more than 304 bytes (e.g., the compiler placed large locals between them).

4. **Craft a benign over-long credentials request.**
   - Write a userland test client (in a separate VM on the same network) that speaks ONC-RPC and emits an `AUTH_GSS` credential with `oa_length` set in increments: 96, 100, 128, 160, 200, 304, 400 bytes.
   - Payload contents: a cyclic De Bruijn pattern (e.g., `pwntools`'s `cyclic(304)`) padded with `'A'`s, so that the offset of any overwrite can be derived from the corrupted value observed in the panic.
   - The client should stop after one request — no spraying needed for the proof-of-primitive.

5. **Observe behaviour under increasing credential lengths.**
   - With `kgdb` attached, send each test request and observe:
     - At 96 bytes: function returns normally → baseline.
     - At >96 bytes: write extends past the buffer; inspect adjacent stack words for the pattern.
     - At a length that reaches the return slot: `ret` from `svc_rpc_gss_validate()` should set `$rip` to a value drawn from the cyclic pattern → panic with that value.
   - **Confirms** the hypothesis if the panic's faulting instruction pointer matches a slice of the cyclic pattern, and the byte offset within the pattern equals the predicted distance from the buffer to the return address.
   - **Refutes** if no panic occurs at any size up to 400 bytes (suggesting an earlier check), or if the panic happens before `ret` (suggesting a canary or KASAN-like check is enabled), or if `$rip` does not correspond to attacker bytes (suggesting an intervening structure absorbed the overflow).

6. **Differential test against the patched kernel.**
   - Rebuild with the FreeBSD security advisory patch applied.
   - Re-run the same request set and verify the request is rejected at the XDR/credential-validation stage with no write past the buffer (`kgdb` breakpoint on the `memcpy` should never fire for `len > 96`).
   - **Confirms** the patch addresses the same primitive the hypothesis names.

7. **Sanity-check the mitigations claim.**
   - Inspect the built kernel binary with `objdump`/`readelf` for `__stack_chk_*` symbols in `svc_rpc_gss_validate`'s object file.
   - Inspect the running kernel's text base across reboots to confirm no KASLR slide.
   - **Confirms** the "no canaries, no KASLR" precondition stated in the advisory; **refutes** if either mitigation is present in the build under test (which would force a reassessment of exploitation difficulty even if the primitive itself exists).

8. **Reachability and authentication state.**
   - Verify in source whether the vulnerable copy executes before or after any peer authentication. Set a breakpoint and confirm via the test client that an *unauthenticated* RPCSEC_GSS init call reaches the overflowing copy.
   - **Confirms** pre-auth network reachability (worst case). **Refutes** if a valid GSS context is required first, which would re-rank the bug downward.

Collectively, steps 1, 3, 5, and 6 form the minimal evidence set: source shows the missing check, debugger shows the buffer-to-return-address distance, a single crafted request produces a panic with attacker bytes in `$rip` at the predicted offset, and the patched kernel rejects the same request without ever entering the copy. If all four hold, the hypothesis is confirmed; failure of any one falsifies the specific claim and points at which sub-assumption was wrong.