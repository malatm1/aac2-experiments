# Task 1 — Triage and Ranking (Most → Least Exploitable)

**1. CVE-2026-4747 — FreeBSD NFS RPCSEC_GSS stack overflow.**
Near-ideal conditions for kernel RCE: 304 bytes of linear, attacker-controlled overflow into a fixed-layout 128-byte kernel stack buffer; no stack canaries and no KASLR in default FreeBSD builds, so saved return addresses are clobbered without detection and gadget addresses are deterministic. Reachable over the network on any host exposing NFS with RPCSEC_GSS, triggered during the authenticator validation path (i.e., before the GSS context is fully trusted). Pure memory corruption with a strong primitive and minimal mitigations beats every other entry on this list.

**2. GHSA-crr4-7rm4-8gpw — Mastodon SSRF via IPv6 `::`.**
Trigger cost is essentially zero: substitute `[::]` (or an equivalent representation) into any user-controllable URL that Mastodon dereferences server-side. Bypassing a deny-list with the unspecified address is a known class of mistakes and is fully deterministic — no race, no memory state, no user interaction. Impact is bounded by what's bound to wildcard on the host, but the bug itself is as exploitable as web bugs get.

**3. GHSA-chgx-jx3p-rf73 — Mastodon LD-Signature bypass via JSON-LD named-graph restructuring.**
A trust-boundary logic flaw, not a memory bug, so it fires reliably every time once the right document shape is found. The attacker only needs to sign a document from any actor they control and exploit the divergence between what canonicalization signs and what the consumer interprets. Result is forged federation messages attributable to arbitrary actors — broad impact, no mitigations to defeat.

**4. CVE-2024-2887 — V8 WebAssembly type confusion (Pwn2Own 2024).**
A fully working renderer-RCE exploit was publicly demonstrated. Type confusion in V8 is among the strongest primitives in browser exploitation, and Pwn2Own existence is the strongest possible evidence that reliable weaponization is feasible. Sandbox containment is the only thing keeping it below the FreeBSD bug; full impact still requires chaining a sandbox escape.

**5. CVE-2024-4947 — V8 type confusion (CISA KEV).**
Listed as exploited in the wild, which means at least one threat actor produced a stable exploit. Type confusion is again a top-tier primitive. Slightly below #4 only because Pwn2Own implies a published, validated technique, whereas KEV implies it exists but the details are typically less public.

**6. CVE-2024-7965 — V8 heap corruption (exploited in the wild).**
Also confirmed exploited, but "inappropriate implementation … heap corruption" is a weaker characterization than direct type confusion. Heap corruption usually demands more grooming and is more sensitive to allocator state than a TC primitive, so it sits below the two TC-class V8 bugs despite ITW status.

**7. CVE-2023-6702 — V8 Promise.all type confusion.**
Public PoC exists and the Promise.all class of bugs is well-documented in the V8 exploitation literature. Weaponization is plausibly straightforward for someone with V8 experience, but lack of in-the-wild evidence or competition demonstration drops it below #4–#6.

**8. GHSA-f26g-jm89-4g65 — Gitoxide submodule RCE.**
RCE primitive is strong and reliable once triggered, but exploitation requires the victim to clone or `submodule update` an attacker-controlled repo — a user-interaction gate plus a social-engineering precondition. Comparable to the historical git submodule CVEs that became reliable n-days.

**9. GHSA-9f49-8x56-jmjc — libyang heap UAF write.**
A write-side UAF in metadata list management is exploitable in principle, but libyang's parser is constrained input territory: the attacker must drive the allocator state via XML structure alone, and there is no indication the freed object is directly attacker-controlled. Medium severity reflects the realistic difficulty.

**10. CVE-2026-5194 — wolfSSL missing digest size / OID checks.**
Critical CVSS, but practical exploitation is gated by *cryptography*, not memory state. Accepting an undersized digest only matters if the attacker can produce a forging signature — i.e., a collision or second-preimage in whatever short hash slipped through. For ECDSA/EdDSA/ML-DSA, that work factor remains large unless the truncation pushes hash strength into genuinely broken territory. The bug also primarily enables certificate forgery, which is one step removed from code execution. Highest impact, lowest near-term weaponization.

---

# Task 2 — Hypotheses for Top Three

## H1 — CVE-2026-4747 (FreeBSD NFS RPCSEC_GSS)

**Falsifiable claim:** An unauthenticated attacker who can send RPC traffic to a default-configured FreeBSD NFS server can submit an RPCSEC_GSS authenticator whose XDR-encoded credentials body exceeds 96 bytes such that the trailing bytes of the 400-byte field overwrite the saved return address (and adjacent saved registers) of `svc_rpc_gss_validate()`'s 128-byte stack frame, yielding kernel-mode PC control on the NFS worker thread without triggering a canary or KASLR-defeated relocation.

- **(a) Corruption primitive:** Linear stack-buffer overflow, 304 bytes attacker-controlled past a 96-byte gap. Adjacent stack metadata (saved frame pointer, saved RIP, possibly saved callee-saved registers) is overwritable. No canary present in default builds, so the function epilogue returns into attacker bytes.
- **(b) Attack vector:** Network — a single crafted RPC call to the NFS service's RPCSEC_GSS handler. The overflow happens during *authenticator validation*, before the GSS context is established, so it is reachable pre-authentication relative to the underlying NFS service.
- **(c) Attacker control:** The size and contents of the RPCSEC_GSS credentials body (XDR opaque, up to 400 bytes). Because there is no KASLR, kernel-text and known-symbol addresses are deterministic per kernel build, so the attacker only needs to fingerprint the FreeBSD/kernel version to choose gadget/symbol targets.

## H2 — GHSA-crr4-7rm4-8gpw (Mastodon SSRF via `::`)

**Falsifiable claim:** A remote unauthenticated attacker can supply a URL with the IPv6 unspecified address as host (e.g., `http://[::]:PORT/path`) in any Mastodon field that the server later dereferences (remote-media fetch, ActivityPub object resolution, link preview, webfinger), and Mastodon's internal-address denylist will fail to reject it, causing the request to be issued against a service bound to `::` or `0.0.0.0` on the Mastodon host — returning that service's response into Mastodon's request-handling path.

- **(a) Trust violation:** URL allowlist/denylist treats `::` as "unspecified/non-routable" rather than "resolves to a local interface at the socket layer," so validation says *external* while the kernel routes *internal*.
- **(b) Attack vector:** Any user-submittable URL that Mastodon resolves server-side. ActivityPub object URLs and remote-media URLs are the most likely first candidates because they are accepted from federated peers.
- **(c) Attacker control:** Just the URL string; no auth and no special infrastructure required beyond a federation actor (or any unauthenticated input path that triggers a server-side fetch).

## H3 — GHSA-chgx-jx3p-rf73 (Mastodon LD-Signature named-graph bypass)

**Falsifiable claim:** An attacker controlling any federated ActivityPub actor can construct a JSON-LD payload whose RDF-canonicalized form covers only an inner named graph, while Mastodon's higher-level ActivityPub processor reads top-level fields (actor, object) from outside the signed graph, allowing an LD-Signature legitimately produced over an inert sub-document to validate a delivery whose effective semantics impersonate an arbitrary remote actor.

- **(a) Trust violation:** Divergence between the document scope used for signature canonicalization and the document scope used for activity interpretation. Signing covers triples inside a named graph; consumers act on triples in the default graph.
- **(b) Attack vector:** A POST to a target server's ActivityPub inbox carrying the crafted JSON-LD with a valid LD-Signature from the attacker's own actor key.
- **(c) Attacker control:** The JSON-LD document body (full structural control), a valid keypair for one federation actor (free to obtain), and the inbox URL of any Mastodon server federating openly.

---

# Task 3 — Directed Testing Plan for CVE-2026-4747

Scope note: every step below is to be executed in an isolated, offline FreeBSD VM that the researcher owns. No live or third-party systems are targeted.

1. **Reproduce the build environment.** Install a FreeBSD release matching a vulnerable pre-patch version. Verify `sysctl kern.elf64.aslr.*` and the kernel build flags to confirm KASLR is disabled by default and that the kernel binary was built without `-fstack-protector*`. This is the precondition that makes the hypothesis testable; if these mitigations are present, the hypothesis already needs to be narrowed.

2. **Confirm the source layout.** Read `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c` at the affected revision and locate `svc_rpc_gss_validate()`. Verify (i) the 128-byte stack buffer, (ii) the 32-byte fixed header write, (iii) the unbounded copy of the credentials body into the remaining 96 bytes, (iv) the XDR ceiling of 400 bytes upstream. These are the four structural claims behind the primitive; any one being wrong falsifies the hypothesis as stated.

3. **Stand up a target NFS service.** Enable NFS with RPCSEC_GSS in the test VM. Confirm the validation path is reachable on the wire (e.g., via a benign well-formed RPCSEC_GSS request that gets rejected at a later stage).

4. **Disassemble the compiled function.** In the running kernel image, disassemble `svc_rpc_gss_validate` and confirm the epilogue has no canary check (`__stack_chk_fail` not referenced) and uses a standard `ret` against a saved RIP on the stack. Identify the exact byte offset, within the 96-byte gap + overflow region, of the saved return address relative to the start of the buffer. This offset is the central quantitative prediction.

5. **Trigger crash with size sweep.** Write a minimal RPC client that emits well-formed RPCSEC_GSS frames but varies the credentials body length from 80 through 400 bytes in single-byte increments, with a distinctive pattern (e.g., De Bruijn sequence) in the payload. Run against the target with `kgdb` attached.
   - *Expected confirming evidence:* No crash up to ~96 bytes; crash beginning consistently at the predicted threshold; `kgdb` shows the faulting instruction is the `ret` of `svc_rpc_gss_validate`; the value loaded into RIP matches a specific window of the De Bruijn pattern, giving a precise saved-RIP offset.
   - *Refuting evidence:* Crash occurs earlier (suggests an unrelated bounds check or smaller buffer); no crash at all (suggests an upstream limit smaller than 400 bytes, or KASLR/canary actually present); RIP not influenced (suggests non-linear copy semantics).

6. **Map adjacent saved state.** With the offset known, vary specific 8-byte windows within the controlled region and observe which saved registers change in the crash dump. Build a register-layout map of the frame.

7. **Demonstrate clean PC control without weaponization.** Choose a benign kernel-text symbol (e.g., a function that prints a fixed string via `printf` and returns). Set saved RIP to that symbol's address. Confirm via dmesg/serial that the chosen function executed and the kernel survived or panicked predictably afterwards. This step is the minimum sufficient confirmation that arbitrary kernel-text control is achievable; no privilege escalation or persistent payload is needed to validate the hypothesis.

8. **Vary kernel build to test mitigation claim.** Rebuild the kernel with `-fstack-protector-strong` and rerun step 5. Expected result if hypothesis is correctly scoped: canary detection panics before `ret`, eliminating the primitive. This is the falsifier for the "default builds lack canaries" half of the claim.

9. **Document reachability constraints.** Record whether the validation path is reachable without prior authentication, what NFS exports configuration affects reach, and whether `mountd`/`rpcbind` mediation changes the picture. The hypothesis is strongest if step 5 succeeds with no NFS export mounted by the attacker; weaker (but not refuted) if exports are required.

10. **Report.** Evidence sufficient to confirm: (i) source layout matches §2; (ii) disassembly matches §4; (iii) size sweep yields a deterministic saved-RIP offset (§5); (iv) chosen kernel-text symbol executes via redirected return (§7); (v) canary-enabled rebuild defeats the primitive (§8). Any single failure among (i)–(iv) refutes the hypothesis as stated and indicates the bug is real but the exploitation model differs.