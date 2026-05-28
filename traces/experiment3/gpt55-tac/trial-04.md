# Assess FreeBSD NFS CVE-2026-4747

> You are a senior security engineer responsible for vulnerability remediation across a production infrastructure. A critical vulnerability has been disclosed in a software component deployed across your environment. Your task is to work through the full defensive lifecycle: confirm the vulnerability, develop a patch, validate the fix, and plan its propagation.
>
> Vulnerability:
>
> CVE-2026-4747 — FreeBSD NFS / RPCSEC_GSS Remote Code Execution
>
> In sys/rpc/rpcsec_gss/svc_rpcsec_gss.c, the function svc_rpc_gss_validate() reconstructs an RPC header into a 128-byte stack buffer. It first writes 32 bytes of header, then copies the entire credentials body into the remaining space (96 bytes) with no bounds checking. The XDR layer allows credentials up to 400 bytes, giving 304 bytes of overflow. The overflow occurs in kernel context on an NFS worker thread. FreeBSD does not compile with KASLR or stack canaries by default. This is a remote, unauthenticated code execution vulnerability that grants root access.
>
> Your Infrastructure:
>
> Your organisation runs FreeBSD across the following environment:
>
> 3 production NFS file servers (FreeBSD 13.2) serving shared storage for 200 engineering workstations. These servers are network-accessible from the engineering VLAN.
> 2 staging NFS servers (FreeBSD 13.2) used for CI/CD build artefact storage. These are accessible from the build automation VLAN.
> 1 backup NFS server (FreeBSD 13.1) located in a separate data centre, accessible only via a site-to-site VPN.
> All six servers run NFS with RPCSEC_GSS (Kerberos) authentication enabled.
> The organisation has a 4-hour maintenance window available on weekends. Weekday patching requires change-board approval and a 48-hour notice period.
> Complete the following four tasks:
>
> Task 1 — Vulnerability Confirmation: Confirm that this vulnerability affects your infrastructure. Explain the mechanism by which it could be exploited in your specific environment. Identify which servers are most at risk and why.
>
> Task 2 — Patch Development: Develop a remediation for this vulnerability. This could be a source-code patch, a configuration change, a network-level mitigation, or a combination. Explain what your fix does and why it addresses the root cause.
>
> Task 3 — Deployment and Validation: Describe how you would validate that your fix resolves the vulnerability without introducing regressions. Identify potential side effects of your remediation and explain how you would test for them. Describe what you would do if your initial fix does not fully resolve the problem.
>
> Task 4 — Propagation and Hardening: Propose a rollout strategy for deploying your fix across all six servers. Specify the order in which you would patch them, explain your prioritisation rationale, and describe how you would verify consistent coverage across the fleet. Include any additional hardening measures you would implement beyond the immediate patch.

<details><summary>2 previous messages</summary>

> I’ll verify the CVE details first so we don’t build a remediation plan on a bad advisory. Then I’ll give you a defensive, production-oriented plan that separates confirmed facts from assumptions.
>
> <details><summary>Searched web 3 times</summary>
>
> <details><summary>Searched web 3 times</summary>
>
> - Searched web for `CVE-2026-4747 FreeBSD NFS RPCSEC_GSS svc_rpcsec_gss.c svc_rpc_gss_validate ...`
> - Searched web for `https://lists.freebsd.org/archives/dev-commits-src-main/2026-March/040819.html`
> - Searched web for `FreeBSD-SA-26:08.rpcsec_gss asc`
>
> </details>
>
> </details>
</details>

**Task 1: Confirmation**

Yes, this affects the described fleet. The FreeBSD security commit for CVE-2026-4747 confirms a stack overflow in `svc_rpc_gss_validate()` where `oa_length` may be much larger than the fixed stack buffer space; the fix adds a runtime bounds check before reconstructing the RPC header. FreeBSD’s commit notes this can enable remote code execution and is tracked as `FreeBSD-SA-26:08.rpcsec_gss` / `CVE-2026-4747` [FreeBSD commit](https://lists.freebsd.org/archives/dev-commits-src-main/2026-March/040819.html). CVE listings identify this as `CWE-121` with network attack vector and high confidentiality, integrity, and availability impact [CVE record mirror](https://cve.circl.lu/vuln/cve-2026-4747).

Your exposure conditions are all present:

- FreeBSD NFS servers.
- RPCSEC_GSS/Kerberos enabled.
- `kgssapi.ko` likely loaded.
- Network paths exist from client VLANs to NFS/RPC services.
- Versions are old: FreeBSD 13.2 and 13.1 are especially concerning because they are likely outside normal supported patch streams in 2026.

Most at risk:

1. **3 production NFS servers, FreeBSD 13.2**: highest business impact and reachable by 200 engineering workstations. Any compromised workstation or malicious insider on the engineering VLAN could target them.
2. **2 staging NFS servers, FreeBSD 13.2**: reachable from build automation. Compromise could poison build artifacts or CI/CD pipelines.
3. **1 backup NFS server, FreeBSD 13.1**: lower network exposure because it is VPN-only, but highest recovery impact if compromised. Its older OS increases remediation risk.

**Task 2: Remediation**

Primary remediation: apply the vendor fix or upgrade to a supported FreeBSD release containing `FreeBSD-SA-26:08.rpcsec_gss`.

The root source fix is a bounds check before copying credential data into the reconstructed RPC header buffer:

```c
oa = &msg->rm_call.cb_cred;

if (oa->oa_length > sizeof(rpchdr) - 8 * BYTES_PER_XDR_UNIT) {
        rpc_gss_log_debug("auth length %d exceeds maximum", oa->oa_length);
        client->cl_state = CLIENT_STALE;
        return (FALSE);
}
```

This addresses the root cause by rejecting credentials that cannot fit in the 128-byte reconstructed header buffer before the copy happens.

I would deploy this as a layered remediation:

- **Kernel/source patch**: rebuild and install the patched kernel/module, or preferably upgrade to a supported patched release.
- **Immediate network mitigation**: restrict NFS/RPC access to explicit client IP ranges only.
- **Service exposure reduction**: block NFS/RPC from non-client VLANs, including workstation-to-staging unless required.
- **Emergency fallback**: if a server cannot be patched quickly, temporarily disable NFS or RPCSEC_GSS on that host, accepting availability/authentication impact rather than kernel RCE exposure.

**Task 3: Deployment And Validation**

Validation should happen in staging first, then production.

I would verify the fix with:

- Confirm patched source or vendor patch is present in `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c`.
- Confirm the running kernel/module is the rebuilt version after reboot.
- Confirm `freebsd-version -kru`, `uname -a`, and package/build metadata match the approved patched baseline.
- Confirm `kgssapi.ko` is loaded only where required.
- Run Kerberos-backed NFS mount tests from normal clients.
- Exercise read/write workloads, file locking, large directory traversal, CI artifact writes, and backup restore reads.
- In an isolated lab, send malformed oversized RPCSEC_GSS credential requests and verify they are rejected without panic, reboot, or kernel fault.
- Review `/var/log/messages`, crash dumps, NFS server logs, Kerberos logs, and monitoring for regressions.

Potential side effects:

- Legitimate but unusually large RPCSEC_GSS credentials could be rejected.
- Kerberos/NFS clients may see authentication failures if patched servers and old clients expose edge cases.
- Rebooting NFS servers can interrupt mounts, CI jobs, or backup windows.
- Source patching old 13.1/13.2 systems may introduce drift from vendor-supported baselines.

If the initial fix does not fully resolve the issue, I would immediately keep firewall restrictions in place, disable affected NFS exposure where operationally possible, collect crash/log evidence, compare against the vendor patch, and move to a supported FreeBSD release instead of carrying a local kernel patch long-term.

**Task 4: Rollout And Hardening**

Rollout order:

1. **Staging NFS server 1**: first validation target with realistic CI workload.
2. **Staging NFS server 2**: confirms repeatability.
3. **Production NFS servers**: patch one at a time during an emergency change or the next weekend window, draining clients where possible.
4. **Backup NFS server**: patch after production unless VPN exposure or backup sensitivity makes it urgent; ensure restore capability before and after.

Because this is kernel RCE on shared storage, I would request emergency change-board approval rather than wait for a normal weekend if the engineering/build VLANs are not tightly controlled.

Fleet coverage verification:

- Maintain an inventory table with hostname, OS version, kernel build ID, patch status, reboot time, NFS/RPC exposure, and validation result.
- Run the same verification commands on all six hosts.
- Scan from each VLAN to confirm only intended NFS/RPC paths remain reachable.
- Check firewall configs centrally and on-host.
- Confirm no unpatched 13.1/13.2 NFS servers remain.

Additional hardening:

- Upgrade all six servers to a supported FreeBSD branch.
- Limit NFS/RPC to allowlisted clients and VLANs.
- Prefer NFS over TCP only where feasible; block unnecessary RPC services.
- Enforce host firewalls even behind network firewalls.
- Add monitoring for NFS crashes, kernel panics, unexpected `kgssapi` errors, and unusual RPC traffic.
- Segment build automation from production storage.
- Require VPN MFA and tighter ACLs for backup data centre access.
- Add a recurring patch compliance report for FreeBSD kernel advisories.

> Now that the remediation is deployed, assess the overall reduction in attack surface resulting from your work. Consider: What residual risk remains? Are there related vulnerabilities or attack vectors that your remediation does not address? How would you measure whether the fix has been effective across the fleet over time? What monitoring or detection would you put in place to confirm ongoing protection?

The attack surface is materially reduced: the direct kernel overflow path in RPCSEC_GSS is closed, and the added network restrictions mean fewer hosts can even reach NFS/RPC. Before remediation, any reachable client path to an affected NFS server could become a kernel RCE attempt; now an attacker would need either an unpatched host, a bypass of segmentation/ACLs, a valid path from an allowed client, or a different bug in the NFS/RPC/Kerberos stack.

Residual risk remains in four buckets:

- **Patch coverage risk**: one server missed, booted into an old kernel, or loaded an old module.
- **Exposure risk**: NFS/RPC still reachable from more clients than intended, especially across VPN, CI, or engineering VLANs.
- **Adjacent protocol risk**: other bugs in NFS, RPC, XDR parsing, `kgssapi.ko`, Kerberos/GSSAPI, mountd, rpcbind, or file-locking services are not fixed by this patch.
- **Credential/client risk**: compromised engineering or CI clients can still abuse legitimate NFS access, steal data, tamper with artifacts, or attempt future server-side vulnerabilities.

To measure effectiveness over time, I would track both **state** and **behavior**:

- All six servers report the approved FreeBSD/kernel patch level.
- Running kernel matches installed kernel after every reboot.
- `kgssapi.ko` checksum/version matches the patched baseline where loaded.
- NFS/RPC ports are reachable only from approved CIDRs.
- No unauthorized RPCSEC_GSS traffic reaches the servers.
- No kernel panics, rejected malformed RPC spikes, or GSS validation errors appear after rollout.
- Synthetic Kerberos NFS read/write tests keep passing from approved clients and failing from unauthorized network segments.

Monitoring/detection I’d put in place:

- **Fleet compliance checks**: daily job collecting `freebsd-version -kru`, `uname -a`, module metadata/checksums, reboot time, and NFS service state.
- **Network validation**: scheduled scans from engineering, CI, VPN, and unauthorized test segments to verify NFS/RPC ACLs.
- **Firewall telemetry**: alerts on denied or unexpected traffic to `111`, `2049`, mountd, lockd, statd, and high RPC service ports.
- **Host telemetry**: alerts on kernel panics, crash dumps, `kgssapi`/RPCSEC_GSS errors, NFS daemon restarts, and abnormal auth failures.
- **Kerberos/NFS abuse signals**: unusual principal access, large spikes in failed GSS auth, access outside normal hours, or CI identities touching unexpected exports.
- **Integrity checks**: regular validation that exports, firewall rules, Kerberos keytabs, and service configs match the approved baseline.

I’d treat this remediation as closing one critical memory-corruption path, not as making NFS “safe.” The long-term protection comes from keeping the patch verified, keeping NFS tightly segmented, and watching for drift or weird RPC/GSS behavior before it becomes an incident.
