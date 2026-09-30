# AAC 2.0 Confirmatory Study — Benchmark Registry

**Version:** 0.1  
**Status:** Pre-freeze feasibility registry  
**Date assessed:** 2026-09-30

This registry records candidate real-world benchmark sources before the confirmatory item lists are frozen.

| Benchmark | Public repository | Current public scope | Relevance to AAC 2.0 | Practical notes | Planned role |
|---|---|---|---|---|---|
| CyberGym | `sunblaze-ucb/cybergym` | 1,507 real patched vulnerability-reproduction tasks | Strong fit for Hypothesis Engine: source inspection, competing causal hypotheses, directed reproduction tests | Dataset ~240 GB; binary-only ~130 GB; full server data can be ~10 TB; task subset workflow exists | Primary HE candidate, pending local storage/reproduction feasibility |
| CyberGym-E2E | `sunblaze-ucb/cybergym-e2e` | 920 real vulnerabilities across 139 open-source projects | Strong fit for EDR and Glasswing: discovery, PoC, patching, regression validation | Supports `e2e` and `patch-only`; firewall/network isolation built in | Preferred EDR/Glasswing substrate |
| ExploitGym | `sunblaze-ucb/exploitgym` | v1.0 canonical public list: 869 instances (paper snapshot 898) across userspace, V8 and Linux kernel | Strong external test of iterative exploit refinement/EDR | Supports task-specific image pulls; current tooling blocks provider-side external retrieval by default | Secondary EDR robustness arm if both model access policies permit |
| ExploitBench | `exploitbench/exploitbench` | 41 patched V8 environments with 16 deterministic capability flags | Direct connection to Mythos exploit-development evidence and long-horizon chaining | Pre-built images; full environment per bug is large; benchmark supports resume/audit | High-value sensitivity/construct-validity arm |
| Firefox 147 evaluation | Anthropic/Mozilla evaluation described in Mythos System Card | 50 real crash categories, 5 trials/category in Mythos evaluation | Direct historical anchor for Mythos triage and exploit refinement | Use only if reproducible public artefacts are obtainable | Optional direct-replication/sensitivity arm |
| Cybench | Public CTF benchmark | 40 challenges; Mythos card used a 35-challenge subset | General cyber capability coverage | Mythos System Card itself notes saturation/declining informativeness | Not a primary AAC confirmatory source |

## Selection Rule

The final main-study benchmark allocation is frozen only after:

1. local disk/compute feasibility is checked;
2. the exact model CLIs can be invoked inside or alongside the benchmark harness;
3. network isolation is verified;
4. task-level data can be obtained without exposing the benchmark services publicly;
5. a small non-main calibration succeeds;
6. the selected task IDs are committed before any confirmatory main run.

Selection decisions are based on reproducibility and construct fit, never on observed GPT-6 Astra or Claude Fable 5 performance.

## Current Preferred Architecture

### Experiment 1 — Hypothesis Engine
**Preferred:** CyberGym Level-1 real vulnerability-reproduction tasks.

**Feasibility fallback before freeze:** a disjoint CyberGym-E2E end-to-end task sample, with HE coding focused prospectively on the discovery/reproduction portion of each trajectory.

The fallback may be invoked only for infrastructure feasibility before any main outcome is observed.

### Experiment 2 — EDR
**Preferred:** CyberGym-E2E `patch-only` mode on a disjoint real-vulnerability sample.

Rationale:
- gives the agent a real vulnerable project, crash/PoC context and a concrete repair objective;
- patch validity is mechanically checked;
- iterative test/diagnose/revise behaviour is naturally observable without naming EDR;
- avoids making the primary study depend on whether general-access model safeguards permit exploit generation.

**Secondary robustness:** ExploitGym/ExploitBench only if both model families can legitimately run the benchmark under the available authorised access.

### Experiment 3 — Glasswing
**Preferred:** CyberGym-E2E `e2e` mode on a disjoint real-vulnerability sample.

The AAC coding extends beyond benchmark pass/fail:
- discovery/confirmation;
- remediation development;
- validation;
- propagation/hardening, operationalised as repository-wide search for homologous weakness, related call sites/configurations, and systemic hardening;
- risk-reduction measurement, operationalised as regression/security validation plus explicit residual-risk assessment.

This interpretation avoids fictitious fleet/deployment stories while retaining the five Glasswing functions.

## Model-Access Constraint

A task that one model cannot attempt because of platform policy is retained as a valid model outcome only when the refusal occurs after a protocol-valid task launch. However, a benchmark requiring capabilities that are categorically unavailable to one model family should not be selected as the sole primary test of an AAC construct.

The primary benchmark architecture therefore prioritises defensive/reproduction/patch tasks that can be presented identically to both model families.

## Version Pinning

Before freeze, record for every external benchmark:

- repository commit SHA;
- benchmark release/tag where available;
- Docker image digests;
- task-list file hash;
- local data hash;
- any local adapter patch as a separate committed diff.

Moving benchmark `main` branches are never used unpinned in the confirmatory run.
