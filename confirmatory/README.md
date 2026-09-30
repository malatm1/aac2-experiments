# AAC 2.0 Confirmatory Study (v2)

This directory contains the redesigned confirmatory study for AAC 2.0.

The original artefacts on `main` are retained as the pilot archive and are not pooled with the confirmatory dataset.

## Systems

The planned model families are:

- GPT-6 Astra via Codex
- Claude Fable 5 via Claude Code

The human-readable product names above are not treated as sufficient provenance. Every run must record the exact runtime model identifier returned by the client, execution date/time, client version, tool permissions, context/session state, and any controllable inference settings.

## Design Principles

1. **Prospective specification.** Hypotheses, coding rules, exclusion rules, stopping rules, and analysis procedures are specified before the main run.
2. **No pseudo-replication by prompt repetition.** The main study uses banks of unique matched items rather than repeatedly sampling one prompt.
3. **Neutral prompts for emergence claims.** AAC 2.0 terminology is withheld from neutral conditions. Cued conditions are used only as positive controls where theoretically useful.
4. **Matched information environments.** Browsing and uncontrolled external retrieval are disabled. Models receive the same task artefacts and materially equivalent tool affordances wherever the platforms allow.
5. **Isolated runs.** Main-run observations begin in fresh sessions with no cross-run memory or prior task context, except where within-run continuation is an explicit manipulated feature.
6. **Observable behaviour only.** Outputs are described as agent/interaction trajectories, not as privileged access to internal chain-of-thought.
7. **Blinded human coding.** Model and condition identifiers are removed from coding packets wherever technically possible.
8. **Pilot separation.** The original 50 traces are used only to inform design and operationalisation. They are never added to the confirmatory sample.
9. **Machine-enforced protocol.** Run manifests, stopping rules, validation checks, retry rules, and completeness checks are enforced by scripts rather than researcher discretion during execution.
10. **Immutable raw data.** Raw model outputs are never overwritten. Corrections or recodings create new derived artefacts.

## Planned Experiments

### Experiment 1 — Hypothesis Engine
Tests whether a Signal Ingestion → Hypothesis Formation → Directed Testing structure emerges from neutral vulnerability-analysis tasks without naming or instructing that sequence.

### Experiment 2 — Evaluate–Diagnose–Revise (EDR)
Tests whether iterative Evaluate → Diagnose → Revise cycles emerge from outcome-oriented debugging/repair tasks without instructing the EDR stages. A separate pre-specified framing experiment tests author-versus-reviewer attribution effects.

### Experiment 3 — Glasswing AAC
Tests whether the proposed defensive cycle emerges under a minimally structured defensive objective. A phase-cued condition serves as a positive-control comparison and is not interpreted as evidence of independent emergence.

## Status

Protocol design is being frozen before runner construction. No confirmatory main-run observations may be generated until the protocol-freeze gate is satisfied.
