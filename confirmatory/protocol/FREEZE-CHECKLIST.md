# Confirmatory v2 — Protocol Freeze Checklist

The confirmatory main run is prohibited until every **REQUIRED** item is complete.

## A. Theory and Hypotheses

- [x] REQUIRED — H1 Hypothesis Engine prospectively specified
- [x] REQUIRED — H2 EDR prospectively specified
- [x] REQUIRED — H3 framing prospectively specified
- [x] REQUIRED — H4 Glasswing prospectively specified
- [x] REQUIRED — non-support/falsification conditions defined
- [x] REQUIRED — audience awareness, framing sensitivity, and concealment separated

## B. Sample and Analysis

- [x] REQUIRED — sample-size sensitivity analysis committed
- [x] REQUIRED — final target set to 80 unique items per bank
- [x] REQUIRED — confirmatory analysis plan committed
- [x] REQUIRED — pilot excluded from confirmatory estimates

## C. Benchmark Feasibility and Pinning

- [ ] REQUIRED — local disk/compute feasibility recorded
- [ ] REQUIRED — CyberGym feasibility decision recorded
- [ ] REQUIRED — CyberGym-E2E feasibility decision recorded
- [ ] REQUIRED — optional ExploitGym/ExploitBench access decision recorded
- [ ] REQUIRED — selected benchmark repositories pinned to commit SHAs
- [ ] REQUIRED — selected Docker images pinned to digests
- [ ] REQUIRED — task-list files and local datasets hashed
- [ ] REQUIRED — model CLI integration verified in isolated benchmark environment
- [ ] REQUIRED — benchmark network isolation verified

## D. Item Banks

- [ ] REQUIRED — 80-item Hypothesis Engine bank complete
- [ ] REQUIRED — 80-item core EDR bank complete
- [ ] REQUIRED — 80-item framing bank complete
- [ ] REQUIRED — 80-item Glasswing bank complete
- [ ] REQUIRED — all reference answers/hidden metadata complete
- [ ] REQUIRED — duplicate/similarity audit passed
- [ ] REQUIRED — safety review passed
- [ ] REQUIRED — executable EDR fixtures pass reference tests
- [ ] REQUIRED — paired framing fixtures differ only in attribution wording
- [ ] REQUIRED — paired Glasswing fixtures differ only in task structure

## E. Coding

- [x] REQUIRED — coding rubric v2 committed
- [ ] REQUIRED — blank independent Coder A sheet generated
- [ ] REQUIRED — blank independent Coder B sheet generated
- [ ] REQUIRED — reconciliation schema generated
- [ ] REQUIRED — blinding transformation tested
- [ ] REQUIRED — reliability script validated on synthetic labels

## F. Execution

- [x] REQUIRED — stopping/retry policy committed
- [x] REQUIRED — run metadata schema committed
- [ ] REQUIRED — exact available GPT-6 Astra runtime identifier captured
- [ ] REQUIRED — exact available Claude Fable 5 runtime identifier captured
- [ ] REQUIRED — Codex client version captured
- [ ] REQUIRED — Claude Code client version captured
- [ ] REQUIRED — tool-permission equivalence documented
- [ ] REQUIRED — model-specific runners implemented
- [ ] REQUIRED — schedule/orchestrator implemented
- [ ] REQUIRED — validator implemented
- [ ] REQUIRED — resumability tested
- [ ] REQUIRED — forbidden browsing/external retrieval guard tested
- [ ] REQUIRED — calibration set completed without protocol-level theory changes

## G. Reproducibility

- [ ] REQUIRED — run schedule generated
- [ ] REQUIRED — input hashes generated
- [ ] REQUIRED — environment snapshot generated
- [ ] REQUIRED — analysis scripts committed
- [ ] REQUIRED — protocol deviation log created
- [ ] REQUIRED — protocol freeze commit recorded
- [ ] REQUIRED — immutable protocol freeze tag created

## Freeze Rule

After the freeze tag:

- hypotheses cannot be changed;
- primary endpoints cannot be changed;
- sample size cannot be changed in response to results;
- exclusion/stopping rules cannot be changed;
- item answers cannot be revised after viewing model outputs;
- deviations must be logged and labelled.

Calibration may identify implementation defects, but any protocol-level change after calibration requires a new pre-run protocol version and a new freeze candidate before the main run starts.
