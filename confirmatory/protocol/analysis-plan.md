# AAC 2.0 Confirmatory Study — Statistical Analysis Plan

**Version:** 0.1  
**Status:** Pre-run

## 1. General Principles

The confirmatory analysis is item-based, not based on treating repeated generations of one prompt as independent evidence.

The original 50-run pilot dataset is excluded from confirmatory hypothesis tests.

All primary analyses will be scripted and committed before unblinded confirmatory coding is merged with model/condition metadata.

Effect estimates and uncertainty intervals are reported alongside p-values. Statistical significance alone is not treated as evidence of theoretical importance.

## 2. Planned Sample Structure

The target item-bank size is 40 unique items per experiment bank, pending a pre-run power/sensitivity analysis.

Expected main-run structure if 40 items are retained:

- Experiment 1: 40 items × 2 models = 80 trajectories
- Experiment 2 core EDR: 40 items × 2 models = 80 trajectories
- Experiment 2 framing: 40 items × 2 framings × 2 models = 160 trajectories
- Experiment 3 Glasswing: 40 items × 2 conditions × 2 models = 160 trajectories

**Planned total: 480 confirmatory trajectories.**

This count may change only before the protocol-freeze tag and only on the basis of the committed power/sensitivity analysis or item-quality screening performed without confirmatory outcome inspection.

## 3. Experiment 1 — Hypothesis Engine

### Primary endpoint
Binary complete spontaneous HE traversal.

### Primary reporting
For each model and pooled across models:

- proportion complete;
- 95% Wilson confidence interval;
- item-level distribution.

### Model comparison
A mixed-effects logistic regression is planned where estimable:

`complete_HE ~ model + (1 | item)`

If model fitting is unstable or inappropriate, report paired item-level contrasts using an exact/permutation alternative.

### Secondary outcomes
Ordinal or count outcomes will use mixed-effects ordinal/count models where assumptions are adequate; otherwise paired non-parametric/permutation analyses.

The theory does not require one model to outperform the other. Model differences are secondary unless explicitly pre-specified before freeze.

## 4. Experiment 2 — Core EDR

### Primary endpoint
Binary indicator: at least one complete spontaneous EDR cycle.

### Primary reporting
- model-specific proportions and 95% CIs;
- pooled proportion with item-level clustering respected.

### Secondary endpoints
- number of complete cycles;
- seeded-defect recall;
- repair correctness;
- regressions introduced;
- tool-call/runtime efficiency.

A mixed-effects model with item as a random intercept will be used where appropriate.

## 5. Experiment 2 — Framing

### Primary endpoint
Detection of the pre-specified subtle defect.

Because every item appears in both framing conditions for each model, the principal contrast is paired within item.

Planned analyses:

- condition-specific proportions;
- absolute risk difference with confidence interval;
- odds ratio where estimable;
- McNemar's exact test for paired binary author-versus-reviewer outcomes;
- mixed-effects logistic regression:
  `detected ~ framing * model + (1 | item)`

Fisher's exact test may be reported as a sensitivity analysis for comparability with the pilot literature/reviewer suggestion, but the paired structure makes McNemar/mixed modelling the primary approach.

### Construct separation
Audience awareness, framing sensitivity, and concealment are analysed separately. No statistical association involving framing is interpreted as deception or concealment without the dedicated concealment code being positive.

## 6. Experiment 3 — Glasswing

### Primary endpoint
Complete five-function traversal in the neutral condition.

### Positive-control comparison
Neutral versus cued traversal is compared within item and model.

Planned model:

`complete_traversal ~ condition * model + (1 | item)`

with paired exact/permutation alternatives if mixed-model assumptions fail.

### Interpretation
- high cued traversal + low neutral traversal: structural compatibility but weak evidence of independent emergence;
- high neutral traversal: support for spontaneous defensive-cycle emergence;
- substantial model interaction: evidence that the framework's behavioural manifestation differs by model family.

## 7. Inter-Coder Reliability

Reliability is calculated **before reconciliation** using the two independent human code files.

For binary primary outcomes:
- Cohen's kappa;
- raw percent agreement;
- positive and negative agreement where useful.

For ordinal outcomes:
- weighted kappa.

For continuous/count annotations:
- ICC or an appropriate agreement statistic where justified.

Report:
- coefficient;
- confidence interval where feasible;
- number of disagreements;
- number/proportion of reconciled changes;
- coder membership/authorship status;
- whether coders were blinded to model and condition.

Reliability values are not interpreted solely through categorical labels such as "substantial"; numerical values and uncertainty are reported.

## 8. Missingness and Failed Runs

Protocol-valid refusals or incomplete task performance are outcomes, not missing data.

Only runs meeting a pre-specified technical exclusion rule are treated as missing/invalid.

All exclusions and retries are reported in a CONSORT-style run-flow table adapted for model experiments.

## 9. Multiplicity

Primary endpoints are limited to one per principal hypothesis.

Secondary outcomes are labelled secondary/exploratory. Where a family of secondary hypothesis tests is interpreted jointly, false-discovery-rate control will be applied.

## 10. Robustness / Sensitivity Analyses

Planned sensitivity checks include:

- excluding any item with coder disagreement on the primary endpoint before reconciliation;
- analysing models separately;
- including/excluding protocol-valid refusals as failures for traversal endpoints;
- comparing human-coded outcomes with mechanically derived indicators where available;
- checking whether results are driven by a small subset of item classes.

## 11. Reporting Language

The following wording rules are pre-specified:

- use **supported** / **not supported** rather than **confirmed** / **proved**;
- use **evaluated** / **stress-tested** rather than **validated** when evidence is indirect or documentary;
- use **observed agent trajectory** rather than **internal reasoning trace**;
- distinguish **structural compatibility** from **independent emergence**;
- avoid claiming cognitive equivalence across model families solely from similar endpoint scores.
