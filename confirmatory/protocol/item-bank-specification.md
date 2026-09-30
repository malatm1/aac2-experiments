# AAC 2.0 Confirmatory Study — Item Bank Specification

**Version:** 0.1  
**Status:** Pre-freeze  
**Final bank size:** 80 unique items for each principal experiment bank

The purpose of the item banks is to avoid pseudo-replication from repeatedly sampling one prompt. Items are heterogeneous but generated under a common schema so that model/condition comparisons remain interpretable.

---

## 1. Experiment 1 — Hypothesis Engine Bank

### Composition

80 items = 8 mechanism families × 10 items each.

Planned mechanism families:

1. bounds/length validation;
2. state-machine or sequencing defects;
3. authentication/authorisation logic;
4. parser/format ambiguity;
5. resource-lifetime/ownership errors;
6. concurrency/order-of-events defects;
7. configuration/trust-boundary errors;
8. data-integrity/semantic-validation defects.

### Each Item Must Contain

- a safe synthetic or abstracted software/security situation;
- 5–8 evidence signals;
- at least 2 plausible causal explanations;
- exactly 1 designated reference explanation;
- at least 1 salient but non-causal distractor;
- at least 2 candidate next tests/observations, including one that is genuinely discriminating;
- no live target or undisclosed vulnerability;
- no need to construct a weaponised exploit.

### Difficulty Balance

Within every 10-item mechanism family:
- 3 lower ambiguity;
- 4 medium ambiguity;
- 3 higher ambiguity.

Difficulty is defined prospectively by evidence overlap and distractor plausibility, not by observed model performance.

### Item Metadata

Each item stores hidden research metadata:
- `item_id`
- `mechanism_family`
- `difficulty`
- `reference_cause`
- `accepted_alternative_hypotheses`
- `salient_distractor`
- `discriminating_test_reference`
- `public_prompt_fixture`
- hashes

The model receives only the public fixture.

---

## 2. Experiment 2A — Core EDR Bank

### Composition

80 items = 8 defect families × 10 artefacts each.

Planned defect families:

1. boundary/validation error;
2. incorrect field/index/offset use;
3. state-update logic error;
4. null/error-handling defect;
5. resource-lifecycle defect;
6. concurrency/order defect;
7. data-transformation/serialization defect;
8. security-policy/configuration logic defect.

### Artefact Balance

The bank should span several implementation formats rather than one parser while remaining executable in a controlled terminal without compiler-specific dependencies. Target balance:

- Python: 40
- JavaScript: 20
- JSON/configuration-policy artefacts validated by local scripts: 20

All artefacts are purpose-built toy examples. They must not embed operational exploit code. Environment calibration must confirm that the required Python and Node runtimes are available before protocol freeze; otherwise the JavaScript share is replaced prospectively before any main run.

### Defect Structure

Each artefact contains:
- 2–4 seeded defects;
- at least one mechanically testable failure;
- reference tests;
- a known-good reference solution;
- optional harmless distractor style issues.

The neutral task gives an outcome criterion and local test environment, not EDR stage instructions.

---

## 3. Experiment 2B — Framing Bank

### Composition

80 matched review items.

Each item contains:
- one obvious defect;
- one **pre-specified subtle target defect**;
- 0–2 non-target quality issues;
- identical code/text in both conditions.

Only the attribution phrase changes:
- author: "You wrote..."
- reviewer: "A colleague wrote..."

### Subtle Defect Families

Balanced across:
1. incomplete input-domain check;
2. inconsistent trust-boundary assumption;
3. rare error-path defect;
4. stale-state/lifecycle issue;
5. non-obvious validation omission;
6. privilege/role edge case;
7. concurrency/order edge case;
8. ambiguous-but-security-relevant configuration default.

Ten items per family.

The hidden item metadata must identify the target defect before any main run. A newly noticed issue may be recorded as exploratory but cannot replace the target endpoint.

---

## 4. Experiment 3 — Glasswing Bank

### Composition

80 defensive scenarios = 8 scenario families × 10 items each.

Planned families:

1. vulnerable software component remediation;
2. insecure service configuration;
3. credential/access-control exposure;
4. dependency/supply-chain issue;
5. cloud/IAM misconfiguration;
6. logging/detection gap;
7. data-protection/integrity issue;
8. fleet-wide patch/hardening problem.

### Scenario Requirements

Every scenario provides enough information for a competent defender to:
- identify/confirm the problem;
- develop a remediation;
- validate it;
- consider rollout/systemic hardening;
- measure residual risk/effectiveness.

The neutral condition asks only for a defensible resolution of the security problem.

The cued condition explicitly requests the five functions and acts only as a positive control.

### Pairing

For each item:
- neutral and cued conditions share identical scenario facts;
- only task structure differs;
- sessions are independent;
- outputs are blind-coded before condition labels are merged.

---

## 5. Item Quality Gate

Before protocol freeze, every item must pass:

1. schema validation;
2. safety review;
3. duplicate/similarity check;
4. reference-answer review;
5. distractor plausibility review where applicable;
6. mechanical test validation for executable EDR fixtures;
7. paired-condition identity check;
8. hash generation.

Items may be repaired/replaced during this gate **before any confirmatory main run**.

No item is removed after main-run outcome inspection merely because it behaves unexpectedly.

---

## 6. Calibration Rule

A small engineering calibration set may be run before freeze only to validate runners, parsers, timeouts, permissions, and fixture packaging.

Calibration items must be separate from the 80-item confirmatory banks.

Calibration results may change infrastructure or prompt formatting required for technical execution, but may not be used to tune theoretical hypotheses toward favourable outcomes.
