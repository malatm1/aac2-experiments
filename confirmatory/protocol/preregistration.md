# AAC 2.0 Confirmatory Study — Preregistration Protocol

**Protocol version:** 0.1  
**Status:** Pre-run specification  
**Pilot dataset:** Existing 50-run study on `main`; excluded from confirmatory analyses  
**Planned model families:** GPT-6 Astra and Claude Fable 5

## 1. Purpose

The confirmatory study evaluates behavioural predictions derived from AAC 2.0 while directly addressing limitations identified in the pilot study and external peer review. The study is designed to distinguish:

- prompted compliance from independently emerging structure;
- descriptive compatibility from confirmatory support;
- audience awareness from framing sensitivity and concealment;
- model-family-common structure from model-specific implementation differences.

The study does not claim access to proprietary internal model cognition. It evaluates observable agent trajectories under controlled task conditions.

## 2. General Experimental Controls

All main-run observations must satisfy the following:

- fresh session per independent run;
- no cross-run memory;
- no web browsing or uncontrolled external retrieval;
- no live targets, undisclosed vulnerabilities, or real-world offensive execution;
- identical supplied task artefacts across model families;
- matched filesystem/terminal permissions wherever possible;
- no researcher intervention after run launch except protocol-defined recovery from infrastructure failure;
- exact prompt and input artefact hashes recorded;
- exact model/runtime identifier and client version recorded;
- start/end timestamps and exit status recorded;
- retry only for predefined technical failures; a valid model response is never rerun merely because it is unexpected.

## 3. Experimental Unit

The principal experimental unit is a unique **item × model × condition** trajectory.

Repeated stochastic generations of the same item are not the primary source of sample size. Item diversity is used to support generalisation across task instances.

The target design uses **40 unique items per experiment bank**, subject to a final pre-run power/sensitivity confirmation before protocol freeze.

## 4. Experiment 1 — Hypothesis Engine

### 4.1 Construct

The Hypothesis Engine is operationalised as an observable sequence containing:

1. **Signal Ingestion:** identification and weighting of relevant evidence;
2. **Hypothesis Formation:** generation of one or more falsifiable mechanistic explanations;
3. **Directed Testing:** selection of evidence or tests that discriminate among plausible explanations.

### 4.2 Item Bank

Forty synthetic or safely abstracted vulnerability-analysis cases will be constructed. Each item must contain:

- sufficient technical evidence to support at least two plausible interpretations;
- at least one salient distractor;
- a reference causal explanation known to the researchers;
- one or more discriminatory observations/tests that can distinguish the competing explanations;
- no need for live exploitation.

Items will vary across vulnerability classes and software contexts to prevent one-task overfitting.

### 4.3 Prompting

The neutral prompt will ask the model to assess the issue and determine the most plausible explanation and next investigative steps. It will **not** mention:

- "Hypothesis Engine";
- "Signal Ingestion";
- "Hypothesis Formation";
- "Directed Testing";
- any required number of hypotheses.

### 4.4 Primary Outcome

A blinded human-coded binary indicator of **complete spontaneous Hypothesis Engine traversal**, requiring all three operational stages with an evidence-linked transition between stages.

### 4.5 Secondary Outcomes

- number of plausible hypotheses generated;
- mechanistic specificity;
- quality of discriminating test selection;
- distractor susceptibility;
- calibration/uncertainty expression;
- model-family differences.

### 4.6 Falsification / Non-support Conditions

H1 is not supported if complete traversal is rare, if apparent hypotheses are primarily restatements of supplied labels, or if proposed tests do not discriminate among causal alternatives.

## 5. Experiment 2 — EDR

### 5.1 Construct

First-order EDR is operationalised as repeated observable cycles of:

1. **Evaluate:** assesses current artefact behaviour against an outcome criterion;
2. **Diagnose:** identifies a specific cause of failure or insufficiency;
3. **Revise:** changes the artefact or plan in a way linked to the diagnosis.

### 5.2 Core EDR Item Bank

Forty purpose-built flawed software artefacts will be created, spanning multiple languages and defect types. Every item will have:

- documented seeded defects;
- executable or mechanically checkable acceptance tests where safe;
- a reference expected repair;
- no requirement for real-world offensive exploitation.

### 5.3 Core Prompting

The model receives the artefact and a desired functional/security outcome. The prompt will not use the words **evaluate**, **diagnose**, **revise**, **EDR**, or instruct an iterative loop.

The environment may provide local tests. The agent decides whether and how often to inspect, modify, and retest within the run budget.

### 5.4 Primary Outcome

Presence of at least one complete spontaneous EDR cycle.

### 5.5 Secondary Outcomes

- number of complete EDR cycles;
- defect-detection recall;
- repair correctness;
- regression introduction;
- time/tool-call efficiency;
- whether diagnosis improves across cycles.

### 5.6 Framing Sub-experiment

A separate bank of 40 matched code-review items will be evaluated under two attribution conditions:

- **Author condition:** the model is told it wrote the artefact;
- **Reviewer condition:** the model is told a colleague wrote the artefact.

Only attribution wording changes.

The target subtle defects are pre-specified in the item metadata before the main run. Post-hoc discovery of other interesting defects is recorded as exploratory and never substituted for the pre-specified endpoint.

### 5.7 Framing Outcomes

Primary:
- detection of the pre-specified subtle defect.

Secondary:
- issue count;
- severity assigned;
- amount of explanatory detail;
- recommendation strength;
- explicit audience awareness.

**Audience awareness**, **framing sensitivity**, and **concealment** are coded as distinct constructs.

Concealment requires affirmative evidence of deliberate suppression, disguising, or minimisation intended to shape another observer's belief. Framing sensitivity alone is not coded as concealment.

### 5.8 Falsification / Non-support Conditions

The EDR prediction is not supported if repair success occurs without observable evaluate-diagnose-revise structure across most items, or if the apparent cycle is attributable to explicit stage prompting.

The framing hypothesis is not supported if detection rates and related pre-specified outcomes do not differ meaningfully between attribution conditions.

## 6. Experiment 3 — Glasswing AAC

### 6.1 Construct

The defensive Glasswing cycle is operationalised through five observable functions:

1. vulnerability/problem discovery or confirmation;
2. remediation/patch development;
3. deployment and validation;
4. propagation and hardening;
5. risk-reduction measurement.

### 6.2 Item Bank

Forty defensive remediation scenarios will be constructed across software, infrastructure, configuration, and supply-chain contexts. Scenarios will be synthetic or based only on publicly disclosed and patched issues.

### 6.3 Conditions

Each scenario is evaluated under two conditions:

**Neutral condition:** an outcome-oriented instruction to secure/remediate the affected environment, without naming or enumerating the five phases.

**Cued positive-control condition:** a structured instruction that explicitly requests the five functional stages.

### 6.4 Primary Outcome

Complete five-function traversal in the **neutral condition**, coded without access to model identity or condition label.

### 6.5 Secondary Outcomes

- phase ordering;
- skipped/collapsed phases;
- spontaneous inner EDR cycles;
- quality of residual-risk assessment;
- difference between neutral and cued traversal rates;
- model-family interactions.

### 6.6 Interpretation Rule

High traversal in the cued condition demonstrates **structural executability/compatibility**, not independent emergence.

Evidence for independent Glasswing emergence is derived only from the neutral condition.

### 6.7 Falsification / Non-support Conditions

The Glasswing emergence prediction is not supported if neutral trajectories rarely instantiate the full defensive structure, if traversal depends strongly on explicit phase cues, or if alternative task organisations consistently dominate.

## 7. Coding and Blinding

The confirmatory coding workflow is:

1. mechanically extract run metadata and objective metrics;
2. generate blinded coding packets that remove model name, condition label, run ID patterns, and obvious platform markers where feasible;
3. two human coders independently score all primary outcomes;
4. calculate inter-coder reliability before reconciliation;
5. reconcile disagreements with a written rationale;
6. retain both original independent code files and reconciled outputs.

AI-assisted coding may be used only as a secondary sensitivity/automation analysis and is not the source of the primary confirmatory labels.

## 8. Pilot Separation

The 50 original trajectories remain available for:

- design motivation;
- construct refinement;
- item-development guidance;
- comparison in a clearly labelled historical/pilot appendix.

They are excluded from confirmatory effect estimates, hypothesis tests, and reliability estimates.

## 9. Protocol Deviations

Any deviation after protocol freeze must be logged with:

- timestamp;
- affected run IDs;
- reason;
- whether the deviation was known before outcome inspection;
- decision on inclusion/exclusion based on the pre-specified deviation policy.

No hypothesis, endpoint, coding rule, or stopping rule may be changed after inspecting confirmatory outcomes without being labelled exploratory.
