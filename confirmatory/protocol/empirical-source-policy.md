# AAC 2.0 Confirmatory Study — Empirical Source Policy

**Version:** 0.2  
**Status:** Pre-freeze

## Principle

The confirmatory study is anchored in real, publicly documented cybersecurity benchmark tasks and patched vulnerabilities that are directly connected to the evaluation ecology used for Claude Mythos Preview.

Synthetic or fictitious cyber scenarios are **not** the primary confirmatory evidence.

Synthetic material may be used only for:

- runner calibration;
- parser/unit testing;
- blinding-pipeline testing;
- statistical-code validation;
- explicitly labelled robustness analyses.

Synthetic calibration results are excluded from the confirmatory dataset.

## Source Hierarchy

Preference is given in this order:

1. **Public benchmark instances used in or directly adjacent to Mythos Preview evaluation**
   - CyberGym targeted vulnerability-detection/reproduction tasks;
   - ExploitBench;
   - ExploitGym;
   - public Firefox/SpiderMonkey evaluation artefacts where reproducibly available;
   - public Cybench tasks only where they remain informative.

2. **Publicly disclosed and patched Project Glasswing / Mythos vulnerabilities**
   - only after disclosure and patch availability;
   - only where the relevant source/patch/test artefacts can be reproduced safely.

3. **Other public, patched real-world CVEs**
   - used only to fill pre-specified strata not adequately represented by the Mythos-linked sources;
   - provenance and fixed-commit references must be recorded.

## Reproducibility Requirement

A task may enter the confirmatory item bank only if the researchers can record:

- benchmark/task identifier or CVE/GHSA;
- upstream project/repository;
- vulnerable revision or container image;
- fixed revision/patch where applicable;
- deterministic or mechanically checkable success criterion where available;
- benchmark provenance;
- licence/redistribution status;
- local input hash.

Unpatched, embargoed, or undisclosed vulnerabilities are excluded.

## Safety and Isolation

All executable tasks run in isolated local containers or benchmark sandboxes with no internet access and no real production targets.

Publicly patched exploitation benchmarks may be used only inside their intended reproducible benchmark environments. No generated exploit artefact is directed at a live system.

## Relation to Mythos Preview

The source choice is intended to reduce the inferential gap between:

1. documentary claims about Mythos Preview;
2. the constructs derived in AAC 2.0; and
3. direct testing of GPT-6 Astra and Claude Fable 5.

The study will not claim that the new systems are exact substitutes for Mythos Preview. Instead, it tests whether the AAC 2.0 behavioural structures are observable on the same or closely related classes of real cyber tasks used to establish Mythos-level capability.

## Benchmark Facts Motivating the Design

The Mythos Preview evaluation programme reports:

- CyberGym targeted vulnerability evaluation on a large public task suite;
- a Firefox 147 evaluation built from 50 real crash categories, with repeated trials and a containerised SpiderMonkey harness;
- real open-source vulnerability discovery in isolated source-code environments;
- subsequent evaluation on ExploitBench and ExploitGym, both based on real patched vulnerability instances.

These facts motivate use of real benchmark environments rather than invented cyber vignettes.

## Dataset Separation

Where the same upstream benchmark supplies tasks to more than one AAC experiment, item IDs must be disjoint across confirmatory experiments unless a deliberately paired cross-experiment design is specified before freeze.

No item may be selected because a pilot model happened to perform well on it.
