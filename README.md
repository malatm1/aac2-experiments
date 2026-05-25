# AAC 2.0 — Experimental Artefacts

**Paper:** *AAC 2.0: Validating and Extending the Autonomous Attack Chain Framework with Frontier Capabilities from Claude Mythos Preview*

**Authors:** M. Malatji and [A. Tolah]

**Malatji Affiliation:** Graduate School of Business Leadership, University of South Africa
**Tolah Affiliation:** College of Computing and Informatics, Saudi Electronic University 

**Target venue:** IEEE ISI 2026 / ICAIC 2026

---

## Overview

This repository contains the complete experimental artefacts for the AAC 2.0 paper. It is designed to support full independent replication of the three proxy benchmark experiments described in Section V of the paper.

The experiments test three extensions to the Autonomous Attack Chain (AAC) framework:

| Experiment | AAC 2.0 Extension | What It Tests |
|---|---|---|
| **Experiment 1** | Hypothesis Engine | Hypothesis-driven vulnerability prioritisation from publicly disclosed crash data |
| **Experiment 2** | EDR Loop | Iterative self-diagnosis (first-order) and concealment reasoning (second-order) in code correction |
| **Experiment 3** | Glasswing AAC | Defensive inversion — whether the offensive cognitive cycle transfers to patching and hardening |

All experiments use two models:
- **Claude Opus 4.7** via Claude Code
- **GPT-5.5 with Trusted Access for Cyber (TAC)** via Codex

No experiment involves live exploitation. All vulnerability data is drawn from publicly available, already-disclosed and patched sources.

---

## Repository Structure

```
aac2-experiments/
├── prompts/                        # Exact prompts for each experiment
│   ├── experiment1-hypothesis-engine/
│   ├── experiment2-edr-loop/
│   └── experiment3-glasswing-aac/
├── datasets/                       # Input data (curated CVEs, code samples)
│   └── code-samples/
├── traces/                         # Raw reasoning traces, per experiment/model/trial
│   ├── experiment1/
│   │   ├── claude-code/
│   │   └── gpt55-tac/
│   ├── experiment2/
│   │   ├── claude-code/
│   │   └── gpt55-tac/
│   └── experiment3/
│       ├── claude-code/
│       └── gpt55-tac/
├── coding/                         # Qualitative coding rubric, coded data, inter-coder reliability
│   ├── coded-data/
│   └── intercoder-reliability/
└── analysis/                       # Summary analysis and figures for the paper
    └── figures/
```

---

## How to Replicate

### Prerequisites

- A Claude Pro subscription with access to Claude Code
- OpenAI GPT-5.5 with Trusted Access for Cyber (TAC) via Codex (requires verified researcher access)

### Steps

1. **Review the prompts** in `prompts/` for the experiment you wish to replicate.
2. **Prepare the input data** from `datasets/`. The curated vulnerability set and code samples are provided as-is.
3. **Run each trial** in a fresh session (no prior context). For Claude Code, start a new Claude Code session. For GPT-5.5 TAC via Codex, start a new Codex session.
4. **Capture the full trace**, including any extended thinking, terminal commands, code execution outputs, and the model's final response. Save as a markdown file in the corresponding `traces/` subdirectory.
5. **Code each trace** against the rubric in `coding/rubric.md` and record results in the corresponding CSV file in `coding/coded-data/`.

### Number of Trials

Each experiment is run with multiple independent trials per model. The exact number of trials is documented in the paper's Section V.

---

## Ethical Statement

These experiments test cognitive patterns (hypothesis formation, self-diagnosis, audience-aware reasoning, defensive-cycle traversal) rather than operational offensive capability. No experiment involves live exploitation, real targets, or undisclosed vulnerabilities. The second-order EDR probe observes naturally emerging reasoning in a standard professional context (code auditor review) and does not instruct the model to conceal, obfuscate, or deceive. See Section V-F of the paper for the full ethical discussion.

---

## Licence

- **Code** (prompts, scripts, analysis tools): [MIT License](LICENSE-MIT)
- **Data and text** (traces, coded datasets, rubric, documentation): [CC BY 4.0](LICENSE-CC-BY-4.0)

---

## Citation

If you use these artefacts in your research, please cite:

```bibtex
@inproceedings{malatji2026aac2,
  title     = {{AAC} 2.0: Validating and Extending the Autonomous Attack Chain Framework with Frontier Capabilities from Claude Mythos Preview},
  author    = {Malatji, Masike and Tolah, Alaa},
  booktitle = {Proceedings of the IEEE International Conference on [TBC]},
  year      = {2026}
}
```
