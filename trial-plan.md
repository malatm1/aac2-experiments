# Trial Plan

**Paper:** *AAC 2.0: Validating and Extending the Autonomous Attack Chain Framework with Frontier Capabilities from Claude Mythos Preview*

**Authors:** M. Malatji and A. Tolah

---

## Overview

This document specifies the complete trial plan for the three experiments. Each trial is run in a fresh session with no prior context. All traces are deposited in the `traces/` directory following the naming convention `trial-01.md`, `trial-02.md`, etc.

## Trial Plan

| Experiment | Prompt | Model | Trials | Session Type | Trace Location |
|---|---|---|---|---|---|
| Exp 1 — Hypothesis Engine | Triage + Hypothesis + Testing Plan | Claude Opus 4.7 (Claude Code) | 5 | Fresh session per trial | `traces/experiment1/claude-code/` |
| Exp 1 — Hypothesis Engine | Triage + Hypothesis + Testing Plan | GPT-5.5 TAC (Codex) | 5 | Fresh session per trial | `traces/experiment1/gpt55-tac/` |
| Exp 2 — EDR Loop (Stage 1+2) | Iterative Correction → Auditor Probe | Claude Opus 4.7 (Claude Code) | 5 | Same session for both stages | `traces/experiment2/claude-code/` |
| Exp 2 — EDR Loop (Stage 1+2) | Iterative Correction → Auditor Probe | GPT-5.5 TAC (Codex) | 5 | Same session for both stages | `traces/experiment2/gpt55-tac/` |
| Exp 2 — Framing Probe (Author) | "Your code" framing | Claude Opus 4.7 (Claude Code) | 5 | Fresh session per trial | `traces/experiment2/claude-code/` |
| Exp 2 — Framing Probe (Author) | "Your code" framing | GPT-5.5 TAC (Codex) | 5 | Fresh session per trial | `traces/experiment2/gpt55-tac/` |
| Exp 2 — Framing Probe (Reviewer) | "Colleague's code" framing | Claude Opus 4.7 (Claude Code) | 5 | Fresh session per trial | `traces/experiment2/claude-code/` |
| Exp 2 — Framing Probe (Reviewer) | "Colleague's code" framing | GPT-5.5 TAC (Codex) | 5 | Fresh session per trial | `traces/experiment2/gpt55-tac/` |
| Exp 3 — Glasswing AAC | Defensive Cycle → Risk Reduction | Claude Opus 4.7 (Claude Code) | 5 | Same session for both prompts | `traces/experiment3/claude-code/` |
| Exp 3 — Glasswing AAC | Defensive Cycle → Risk Reduction | GPT-5.5 TAC (Codex) | 5 | Same session for both prompts | `traces/experiment3/gpt55-tac/` |
| | | | **Total: 50 traces** | | |

## File Naming Convention

Traces are named by trial type and number:

| Experiment | File Pattern | Example |
|---|---|---|
| Exp 1 | `trial-01.md` to `trial-05.md` | `traces/experiment1/claude-code/trial-01.md` |
| Exp 2 — Stage 1+2 | `trial-stage12-01.md` to `trial-stage12-05.md` | `traces/experiment2/gpt55-tac/trial-stage12-01.md` |
| Exp 2 — Author framing | `trial-author-01.md` to `trial-author-05.md` | `traces/experiment2/claude-code/trial-author-01.md` |
| Exp 2 — Reviewer framing | `trial-reviewer-01.md` to `trial-reviewer-05.md` | `traces/experiment2/claude-code/trial-reviewer-01.md` |
| Exp 3 | `trial-01.md` to `trial-05.md` | `traces/experiment3/gpt55-tac/trial-01.md` |

## What to Capture in Each Trace

Each trace file should contain the complete interaction for that trial:

1. The exact prompt given to the model (copy from the `prompts/` directory)
2. The model's full response, including any reasoning, code output, and terminal commands executed
3. Any follow-up prompts and the model's responses (for multi-turn trials like Exp 2 Stage 1+2)
4. The model name and environment (Claude Code or Codex) noted at the top of the file

Raw transcripts are sufficient. Formatting is not required. The qualitative coding step (using `coding/rubric.md`) is where structured analysis occurs.

## Key Rules

- **Fresh session:** Every trial starts in a new session with no prior context, except where noted (Exp 2 Stage 2 follows Stage 1 in the same session; Exp 3 Risk Reduction follows the Defensive Cycle in the same session).
- **No hints:** Do not tell the model how many errors exist (Exp 2), do not suggest an analytical method (Exp 1), and do not instruct the model to conceal anything (Exp 2 Stage 2).
- **Identical prompts:** Use the exact prompts from the `prompts/` directory. Do not modify prompts between trials.
