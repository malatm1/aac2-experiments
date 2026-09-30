# Pre-Run Power and Sensitivity Analysis

**Protocol version:** 0.1  
**Status:** Pre-freeze design decision

## Purpose

The original pilot used five trials per model/condition. The confirmatory study instead uses heterogeneous item banks and selects sample size prospectively.

Because the study contains both prevalence-style hypotheses (e.g., spontaneous structure is commonly observed) and paired-condition hypotheses (e.g., author vs reviewer; neutral vs cued), sample size was assessed against both types.

## 1. Prevalence-Style Sensitivity

For a one-sided exact binomial test of:

- null prevalence: p = 0.50
- alpha = 0.05

the approximate powers are:

| Items per model | True p=.65 | True p=.70 | True p=.75 | True p=.80 |
|---:|---:|---:|---:|---:|
| 40 | .572 | .807 | .946 | .992 |
| 50 | .622 | .859 | .971 | .997 |
| 60 | .753 | .937 | .993 | ~1.000 |
| 64 | .712 | .924 | .991 | ~1.000 |
| 80 | .854 | .979 | .999 | ~1.000 |

The non-monotonicity in the .65 column at some sample sizes reflects the discreteness of the exact binomial critical value.

## 2. Paired Binary Sensitivity

The framing and Glasswing condition contrasts are paired within item. Approximate two-sided McNemar power (alpha = .05) was examined under several plausible discordant-pair structures.

| Items | 20pp effect, discord=.40 | 20pp effect, discord=.35 | 20pp effect, discord=.30 | 25pp effect, discord=.35 | 25pp effect, discord=.45 |
|---:|---:|---:|---:|---:|---:|
| 40 | .559 | .622 | .699 | .839 | .719 |
| 50 | .654 | .719 | .792 | .909 | .811 |
| 60 | .733 | .795 | .860 | .951 | .875 |
| 64 | .760 | .820 | .881 | .962 | .895 |
| 80 | .846 | .895 | .939 | .986 | .949 |

The 80-item design is therefore preferred because it retains at least roughly .85 power for a 20 percentage-point paired difference even under the more conservative discordance scenario shown above, while providing substantially higher power for larger effects.

## 3. Final Planned Item-Bank Size

The confirmatory design will use **80 unique items per experiment bank**.

Expected trajectory counts:

- Experiment 1 — Hypothesis Engine: 80 items × 2 models = **160**
- Experiment 2 — Core EDR: 80 items × 2 models = **160**
- Experiment 2 — Framing: 80 items × 2 framings × 2 models = **320**
- Experiment 3 — Glasswing: 80 items × 2 conditions × 2 models = **320**

**Total planned confirmatory trajectories: 960.**

The 960 trajectories are not interpreted as 960 independent repetitions of one prompt. Generalisation is supported through 80 distinct items per bank, with item retained as a clustering/pairing factor in the statistical analysis.

## 4. Design Consequences

- No confirmatory item is generated from the outcome of another confirmatory run.
- Item banks must be frozen before the main run.
- Paired-condition items must be materially identical except for the manipulated wording/condition.
- Pilot outcomes are excluded from the power calculation's confirmatory sample and from all main effect estimates.
- If item-quality screening removes items before protocol freeze, the bank will be replenished to 80 before the main run.
- After the protocol-freeze tag, sample size is not increased or decreased in response to observed confirmatory effects.

## 5. Interpretation

The purpose of this sample size is not to guarantee statistical significance. It is to ensure that failure to detect a practically meaningful effect is informative rather than merely a consequence of the five-trial pilot design.

The main paper will report effect sizes, paired contrasts, confidence intervals, and model/item heterogeneity rather than relying on p-values alone.
