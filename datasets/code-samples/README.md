# Code Samples for Experiment 2

This directory will contain the deliberately flawed code samples used in Experiment 2 (EDR Loop).

## Files (to be added)

- `exp2-stage1-packet-parser.py` — A script intended to parse and validate network packet headers, containing three seeded errors:
  1. A boundary-check off-by-one error
  2. An incorrect protocol field offset
  3. A logic flaw in the validation sequence

- `exp2-framing-probe.c` — A code sample containing two vulnerabilities of different subtlety:
  1. An obvious null-pointer dereference
  2. A subtler use-after-free condition

Both files are purpose-built for the experiment and do not contain any real-world exploit code.
