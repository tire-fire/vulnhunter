---
name: finding-validation
description: Staged real→reachable→exploitable pipeline that turns a candidate-*.json into a finding-*.json (status confirmed/exploitable) or rules it out. The false-positive filter and rigor centerpiece of the vulnhunter pipeline.
user-invocable: false
---

# finding-validation

Validates a candidate vulnerability through a staged gauntlet and produces a schema-valid `finding-*.json`. Input: `candidate-*.json` matching `references/schemas/candidate.schema.json`. Output: `finding-*.json` matching `references/schemas/finding.schema.json` with status `confirmed`, `exploitable`, or `ruled_out`.

All PoC execution runs through `scripts/sandbox.sh <workspace> -- <cmd>`. Finding output is validated with `scripts/validate-artifact.sh finding <file>`. On confirmation, call the `vuln-taxonomy` skill to assign `cwe`, `attack_techniques`, and `cvss`.

See `skills/finding-validation/stages.md` for entry/exit criteria, gate assignments, and artifacts per stage.

---

## Hard Gates

The gates below are adapted from the RAPTOR vulnerability validation methodology (github.com/gadievron/raptor, MIT License). Any candidate that cannot pass all applicable gates is ruled out — no exceptions.

---

### NO-HEDGING

Every claim in the candidate `hypothesis` field and all intermediate findings must be verified. Hedged language — "maybe", "could", "in theory", "possibly", "might" — is a disqualifier until the underlying claim is proven.

**Enforcement:** If the hypothesis contains unverified hedged language, do not advance past Stage A. Either verify the claim (produce concrete evidence) or set `status: ruled_out` with a reason documenting what was unverifiable.

---

### PROOF

The vulnerable code, configuration, or system state that enables the weakness must be shown explicitly.

**Enforcement:** Stage 0 must confirm the referenced asset and code path exist. Stage A must identify the specific construct (function, sink, config key, protocol handler) that is weak. "The binary likely contains this" is not proof — locate and cite the actual artifact.

---

### POC-EVIDENCE

"Ran without error" is not evidence. A proof-of-concept must produce an **observable, externally measurable effect**:

- A crash or segfault (with signal and address logged)
- Changed output that differs from the non-exploited baseline
- An out-of-band callback (DNS lookup, HTTP request to a listener) confirming execution or data exfiltration
- A file created, read, or modified outside the intended scope
- A measurable state change in the target (process killed, socket closed, value overwritten)

**Enforcement:** Stage C requires at least one observable effect logged in `evidence`. A PoC that exits cleanly with no measurable difference from the baseline does not satisfy this gate regardless of theoretical correctness. All PoC runs use `scripts/sandbox.sh`.

---

### CONSISTENCY

Severity must match the proof. A finding cannot carry a higher severity rating than its demonstrated impact.

- A memory-safety bug with no demonstrated code-execution primitive cannot be rated Critical or High.
- A denial-of-service that crashes one worker thread cannot claim a CVSS Availability score of High if the service self-recovers.
- An information disclosure of non-sensitive data (e.g., a version banner) cannot carry High Confidentiality impact.

**Enforcement:** Stage F verifies that the CVSS vector values and severity field are consistent with the evidence recorded in Stages C–E. Inconsistencies must be corrected before the finding is emitted; they are not a basis for ruled_out unless the bug itself turns out to be benign.

---

### REACHABILITY-GATE

A candidate cannot receive `status: exploitable` without demonstrating that an attacker can reach the vulnerable code from an entry point.

**Enforcement:**
- Stage B identifies what attacker position, credentials, and preconditions are required.
- Stage C traces an execution path from a listed entry point to the vulnerable construct.
- A finding that fails Stage C must remain `status: confirmed` (weakness is real but reachability unproven) or be set to `status: ruled_out` if the code path is provably unreachable.
- `exploitable` is only available after Stage B and Stage C both pass.

---

## Pipeline Summary

```
candidate-*.json
      │
  Stage 0 ── confirm asset exists (PROOF gate starts here)
      │
  Stage A ── verify weakness class; call vuln-taxonomy for CWE
      │
  Stage B ── preconditions + attacker reach
      │
  Stage C ── trace execution path; run PoC via scripts/sandbox.sh (POC-EVIDENCE gate)
      │
  Stage D ── ruling: confirmed | exploitable | ruled_out
      │
  Stage E ── binary targets: check NX/ASLR/canary/PIE
      │
  Stage F ── CONSISTENCY gate + scripts/validate-artifact.sh finding
      │
  finding-*.json
```

Status transitions:

| Condition | Status |
|---|---|
| Asset does not exist | `ruled_out` |
| Pattern is not a real weakness | `ruled_out` |
| Weakness real, reachability unproven | `confirmed` |
| Weakness real, path traced, PoC observable | `exploitable` |

A finding cannot jump from candidate to `exploitable` without passing Stages B and C. `confirmed` is a legitimate terminal status when reachability cannot be established within engagement scope.
