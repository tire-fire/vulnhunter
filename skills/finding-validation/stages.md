---
name: finding-validation-stages
description: Concrete stage definitions for the finding-validation gauntlet: entry/exit criteria, gates enforced, and the artifact or field each stage writes.
user-invocable: false
---

# finding-validation — Stage Definitions

Each stage has a single responsibility, explicit entry and exit criteria, the gate(s) it enforces, and the artifact or `finding-*.json` field it writes. Stages run sequentially. Failure at any stage stops progression and triggers a ruling (Stage D).

Input schema: `references/schemas/candidate.schema.json`
Output schema: `references/schemas/finding.schema.json`

---

## Stage 0 — Asset Inventory

**Purpose:** Confirm that every artifact referenced in the candidate actually exists before spending effort on analysis. Prevents hallucinated findings from advancing.

**Entry criteria:** A `candidate-*.json` with at least `id`, `asset`, `hypothesis`, and `cwe_guess` populated.

**Procedure:**
1. Resolve the `asset` field to a file path, network endpoint, binary, or service within the engagement scope.
2. Confirm the asset is present and readable (or reachable for network targets).
3. Confirm any specific code location, function name, or config key cited in `hypothesis` exists in the asset.
4. If `source_chain` is `static-re`, confirm the binary or source file referenced by the candidate is the same artifact that generated the candidate (check path and hash where available).

**Exit criteria (pass):** Asset and all cited code/config locations are confirmed present.

**Exit criteria (fail):** Asset is missing, path is wrong, or the cited function/config key does not exist in the asset → set `status: ruled_out`, record reason in `summary`, write `finding-*.json`, stop. The written `finding-*.json` is schema-valid under the conditional schema: it carries only the base-required fields (`id`, `title`, `status: ruled_out`, `asset`, `summary`). No rich fields (cwe, evidence, cvss, etc.) are required or emitted for `ruled_out`. Run `scripts/validate-artifact.sh finding finding-<id>.json` to confirm validity before stopping.

**Gates enforced:** PROOF (asset existence is the first proof requirement), NO-HEDGING (unverifiable asset references are resolved or ruled out here).

**Artifacts written:** `asset` field confirmed; `id` and `title` drafted in working finding.

---

## Stage A — Weakness Classification

**Purpose:** Determine whether the pattern identified in the hypothesis is a genuine software or configuration weakness, not a false pattern or expected behavior.

**Entry criteria:** Stage 0 passed; asset and code location confirmed.

**Procedure:**
1. Examine the specific construct (sink, API call, config value, protocol behavior) cited by the hypothesis.
2. Apply the weakness taxonomy in `references/attack-taxonomy.md` Part 1 to determine whether the pattern matches a known CWE. Start at the most specific entry; do not assign a parent class when a child applies.
3. If the pattern matches a known weakness, call the `vuln-taxonomy` skill (Steps 1–4) to produce `cwe`, `attack_techniques`, and `cvss` fields for the working finding.
4. If the pattern is not a weakness (expected behavior, defense-in-depth, informational only), set `status: ruled_out`.

**Exit criteria (pass):** At least one CWE assigned; `cwe` array populated with entries matching `^CWE-[0-9]+$`.

**Exit criteria (fail):** No applicable CWE; pattern is not a genuine weakness → `status: ruled_out`.

**Gates enforced:** NO-HEDGING (a "possible" CWE must be verified against the actual code construct), PROOF (the specific vulnerable construct must be named, not inferred).

**Artifacts written:** `cwe` (via vuln-taxonomy), `attack_techniques` (via vuln-taxonomy), partial `cvss` (via vuln-taxonomy), `severity` drafted from CVSS score. Additionally, write the first `evidence` entry at this stage: a string citing the specific code location or config path of the weakness (e.g., `"use-after-free at src/foo.c:42"` or `"world-writable config at /etc/app/service.conf"`). This Stage A code-location entry ensures that a `confirmed` or `exploitable` finding always satisfies `evidence` minItems 1 even when Stage C achieves no observable PoC effect.

---

## Stage B — Preconditions and Attacker Reach

**Purpose:** Enumerate what an attacker must control, know, or hold to trigger the weakness. Establishes whether exploitation is theoretically possible given the engagement scope.

**Entry criteria:** Stage A passed; weakness confirmed and classified.

**Procedure:**
1. List every precondition required to reach the vulnerable code:
   - Attacker network position (internet, adjacent network, local, physical)
   - Authentication or authorization required (none, unprivileged account, admin account)
   - User interaction required (none, victim must open file, victim must click link)
   - Non-default configuration or specific runtime state. When reachability hinges on whether a feature is enabled by default, resolve its default state from config-defaults shipped in the image — and check whether build/platform variants override that default (a feature off by default globally may be on for a specific variant).
2. Cross-check preconditions against the engagement scope. If the required attacker position is explicitly out of scope, set `status: ruled_out`.
3. Identify the attack chain: what sequence of inputs or requests reaches the vulnerable construct.
4. Note any mitigations already in place (WAF, authentication, rate limiting) that must be bypassed.

**Exit criteria (pass):** Preconditions documented; attack chain sketched; no precondition is provably impossible within scope.

**Exit criteria (fail):** A required precondition is provably unachievable within scope → `status: ruled_out`; or required attacker position is out of scope → `status: ruled_out`.

**Gates enforced:** REACHABILITY-GATE (Stage B is the prerequisite; `exploitable` cannot be set without passing B and C).

**Artifacts written:** `reproduction` array (precondition steps); notes added to `summary`.

---

## Stage C — Reachability Verification

**Purpose:** Trace an actual execution path from a listed entry point to the vulnerable construct and produce observable evidence of trigger. This is the PoC execution stage.

**Entry criteria:** Stage B passed; preconditions documented; attack chain sketched.

**Procedure:**
1. Identify the entry point in the attack surface (network endpoint, binary input, web endpoint, IPC socket) that feeds the vulnerable construct.
2. Construct a minimal proof-of-concept that traverses the path from entry point to the weakness. The PoC must produce an **observable, externally measurable effect** per the POC-EVIDENCE gate.
3. Run the PoC exclusively through the sandbox:
   ```
   scripts/sandbox.sh <workspace> -- <poc-command>
   ```
   - **No live target?** A function-level PoC still produces observable evidence: emulate the actual firmware code on controlled inputs per `references/harnesses/firmware-fn-emulation.md` (qemu-user caller or pyghidra p-code). Proving the firmware routine maps input→output exactly as your exploit model assumes is a valid Stage-C observable effect for crypto/parser weaknesses.
   - **No isolation backend** (bwrap absent + restricted user namespaces)? `sandbox.sh` refuses by default; for emulation of extracted code that does no network I/O, opt in with `SANDBOX_DEGRADED_OK=1 scripts/sandbox.sh …` (resource/wall limits still apply). Do not use degraded mode to detonate untrusted network-active code.
4. Capture the output. Record the observable effect (crash signal and address, changed output diff, callback log, file read/write confirmation, or state change) as a string in the `evidence` array.
5. If the PoC exits cleanly with no measurable difference from baseline, the POC-EVIDENCE gate is not satisfied. Refine the PoC or downgrade to `status: confirmed` if the path is traced but no trigger effect is achievable within engagement constraints.
6. If no execution path from any entry point reaches the vulnerable construct, set `status: confirmed` (weakness is real, reachability unproven within scope).

**Exit criteria (pass):** An observable effect is recorded in `evidence`; execution path from entry point to weakness is demonstrated.

**Exit criteria (partial):** Path exists but PoC produces no observable effect within engagement constraints → `status: confirmed` (not `exploitable`). The Stage A code-location evidence entry satisfies the `evidence` minItems 1 requirement when no PoC effect is achievable.

**Exit criteria (fail):** No path from any entry point reaches the vulnerable construct → `status: confirmed` or `status: ruled_out` depending on Stage A findings. The Stage A code-location evidence entry satisfies the `evidence` minItems 1 requirement when no PoC effect is achievable.

**Gates enforced:** POC-EVIDENCE (observable effect required), REACHABILITY-GATE (path from entry point must be demonstrated to reach `exploitable`).

**Artifacts written:** `evidence` array (minItems 1 required by `references/schemas/finding.schema.json`); `reproduction` array completed.

---

## Stage D — Ruling

**Purpose:** Assign the terminal `status` value based on the cumulative results of Stages 0–C.

**Entry criteria:** Stages 0, A, B, C each have a recorded outcome (pass, partial, fail, or N/A if not reached due to an earlier failure).

**Decision table:**

| Stage 0 | Stage A | Stage B | Stage C | Status |
|---|---|---|---|---|
| fail | — | — | — | `ruled_out` |
| pass | fail | — | — | `ruled_out` |
| pass | pass | fail | — | `ruled_out` |
| pass | pass | pass | fail (no path) | `confirmed` |
| pass | pass | pass | partial (path, no effect) | `confirmed` |
| pass | pass | pass | pass (path + effect) | `exploitable` |

**Rules:**
- `exploitable` requires Stage B pass AND Stage C pass (path traced AND observable effect produced).
- `confirmed` is valid when the weakness is real (Stage A pass) but reachability is unproven or limited within scope.
- `ruled_out` always includes a `summary` explaining the ruling; do not emit `ruled_out` with an empty summary.
- A finding at `confirmed` or `exploitable` must have `evidence` with at least one entry.

**Gates enforced:** REACHABILITY-GATE (enforces the B+C requirement for `exploitable`).

**Artifacts written:** `status` field; `summary` field completed.

---

## Stage E — Exploit Feasibility for Binary Targets

**Purpose:** For binary targets (ELF/PE/Mach-O), assess whether memory mitigations reduce practical exploit feasibility and whether the CVSS score reflects that reduction.

**Entry criteria:** `status` is `exploitable` AND `asset` resolves to a compiled binary. Skip this stage for web applications, configuration weaknesses, and logic bugs.

**Procedure:**
1. Check binary mitigations:
   ```bash
   checksec --file="<binary>"
   ```
   Record the presence or absence of: NX (No-Execute), ASLR (system-wide), stack canary, PIE (Position-Independent Executable), RELRO.
2. Assess bypass feasibility:
   - NX without a ROP chain: note that shellcode injection is blocked but ROP may be viable.
   - ASLR with PIE: note that arbitrary code execution requires an information leak; if none is available, downgrade impact or note the dependency.
   - Stack canary: note that stack-overflow exploitation requires a canary bypass; assess whether a leak primitive exists.
3. If mitigations collectively make exploitation implausible within the engagement scope (e.g., full ASLR + PIE + canary with no leak primitive and no brute-force window), downgrade `status` to `confirmed` and update `summary` to explain the mitigation barrier.
4. If mitigations are present but bypassable (ROP chain demonstrated, leak primitive identified), record the bypass technique in `reproduction` and retain `status: exploitable`.
5. Update the CVSS vector if the mitigation assessment changes the Attack Complexity metric (e.g., a canary that must be leaked raises AC to High).

**Gates enforced:** CONSISTENCY (severity and CVSS must reflect actual exploit feasibility given mitigations), PROOF (mitigation status must be measured, not assumed).

**Artifacts written:** Notes added to `reproduction`; `cvss` vector and `severity` potentially updated.

---

## Stage F — Consistency Review and Final Validation

**Purpose:** Verify internal consistency across all fields, enforce the CONSISTENCY gate, and emit the schema-valid `finding-*.json`.

**Entry criteria:** Stages 0–E complete; all required finding fields drafted.

**Procedure:**
1. **Severity vs. evidence check (CONSISTENCY gate):**
   - Critical/High severity requires demonstrated code execution, full data exfiltration, or complete availability loss in `evidence`.
   - Medium severity: partial impact demonstrated.
   - Low/Info: theoretical or minimal demonstrated impact.
   - If severity is higher than the evidence supports, downgrade severity and recalculate CVSS.
2. **CVSS vector consistency check:**
   - Verify every CVSS metric value is supported by the evidence and reproduction steps.
   - AV must match the demonstrated entry point (network-reachable vs. local vs. physical).
   - PR must reflect whether authentication was bypassed or not required.
   - S must reflect whether the PoC crossed a trust boundary.
   - The `version` field must match the prefix in `vector` (e.g., `"3.1"` ↔ `"CVSS:3.1/..."`).
3. **Required-field audit:** Confirm `id`, `title`, `status`, `severity`, `cwe` (minItems 1), `attack_techniques`, `cvss`, `asset`, `summary`, and `evidence` (minItems 1) are all populated and non-empty.
4. **Validate the output file:**
   ```bash
   scripts/validate-artifact.sh finding finding-<id>.json
   ```
   The script must print `VALID` and exit 0. Fix any `INVALID:` lines before emitting the finding.
5. Write the validated `finding-*.json`.

**Gates enforced:** CONSISTENCY (severity-to-evidence alignment; CVSS-to-evidence alignment), PROOF (all fields are substantiated by recorded evidence, not placeholder text).

**Artifacts written:** Final `finding-*.json` validated against `references/schemas/finding.schema.json`.
