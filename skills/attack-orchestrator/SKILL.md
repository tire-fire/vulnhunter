---
name: attack-orchestrator
description: Orchestrate end-to-end vulnerability hunting against firmware and/or in-scope live targets - enumerate attack surface, prioritize, dispatch specialized chains, validate findings, and write CWE/ATT&CK/CVSS bug-bounty reports. Use when given a firmware image or an authorized live target plus an engagement scope file.
---

# attack-orchestrator

End-to-end lifecycle orchestrator for firmware and live-target vulnerability discovery. Runs seven phases in sequence, dispatching specialized agents and validating all artifacts against `references/schemas/` before advancing.

**Agents hand off exclusively via schema-validated JSON artifacts.** The orchestrator surfaces substantive results (confirmed findings, PoC output, cross-chain attack chains) and does not narrate schema-pass events or gate-compliance steps.

---

## Phase 1 — Intake and Scope

**Required inputs (refuse active work without both):**
- Path to `engagement.yaml` — defines in-scope targets, program name, and out-of-scope exclusions.
- One or more targets (firmware image path or live host/domain).

**Setup:**
```bash
PROGRAM=$(grep '^program:' engagement.yaml | awk '{print $2}' | tr -d '"')
PROGRAM="${PROGRAM:-run}"
RUN_ID=$(date +%Y%m%d-%H%M%S)
WS="vulnhunter-runs/${PROGRAM}/${RUN_ID}"
mkdir -p "$WS"

scripts/capabilities.sh --out "$WS/capabilities.json"
```

`capabilities.json` records which analysis tools are available (pyghidra, ghidra, gdb, radare2, frida, binwalk, bwrap, unshare, qemu variants). Downstream agents read it to select the analysis path appropriate for the installed toolchain.

Do not proceed to Phase 2 without a valid `engagement.yaml` and at least one target. If either is missing, tell the user what is required and stop.

---

## Phase 2 — Enumerate (attack-surface.json)

Dispatch the **`recon-mapper`** agent, which follows the `skills/attack-surface-mapping/SKILL.md` procedure. Pass it:
- The target and its kind (firmware / network_host / local_binary / web_app)
- The workspace path `$WS`
- The engagement file path

The agent writes `$WS/attack-surface.json`. Validate before continuing:

```bash
scripts/validate-artifact.sh attack-surface "$WS/attack-surface.json"
```

Schema reference: `references/schemas/attack-surface.schema.json`

Required fields: `target`, `components` (non-empty array), `entry_points` (non-empty array). If validation fails, return the `INVALID:` lines to the user and stop.

---

## Phase 3 — Prioritize (targets.json)

Apply the scoring model in `references/scoring.md` to rank every entry point in `attack-surface.json`.

For each entry point, compute:

```
priority_score = exposure_weight × impact_weight × likelihood_weight × reachability_weight
```

**Drop any item whose `reachability_weight = 0` (`unreachable` verdict) entirely from the queue.** Do not include zero-score items in `targets.json` — a zeroed entry that remains in the queue causes false reporting.

Assign `assigned_chain` based on target kind and entry point nature:
- Firmware binaries and local ELF targets → `"static-re"`
- Live hosts requiring active probing (network daemons, IPC endpoints) → `"dynamic"`
- Web applications and HTTP endpoints → `"web-proto"`

Pre-tag candidate CWEs using the `skills/vuln-taxonomy/SKILL.md` procedure (Step 1 only at this stage). Write the guesses into the `cwe_guess` array on each queue entry.

Write `$WS/targets.json` and validate:

```bash
scripts/validate-artifact.sh targets "$WS/targets.json"
```

Schema reference: `references/schemas/targets.schema.json`

Required per queue entry: `id`, `asset`, `assigned_chain` (one of `static-re | dynamic | web-proto`), `priority_score`.

---

## Phase 4 — Dispatch Chain Agents (parallel)

For each entry in `targets.json`'s `queue` array, launch the agent corresponding to `assigned_chain` as a subagent. Run all queue items in parallel.

| `assigned_chain` value | Agent to dispatch |
|---|---|
| `static-re` | **`static-re-chain`** |
| `dynamic` | **`dynamic-chain`** |
| `web-proto` | **`web-proto-chain`** |

Pass each agent:
- Its queue entry (id, asset, priority_score, cwe_guess)
- The workspace path `$WS`
- The engagement file path
- Path to `$WS/capabilities.json`

**Scope gate — mandatory for `dynamic-chain` and `web-proto-chain`:** these agents MUST run the following check before any active probe:

```bash
scripts/scope-check.sh <engagement.yaml> <target>
```

Exit code 0 means IN_SCOPE — proceed. Exit code 2 means out of scope or not listed — abort that agent and log the target as excluded. This check must run before every distinct active action, not only at agent startup.

Each chain agent writes one or more `candidate-*.json` files into `$WS/`. Validate each on receipt:

```bash
scripts/validate-artifact.sh candidate "$WS/candidate-<id>.json"
```

Schema reference: `references/schemas/candidate.schema.json`

Required fields: `id`, `source_chain`, `asset`, `hypothesis`, `cwe_guess`. Candidates that fail validation are discarded.

---

## Phase 5 — Validate Candidates (finding-*.json)

For each schema-valid `candidate-*.json`, dispatch the **`finding-validator`** agent, which follows the `skills/finding-validation/SKILL.md` gauntlet. Pass it:
- The candidate file path
- The workspace path `$WS`
- The engagement file path

The agent runs the staged validation pipeline (Stage 0 through Stage F), executes any PoC via `scripts/sandbox.sh $WS -- <cmd>`, and writes `$WS/finding-<id>.json`. Validate:

```bash
scripts/validate-artifact.sh finding "$WS/finding-<id>.json"
```

Schema reference: `references/schemas/finding.schema.json`

Findings with `status: ruled_out` are logged but excluded from Phase 6. Findings with `status: confirmed` or `status: exploitable` advance.

---

## Phase 6 — Exploit Development

For each finding with `status: exploitable`, dispatch the **`exploit-dev`** agent. Pass it:
- The finding file `$WS/finding-<id>.json`
- The workspace path `$WS`
- The engagement file path

The agent develops a sandboxed proof-of-concept. All execution uses `scripts/sandbox.sh $WS -- <cmd>`. PoC output (crash logs, observable effects, out-of-band callbacks) is written to `$WS/poc-<id>/` and referenced in the finding's `evidence` array via an updated `finding-<id>.json`.

Surface the PoC output and any confirmed exploitation primitives (crash addresses, controlled register values, achieved code execution) directly to the user.

---

## Phase 7 — Report

Dispatch the **`report-writer`** agent. Pass it:
- All `finding-*.json` files in `$WS/` with status `confirmed` or `exploitable`
- The workspace path `$WS`
- The engagement file path
- The desired report template (default: standard bug-bounty)

The agent identifies cross-finding attack chains (findings sharing `chain_id` or whose exploitation primitives compose), writes `$WS/report.md` with CWE/ATT&CK/CVSS annotations, and writes `$WS/findings.json` aggregating all confirmed findings.

Surface the report path and a summary of confirmed and exploitable finding counts to the user.

---

## Reference Index

Schemas: `references/schemas/attack-surface.schema.json`, `references/schemas/targets.schema.json`, `references/schemas/candidate.schema.json`, `references/schemas/finding.schema.json`

Scoring model: `references/scoring.md`

Skills used: `skills/attack-surface-mapping/SKILL.md`, `skills/finding-validation/SKILL.md`, `skills/vuln-taxonomy/SKILL.md`
