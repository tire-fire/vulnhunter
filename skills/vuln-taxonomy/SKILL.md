---
name: vuln-taxonomy
description: Assign CWE classes, MITRE ATT&CK technique IDs, and CVSS 3.1/4.0 vectors to a vulnerability finding. Use when classifying or scoring a confirmed finding before reporting.
user-invocable: false
---

# vuln-taxonomy

Given a confirmed or exploitable finding, produce the three classification fields required by `references/schemas/finding.schema.json`: `cwe` (array), `attack_techniques` (array), and `cvss` (object). Follow the steps below in order.

---

## Step 1 — Assign CWE(s)

Open `references/attack-taxonomy.md` Part 1. For each weakness in the finding:

1. Identify the vulnerable code construct (sink, API call, or pattern) from the evidence.
2. Work through the "Assign when" column from most specific to most general. Select the **most specific** matching CWE. Do **not** use a parent class when a child applies (e.g., prefer CWE-121 over CWE-119 for a confirmed stack overflow).
3. If a secondary, distinct weakness co-exists (e.g., an integer overflow that causes a heap overflow), add both CWEs: list the root cause first, then the exploitable consequence.
4. Do not assign `CWE-0` or any CWE not present in `references/attack-taxonomy.md` Part 1 unless `references/novel-research.md` authorizes an extension.

Write each id as the string `CWE-N` (e.g., `"CWE-787"`) — must match `^CWE-[0-9]+$`.

---

## Step 2 — Map to MITRE ATT&CK Technique IDs

Open `references/attack-taxonomy.md` Part 2. For each CWE selected in Step 1:

1. Locate the matching row in the mapping table (Enterprise or ICS section).
2. **Memory-corruption technique selection (CWE-119/120/121/122/787/190):**
   - If the vulnerable component is a **network-reachable server-side service** (daemon, HTTP server, embedded parser listening on a routed or link-local interface), assign **T1190**.
   - If exploitation requires a victim to open attacker-supplied content in a **client-side binary** (PDF/document/media parser, browser plugin), assign **T1203**.
3. **ICS/OT targets:** Check whether the target appears in `targets.json` as a firmware, PLC, RTU, HMI, or industrial-protocol asset. If so, apply ICS techniques (`T0xxx`) first; include Enterprise IDs only when they describe additional post-exploitation behavior. Include both in the array when both apply.
4. Select the technique(s) that describe what an attacker *does* with the weakness, not what the weakness *is*.
5. Write each id exactly: four digits after `T` for base techniques, three additional digits after a period for sub-techniques (e.g., `"T1059.004"`, not `"T1059.4"`). Must match `^T[0-9]{4}(\.[0-9]{3})?$`.

---

## Step 3 — Build the CVSS Vector and Score

Open `references/cvss.md`.

**Choose version:**
- Use **CVSS 3.1** by default.
- Use **CVSS 4.0** when the target is firmware, an embedded system, or a supply-chain component where the Vulnerable/Subsequent system impact split is material.

**CVSS 3.1 procedure:**

Score each of the eight base metrics using the metric definitions and per-finding-type guidance in `references/cvss.md`:

| Metric | Key question |
|---|---|
| AV | Is the service network-reachable (N), adjacent-network (A), local (L), or physical (P)? |
| AC | Does exploitation require a race condition or specific non-default configuration (H), or not (L)? |
| PR | Must the attacker hold an account before exploiting — none (N), unprivileged (L), or admin (H)? |
| UI | Does a legitimate user need to take an action (R), or not (N)? |
| S | Does exploitation escape the vulnerable component's sandbox or gain cross-boundary code execution (C), or stay within it (U)? |
| C | Full read of in-scope data (H), partial read (L), or none (N)? |
| I | Arbitrary write / code execution (H), partial modification (L), or none (N)? |
| A | Crash or denial of all availability (H), degraded (L), or none (N)? |

Compose the vector string: `CVSS:3.1/AV:<v>/AC:<v>/PR:<v>/UI:<v>/S:<v>/C:<v>/I:<v>/A:<v>`

**CVSS 4.0 procedure:**

Score all eleven base metrics (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA) using the definitions in `references/cvss.md`. Compose the vector: `CVSS:4.0/AV:<v>/AC:<v>/AT:<v>/PR:<v>/UI:<v>/VC:<v>/VI:<v>/VA:<v>/SC:<v>/SI:<v>/SA:<v>`

**Score calculation rules (both versions):**
- Compute the numeric Base Score per the CVSS specification. Round up to one decimal place (ceiling to nearest 0.1).
- Do not use Temporal or Environmental scores unless explicitly required by the task spec.
- The `version` value must match the prefix in `vector` — mismatches fail schema validation.

---

## Step 4 — Emit the Three Schema Fields

Produce the fields exactly as `references/schemas/finding.schema.json` requires:

```json
"cwe": ["CWE-N", ...],
"attack_techniques": ["T1234", ...],
"cvss": {
  "version": "3.1",
  "vector": "CVSS:3.1/AV:.../...",
  "score": 0.0
}
```

Constraints:
- `cwe`: array of strings, each matching `^CWE-[0-9]+$`, minimum one element.
- `attack_techniques`: array of strings, each matching `^T[0-9]{4}(\.[0-9]{3})?$`; may be empty only if no applicable ATT&CK technique exists (document the reason in the finding summary in that case).
- `cvss.version`: `"3.1"` or `"4.0"` only.
- `cvss.vector`: string beginning with `CVSS:3.1/` or `CVSS:4.0/`; must include all required metrics for the chosen version.
- `cvss.score`: number in `[0, 10]`.

Do not add ATT&CK tactic labels, CWE names, or any extra fields to these three schema properties.

---

## Worked Example — Network RCE via Out-of-Bounds Write in HTTP Daemon

**Scenario:** An out-of-bounds write (heap) in an embedded router's HTTP management daemon, reachable over WAN on port 80. No authentication required. No memory mitigations (NX/ASLR) on the target. Exploitation yields arbitrary code execution as root.

### Step 1 — CWE

The sink is a heap buffer written past its end. From `references/attack-taxonomy.md` Part 1, Memory Safety table:
- "Index or pointer writes past buffer bounds" → **CWE-787** (Out-of-bounds Write). This is more specific than CWE-119 and applies because the write primitive is confirmed.

`"cwe": ["CWE-787"]`

### Step 2 — ATT&CK

From `references/attack-taxonomy.md` Part 2, Enterprise table, row for CWE-787:
- The vulnerable component is a **network-reachable server-side HTTP daemon** — not a client-side binary. Per the memory-corruption selection rule, assign **T1190** (Exploit Public-Facing Application).
- The target is a consumer router, not an ICS/PLC asset, so no ICS techniques apply.

`"attack_techniques": ["T1190"]`

### Step 3 — CVSS 3.1

Target is not firmware where 4.0's Subsequent System split adds material information, so use CVSS 3.1.

| Metric | Value | Reasoning |
|---|---|---|
| AV | N | Service reachable over the internet (WAN port 80) |
| AC | L | Straightforward heap overflow; no race condition or special config |
| PR | N | Pre-authentication; no account required |
| UI | N | Server-side exploit; no user action needed |
| S | U | Code execution within the same firmware process; no boundary crossing |
| C | H | Full read of all device memory, credentials, config |
| I | H | Arbitrary write / code execution |
| A | H | Attacker can crash or persistently control the device |

Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
Score: **9.8** (Critical)

### Step 4 — Schema Fields

```json
"cwe": ["CWE-787"],
"attack_techniques": ["T1190"],
"cvss": {
  "version": "3.1",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "score": 9.8
}
```
