# Phase-2 Prioritization Scoring Model

Agents use this model to rank candidates queued in `targets.json`. Each queue entry must carry a `priority_score` (number, 0–1) computed from the four weights below.

## Formula

```
priority_score = exposure_weight × impact_weight × likelihood_weight × reachability_weight
```

All four weights are real numbers in [0, 1]. Because the product is used for rank-ordering, a value of 0 in any factor collapses the score to 0.

**Reachability rule:** if `reachability_weight = 0` (the sink is provably unreachable under any attacker-controlled input), the candidate is dropped from the queue entirely and never passed to a chain skill. Do not score it — discard it.

---

## Weight Tables

### exposure_weight — how broadly an attacker can reach the entry point

| Exposure class | Weight | Assign when |
|---|---|---|
| `network` | 1.0 | Entry point is reachable over a routed network (HTTP API, TCP service, UDP) with no prior foothold |
| `adjacent_network` | 0.8 | Reachable only on the same L2 segment or VLAN (ARP-reachable) |
| `ipc` | 0.7 | Reachable via a local IPC mechanism (D-Bus, named pipe, Unix socket) exposed to a different process context |
| `local` | 0.5 | Requires an OS-level local login or shell session on the same host |
| `physical` | 0.3 | Requires physical hardware access (UART, JTAG, SD card swap, USB DFU) |

Corresponds to CVSS 3.1 AV metric; choose the **least-privileged** path available to the attacker, not the most.

### impact_weight — worst-case consequence if exploited

| Severity label | Weight | Assign when |
|---|---|---|
| `critical` | 1.0 | RCE as root/kernel, full device compromise, safety-system override |
| `high` | 0.8 | RCE as unprivileged user, persistent backdoor, mass credential theft |
| `medium` | 0.5 | Partial data exfiltration, privilege escalation pre-conditions, service DoS |
| `low` | 0.2 | Limited info disclosure (e.g., stack address leak), minor config exposure |
| `info` | 0.1 | Banner/version disclosure, non-sensitive data leakage with no exploit path |

Set `severity` in the finding to the same label. These two values must be consistent.

### likelihood_weight — confidence that exploitation succeeds in practice

| Likelihood band | Weight | Assign when |
|---|---|---|
| `confirmed_exploit` | 1.0 | PoC or exploit code already executed and verified |
| `known_pattern` | 0.8 | Vulnerability class with well-documented exploitation (e.g., stack overflow with NX+ASLR bypass primitives known) |
| `unclear_constraint` | 0.5 | Sink reached but memory layout, constraint checking, or mitigations make exploitation uncertain |
| `theoretical` | 0.2 | Control flow to sink modeled but no concrete trigger constructed |

### reachability_weight — whether attacker-controlled data reaches the sink

| Reachability verdict | Weight | Assign when |
|---|---|---|
| `fully_reachable` | 1.0 | Taint analysis or manual trace confirms attacker data arrives at sink unfiltered |
| `conditional` | 0.7 | Reaches sink after passing a non-security check (format validation, length cap that can be bypassed) |
| `requires_auth` | 0.5 | Sink reachable but path requires prior authenticated session (note: stolen/default creds raise this) |
| `isolated` | 0.1 | Sink reachable only in a code path never triggered by normal input; no known trigger yet found |
| `unreachable` | 0.0 | Provably unreachable (dead code, hardware feature permanently disabled, always-false guard) — **drop from queue** |

---

## Worked Examples

### Example 1 — Network stack-overflow in a firmware HTTP server

| Factor | Class | Weight |
|---|---|---|
| Exposure | `network` | 1.0 |
| Impact | `critical` (RCE as root) | 1.0 |
| Likelihood | `known_pattern` (heap overflow, known bypass primitives) | 0.8 |
| Reachability | `fully_reachable` (HTTP Content-Length flows to `memcpy` without bounds check) | 1.0 |

`priority_score = 1.0 × 1.0 × 0.8 × 1.0 = 0.80`

### Example 2 — Local integer overflow in a privileged CLI tool

| Factor | Class | Weight |
|---|---|---|
| Exposure | `local` | 0.5 |
| Impact | `medium` (escalates to SUID binary owner, not root) | 0.5 |
| Likelihood | `unclear_constraint` (overflow possible but allocation size still unclear) | 0.5 |
| Reachability | `conditional` (user-controlled argv passes one length check) | 0.7 |

`priority_score = 0.5 × 0.5 × 0.5 × 0.7 = 0.0875`

---

## Priority Score Scale: Two Distinct Uses

`priority_score` appears in two different artifact types and is **not on the same scale** in both:

- **`targets.json` queue entries** — the orchestrator's rank-ordering score. It is the product of the four weights above and therefore a number in [0, 1] (e.g., 0.80, 0.0875). Do not compare this against candidate scores.
- **`candidate-*.json` files** — each chain agent's own severity/confidence hint, expressed on a 0–10 scale per the candidate schema (see `references/schemas/candidate.schema.json`). It is **not** the same formula; do not interpret it as a 0–1 weight product and do not compare it directly to a `targets.json` priority_score.

These two values live on different artifacts with different scales. Comparing them directly produces meaningless results.

---

## Notes on Consistency with Schemas

- `priority_score` is stored as a JSON number in `targets.json` queue entries (`references/schemas/targets.schema.json`).
- The `severity` label in a finding (`finding.schema.json`) must match the `impact_weight` band used during scoring.
- Agents must not invent intermediate weight values; use the table rows above. If a finding straddles two bands, choose the lower weight (conservative).
- Reachability verdict `unreachable` (weight 0.0) must result in the queue entry being removed, not zeroed. A zero score that remains in the queue can cause false reporting.
