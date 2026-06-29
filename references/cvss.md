# CVSS Scoring Procedure

Agents must emit a `cvss` object for every confirmed or exploitable finding. The schema requires:

```json
{ "version": "3.1" | "4.0", "vector": "<string>", "score": <0-10> }
```

The `version` field determines which vector grammar and score calculation apply. Use **CVSS 3.1** by default; use **CVSS 4.0** when the target is firmware, an embedded system, or a supply-chain component where the 4.0 Vulnerable/Subsequent system split is material.

---

## CVSS 3.1

### Base Metric Definitions

| Metric | Abbr | Values | Meaning |
|---|---|---|---|
| Attack Vector | AV | N / A / L / P | Network / Adjacent / Local / Physical — how far the attacker must be from the target |
| Attack Complexity | AC | L / H | Low: no special conditions; High: requires a race condition, specific config, or other non-attacker-controlled state |
| Privileges Required | PR | N / L / H | None / Low (authenticated user) / High (admin) — minimum privilege before exploitation |
| User Interaction | UI | N / R | None / Required — whether a legitimate user must take an action |
| Scope | S | U / C | Unchanged / Changed — whether exploitation affects resources beyond the vulnerable component |
| Confidentiality | C | N / L / H | None / Low / High impact on confidentiality of the vulnerable component |
| Integrity | I | N / L / H | None / Low / High impact on integrity |
| Availability | A | N / L / H | None / Low / High impact on availability |

Vector string format: `CVSS:3.1/AV:<v>/AC:<v>/PR:<v>/UI:<v>/S:<v>/C:<v>/I:<v>/A:<v>`

### Choosing Each Metric for Common Finding Types

**Firmware / embedded network service (e.g., HTTP, Modbus, Telnet)**
- AV: `N` if the service listens on a routed interface; `A` if VLAN/link-local only; `L` if only localhost.
- AC: `L` for straightforward memory corruption with no race; `H` if ASLR+PIE must be defeated with a separate info-leak step.
- PR: `N` if the service has no auth or the vulnerability is pre-auth; `L` if an unprivileged account suffices.
- UI: `N` for server-side vulnerabilities; `R` for client-side (XSS, CSRF, browser-triggered).
- S: `C` if exploitation escapes the service sandbox or gains kernel/hypervisor code execution; `U` otherwise.
- C/I/A: Set `H` for any component where the attacker gains full read access, write access, or the ability to crash/DoS, respectively.

**Web application finding (XSS, SQLi, SSRF)**
- AV: `N` (web is always network-reachable).
- AC: `L` for reflected XSS or error-based SQLi; `H` for blind SQLi requiring timing analysis.
- PR: `N` for unauthenticated endpoints; `L` for authenticated user actions.
- UI: `R` for XSS/CSRF (requires victim to load page); `N` for SQLi/SSRF.
- S: `C` for stored XSS that executes in an admin context; `U` for same-site reflected XSS.
- C: `H` for SQLi dumping full DB; `L` for partial field leakage (e.g., username enumeration).

**Local binary (privilege escalation, SUID, format string)**
- AV: `L` (requires shell on the host).
- AC: `L` for straightforward stack overflow; `H` if heap feng shui or kernel pointer leak required.
- PR: `L` for SUID binary exploitable by any local user; `N` only if readable/executable by unauthenticated OS session.
- UI: `N` for CLI-triggered; `R` if an admin must run a script that calls the binary.
- S: `C` if escalation crosses privilege boundary (e.g., root); `U` for lateral movement within same user.

---

## CVSS 4.0

### New and Changed Base Metrics vs 3.1

| Metric | Abbr | Values | Change from 3.1 |
|---|---|---|---|
| Attack Vector | AV | N / A / L / P | Unchanged |
| Attack Complexity | AC | L / H | Unchanged semantics; H now more narrowly defined |
| Attack Requirements | AT | N / P | **New** — N: no prerequisite configuration; P: successful attack depends on specific deployment condition |
| Privileges Required | PR | N / L / H | Unchanged |
| User Interaction | UI | N / P / A | **Changed** — Passive (victim browses/opens) replaces Required; Active (victim must take specific steps) is new |
| Vulnerable System Confidentiality | VC | N / L / H | **New** — C/I/A impact scoped to the vulnerable component specifically |
| Vulnerable System Integrity | VI | N / L / H | **New** |
| Vulnerable System Availability | VA | N / L / H | **New** |
| Subsequent System Confidentiality | SC | N / L / H | **New** — C/I/A impact on other systems reachable after exploitation |
| Subsequent System Integrity | SI | N / L / H | **New** |
| Subsequent System Availability | SA | N / L / H | **New** |

Vector string format: `CVSS:4.0/AV:<v>/AC:<v>/AT:<v>/PR:<v>/UI:<v>/VC:<v>/VI:<v>/VA:<v>/SC:<v>/SI:<v>/SA:<v>`

**When to use 4.0:** prefer 4.0 for firmware and embedded findings where subsequent-system impact (e.g., exploiting a gateway firmware to reach downstream PLCs) is distinct and material. The VC/VI/VA vs SC/SI/SA split captures this cleanly.

---

## Worked Examples

### Example 1 — Network RCE via heap buffer overflow in firmware HTTP parser

**Scenario:** A stack buffer overflow in the HTTP `Content-Length` parser of a router's web management interface, reachable over WAN, no authentication required, leads to arbitrary code execution as root. No mitigation (NX, ASLR) present on the target.

**CVSS 3.1 metric choices:**
| Metric | Value | Reason |
|---|---|---|
| AV | N | Reachable over the internet |
| AC | L | No race or special condition; straightforward overflow |
| PR | N | Pre-authentication |
| UI | N | Server-side; no user action needed |
| S | U | Gains root within the same firmware process space |
| C | H | Full read access to all device memory and credentials |
| I | H | Arbitrary write / code execution |
| A | H | Crash or persistent control over device |

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Score:** 9.8 (Critical)

**JSON field in finding:**
```json
"cvss": { "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8 }
```

---

### Example 2 — Local out-of-bounds read leaking kernel pointers

**Scenario:** An out-of-bounds read in a SUID binary returns kernel pointer values via an error message, enabling ASLR defeat for a subsequent kernel exploit. Requires a local shell. No write primitive available from this bug alone.

**CVSS 3.1 metric choices:**
| Metric | Value | Reason |
|---|---|---|
| AV | L | Requires existing local shell session |
| AC | L | Easily triggered via crafted argument |
| PR | L | Any local user can run the SUID binary |
| UI | N | No admin or user interaction required |
| S | U | Read-only leak; no scope change from this bug alone |
| C | H | Leaks sensitive kernel addresses enabling further attack |
| I | N | No write capability |
| A | N | No availability impact |

**Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
**Score:** 5.5 (Medium)

**JSON field in finding:**
```json
"cvss": { "version": "3.1", "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "score": 5.5 }
```

---

## Schema Consistency Rules

- The `version` value (`"3.1"` or `"4.0"`) must match the prefix in the `vector` string (`CVSS:3.1/...` or `CVSS:4.0/...`). A mismatch will fail schema validation.
- `score` must be the numeric Base Score (0.0–10.0). Do not use Temporal or Environmental adjusted scores unless the task spec explicitly says to.
- Always round to one decimal place. CVSS 3.1 defines Roundup as ceiling to the nearest 0.1.
- Do not omit the `CVSS:3.1/` or `CVSS:4.0/` prefix from the vector string.
- For CVSS 4.0 vectors, all eleven base metric abbreviations are required; omitting any will produce an invalid vector.
