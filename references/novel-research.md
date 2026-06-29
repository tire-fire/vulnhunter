# Novel Attack Research Protocol

When a hunting agent encounters a sink, primitive, or target component that does not fit any pattern in `references/attack-taxonomy.md`, it must pause active hunting and perform read-only research before continuing. This document defines when that pause is warranted, what tools to use, and how to incorporate findings back into the candidate.

---

## When to Pause and Research

Pause hunting and enter research mode in any of the following situations:

### 1. Unknown Chipset or SoC

The target firmware identifies a CPU core, microcontroller, or SoC family not covered by the team's existing knowledge (e.g., a vendor-specific MIPS derivative, an FPGA soft-core, a proprietary DSP). Research is needed to determine:
- Memory layout, calling conventions, and any non-standard ABI
- Whether standard exploitation primitives (ROP, ret2libc) apply
- Whether a vendor-specific debugging interface (JTAG pin assignment, ROM monitor commands) is exposed

### 2. Unknown RTOS or Embedded OS

The target runs a RTOS not in the agent's knowledge base (e.g., a proprietary fork, an obscure POSIX-subset OS like eCos, Nucleus, ThreadX/Azure RTOS). Research determines:
- Whether standard libc calls exist or a vendor reimplementation is used
- Heap allocator design (affects heap exploitation strategy)
- Available system calls and privilege separation model

### 3. Unknown Industrial Protocol or Proprietary Framing

The target speaks a protocol the agent cannot decode from the binary or packet captures alone (e.g., a vendor-specific extension to Modbus, a binary-framed IEC 61850 variant, a proprietary commissioning protocol). Research determines:
- Field semantics and valid value ranges (needed to construct malformed frames)
- Whether a public parser implementation or Wireshark dissector exists
- Known vulnerabilities in similar implementations

### 4. Sink with No Known CWE Mapping

A data flow reaches a function or system call that:
- Has no directly applicable entry in `references/attack-taxonomy.md`, and
- Does not map cleanly to any CWE in the MITRE CWE catalog from memory

Examples: a cryptographic API misuse that is not simple key hardcoding, a hardware register write path, a custom memory allocator with novel overflow semantics, a deserialization sink in an unfamiliar serialization format (ASN.1, MessagePack, CBOR with custom schema).

### 5. Primitive That Appears Novel

A code pattern is observed that may represent a new vulnerability class or exploitation primitive not documented in public literature. Before assigning it a CWE and technique, research is required to determine whether it has been described before and what existing work applies.

---

## Research Procedure

Research is always **read-only** and **in-scope**. Agents must not interact with live systems, trigger requests to the target, or download binaries from untrusted sources during research mode.

### Step 1 — WebSearch

Issue targeted queries using the `WebSearch` tool. Construct queries that include:
- The vendor, chipset, protocol, or framework name
- The suspected vulnerability class or relevant function name
- Terms such as "CVE", "exploit", "advisory", "security analysis", "fuzzing"

Run at least two queries from different angles (e.g., one vendor-specific, one CVE-database-oriented). Record the URLs of results that appear relevant.

### Step 2 — deep-research skill (multi-source synthesis)

If WebSearch returns conflicting information, sparse results, or results that require synthesis across multiple sources, invoke the `deep-research` skill. Pass the refined research question as the argument. The skill performs fan-out searches, fetches sources, adversarially verifies claims, and produces a cited synthesis.

Use `deep-research` when:
- The chipset/protocol/framework is niche and WebSearch returns fewer than three substantive results
- Claims from different sources conflict and need reconciliation
- The question spans multiple technical domains (e.g., hardware + protocol + OS interaction)

### Step 3 — Assess and Decide

After research, the agent must:
1. Determine whether a CWE and ATT&CK technique can now be assigned. If yes, proceed normally.
2. If the vulnerability class is genuinely novel (no existing CWE applies cleanly), assign the closest ancestor CWE (e.g., CWE-119 if a buffer issue, CWE-20 for validation issues) and note in `evidence` that a more specific classification is pending.
3. Record a finding status of `confirmed` or `exploitable` only if the research provides sufficient technical basis. If not, set status to match the actual confidence level.

---

## Incorporating Research into a Candidate Finding

All sources consulted during research must appear in the `evidence` array of the finding. Use the following formats:

- Web pages and advisories: full URL, e.g., `"https://example.com/advisory/CVE-2023-1234"`
- CVE entries: `"CVE-2023-1234: <one-line description>"`
- Academic papers or whitepapers: title + URL if available, e.g., `"'Exploiting the Nucleus RTOS heap allocator', Black Hat 2022: https://..."`
- Internal analysis artifacts: relative path within the engagement workspace, e.g., `"analysis/chipset-memory-layout.txt"`

The `evidence` array must contain at least one entry per `finding.schema.json`. If research is the primary basis for a finding, the source URLs are mandatory evidence — not optional.

---

## Constraints

- **Read-only:** research tools (`WebSearch`, `deep-research`) fetch public information. Do not use research mode as cover for active enumeration of the target.
- **In-scope:** research may only inform findings on assets listed in the targets file. Do not pivot to out-of-scope assets based on research results.
- **Time-bounded:** research per candidate should not exceed the time budget set by the orchestrator. If the question cannot be resolved with one WebSearch pass and one `deep-research` invocation, flag the candidate with a `theoretical` likelihood weight and return it to the queue for human review.
- **No fabrication:** if research returns no usable results, do not invent CWE IDs, technique IDs, or CVE references. Leave the field as an empty array or note the gap in `evidence`.
