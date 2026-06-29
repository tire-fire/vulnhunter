# Attack Taxonomy: CWE Assignment and MITRE ATT&CK Mapping

This reference governs how agents assign CWE weakness classes to findings and map them to MITRE ATT&CK technique IDs. Three distinct taxonomies are in play; keep them separate:

- **CWE** (Common Weakness Enumeration) — classifies the *vulnerability* (the flaw in the code).
- **MITRE ATT&CK** — classifies the *adversary behavior* (what an attacker does with the flaw).
- **CVSS** — quantifies *severity* (see `references/cvss.md`).

A finding records all three. CWE identifies what is broken; ATT&CK technique IDs describe how an attacker would operationalize it.

---

## ID Formats Enforced by finding.schema.json

- CWE ids must match `^CWE-[0-9]+$` — e.g., `CWE-787`, `CWE-78`.
- ATT&CK technique ids must match `^T[0-9]{4}(\.[0-9]{3})?$` — e.g., `T1203`, `T1059.004`, `T0822`.
- Both fields are arrays; a finding may carry more than one CWE or ATT&CK ID when multiple weaknesses or behaviors apply.

---

## Part 1 — Assigning CWE Classes

Assign the **most specific** applicable CWE. If a finding is a stack buffer overflow, assign CWE-121, not the parent CWE-119.

### Memory Safety

| CWE | Name | Assign when |
|---|---|---|
| CWE-119 | Improper Restriction of Operations within the Bounds of a Memory Buffer | Use only if the exact direction (read vs write) or stack/heap is undetermined |
| CWE-120 | Buffer Copy without Checking Size of Input | `strcpy`, `sprintf`, or equivalent copies user-controlled data into a fixed buffer without length validation |
| CWE-121 | Stack-based Buffer Overflow | Overflow is into a stack-allocated array (confirmed by disassembly or source inspection) |
| CWE-122 | Heap-based Buffer Overflow | Overflow is into a heap-allocated region (`malloc`/`new`) |
| CWE-125 | Out-of-bounds Read | Index or pointer reads past the end or before the start of a buffer; no write primitive |
| CWE-787 | Out-of-bounds Write | Index or pointer writes past buffer bounds; includes heap overflows where the write is the primary primitive |
| CWE-190 | Integer Overflow or Wraparound | An arithmetic expression wraps (signed or unsigned) and the result is used as an allocation size, index, or length |

### Injection

| CWE | Name | Assign when |
|---|---|---|
| CWE-78 | OS Command Injection | Attacker-controlled data is concatenated into a shell command string passed to `system()`, `popen()`, or equivalent |
| CWE-89 | SQL Injection | Attacker-controlled data is interpolated into a SQL query without parameterization |
| CWE-79 | Cross-site Scripting (XSS) | Attacker-supplied HTML/JS is reflected or stored and rendered in a victim's browser without escaping |

### Access Control and Authentication

| CWE | Name | Assign when |
|---|---|---|
| CWE-306 | Missing Authentication for Critical Function | A sensitive endpoint or function is reachable without any credential check |
| CWE-352 | Cross-site Request Forgery (CSRF) | A state-changing request can be issued by a third-party origin because no CSRF token or SameSite cookie policy is enforced |
| CWE-798 | Use of Hard-coded Credentials | Credentials (password, key, token, certificate) appear as literals in firmware, source, or compiled binary |

### File and Path

| CWE | Name | Assign when |
|---|---|---|
| CWE-22 | Path Traversal | Attacker-controlled `../` sequences (or equivalent) can escape an intended directory boundary |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | A file-upload endpoint accepts executable or otherwise dangerous MIME types without validation |

### Network / Service

| CWE | Name | Assign when |
|---|---|---|
| CWE-918 | Server-side Request Forgery (SSRF) | The server fetches a URL or socket target that is attacker-controlled, potentially reaching internal services |

---

## Part 2 — Mapping CWE to MITRE ATT&CK Technique IDs

### Enterprise ATT&CK Matrix (for IT / web / network targets)

| CWE(s) | Most Likely Enterprise Technique(s) | Rationale |
|---|---|---|
| CWE-119, CWE-120, CWE-121, CWE-122, CWE-787, CWE-190 | T1203 (Exploitation for Client Execution) | Memory corruption used to gain code execution; T1203 covers exploitation of software vulnerabilities for execution |
| CWE-125 | T1005 (Data from Local System) | Out-of-bounds reads leak in-process data to the attacker |
| CWE-78 | T1059.004 (Command and Scripting Interpreter: Unix Shell), T1059.003 (Windows Command Shell) | OS command injection directly invokes a shell interpreter |
| CWE-89 | T1190 (Exploit Public-Facing Application) | SQLi is an application-layer exploit; may also enable T1005 if query results are returned |
| CWE-79 | T1059.007 (JavaScript), T1185 (Browser Session Hijacking) | Stored/reflected XSS executes attacker JavaScript and can steal session cookies |
| CWE-352 | T1185 (Browser Session Hijacking) | CSRF hijacks an authenticated browser session to perform actions as the victim |
| CWE-306 | T1078 (Valid Accounts) | Absence of auth grants the same access as a legitimate account; also consider T1190 if it's a network-exposed service |
| CWE-798 | T1552.001 (Unsecured Credentials: Credentials in Files) | Hardcoded credentials are a static credential stored in a file or binary |
| CWE-22 | T1083 (File and Directory Discovery), T1005 (Data from Local System) | Path traversal enables directory listing (T1083) and then file exfiltration (T1005) |
| CWE-434 | T1505.003 (Server Software Component: Web Shell) | Unrestricted upload commonly delivers a web shell enabling persistent execution |
| CWE-918 | T1090 (Proxy), T1552.005 (Cloud Instance Metadata API) | SSRF turns the server into an internal proxy; against cloud targets it commonly reaches the IMDS endpoint for credential theft |

### ICS / OT ATT&CK Matrix (for firmware, PLC, SCADA, embedded targets)

Use ICS techniques (`T0xxx`) instead of or in addition to Enterprise techniques when the target is firmware on an embedded system, a PLC, an RTU, a HMI, or industrial protocol stack.

| CWE(s) | ICS Technique(s) | Rationale |
|---|---|---|
| CWE-119, CWE-121, CWE-122, CWE-787 | T0853 (Scripting), T0839 (Module Firmware) | Memory corruption in firmware can be used to inject malicious firmware modules |
| CWE-798 | T0812 (Default Credentials) | Hardcoded credentials in ICS devices are often factory-default style; T0812 is the ICS-matrix parallel |
| CWE-306 | T0822 (External Remote Services) | Missing auth on a remote-accessible ICS service (Modbus, EtherNet/IP, OPC-UA) directly enables T0822 |
| CWE-78 | T0853 (Scripting) | Command injection in device management interfaces enables script execution on the controller |
| CWE-22 | T0845 (Program Upload) | Path traversal against a PLC's file interface can exfiltrate ladder-logic programs |
| CWE-434 | T0839 (Module Firmware) | Unrestricted file upload to a firmware update endpoint allows loading of malicious firmware |
| CWE-125 | T0802 (Automated Collection) | OOB read from process-value memory can leak sensor readings or PLC state |
| CWE-190 | T0836 (Modify Parameter) | Integer overflow in setpoint or parameter parsing can corrupt control parameters |
| CWE-918 | T0883 (Internet Accessible Device) | SSRF against an ICS device can pivot to internally-networked PLCs that should not be internet-reachable |

**Rule for firmware/PLC targets:** always check whether an ICS technique applies before defaulting to an Enterprise technique. Include both if both characterize the behavior (e.g., `["T1203","T0839"]`).

---

## Part 3 — Mapping Procedure

1. Identify the vulnerable code construct (sink, API, pattern).
2. Select the most specific CWE from Part 1. Add a secondary CWE only if a distinct weakness co-exists (e.g., CWE-190 causing CWE-122 — list both).
3. For each CWE, look up the corresponding row in Part 2. Select the technique(s) that best describe what an attacker *does* with this weakness, not what the weakness *is*.
4. If the target is in scope as an ICS/firmware asset (per `targets.json`), apply the ICS matrix first; include Enterprise IDs only if they describe additional post-exploitation behavior.
5. Write technique IDs into `attack_techniques` array in the finding. IDs must be exact: four digits after `T` for base techniques, three additional digits after a period for sub-techniques (e.g., `T1059.004`, not `T1059.4`).
6. Do not include ATT&CK tactic labels in the schema field — technique IDs only.

### Techniques Not Covered Above

If a sink maps to no CWE in this table (e.g., a protocol-specific deserialization flaw, a novel cryptographic weakness), consult `references/novel-research.md` before assigning a CWE or technique. Do not assign `CWE-0` or `T0000` as placeholders.
