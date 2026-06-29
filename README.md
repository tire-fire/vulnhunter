# Vulnhunter

Orchestrated firmware and live-target vulnerability hunting plugin for Claude Code. Automatically enumerate attack surfaces, prioritize findings, dispatch specialized vulnerability-hunting chains, validate discoveries, and generate CWE/ATT&CK/CVSS-classified bug-bounty reports.

## Install

Add the marketplace source:

```bash
claude plugin marketplace add /home/tirefire/vulnhunter
```

Install the plugin:

```bash
claude plugin install vulnhunter@vulnhunter
```

## Usage

Vulnhunter requires an `engagement.yaml` configuration file that describes the target scope, vulnerability preferences, and reporting options.

The orchestrator is invoked via the `attack-orchestrator` skill — ask Claude to run it and supply the path to your engagement file and target:

> "Run the attack-orchestrator skill with engagement.yaml and target firmware.bin"

Or invoke it directly in Claude Code via the Skill tool with the `attack-orchestrator` skill name. The engagement configuration drives all hunting phases: surface enumeration, prioritization, chain dispatch, validation, and report generation.

**Note:** The `claude plugin marketplace add` path in the install section is an example. Replace `/home/tirefire/vulnhunter` with the actual path of your clone.

## Tooling

### Required
- `jq`: JSON validation and transformation
- Python 3.8+: orchestration logic, attack-surface parsing

### Optional
- `nmap`: Live-target network enumeration
- `binwalk`: Firmware extraction and analysis
- `ghidra`: Binary decompilation (via Ghidra headless)

See `scripts/setup.sh` for environment initialization.

### Sandbox prerequisite

The sandboxed execution harness (`scripts/sandbox.sh`) uses `bwrap`. On most Linux systems this requires unprivileged user namespaces to be enabled:

```bash
# verify
sysctl kernel.unprivileged_userns_clone   # should be 1
# enable if not (requires root, survives reboot via sysctl.d)
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

Systems where user namespaces are disabled will fail the sandbox containment checks; all other functionality remains available.

## Attribution

Vulnhunter builds on staged-validation, JSON-artifact-handoff, sandboxing, and attack-surface-mapping patterns from [RAPTOR](https://github.com/gadievron/raptor) (MIT license). Credit to gadievron for research infrastructure design.
