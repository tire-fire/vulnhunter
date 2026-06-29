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

Vulnhunter requires an `engagement.yaml` configuration file that describes the target scope, vulnerability preferences, and reporting options. The orchestrator is invoked via its skill:

```bash
claude vulnhunter
```

The engagement configuration drives all hunting phases: surface enumeration, prioritization, chain dispatch, validation, and report generation.

## Tooling

### Required
- `jq`: JSON validation and transformation
- Python 3.8+: orchestration logic, attack-surface parsing

### Optional
- `nmap`: Live-target network enumeration
- `binwalk`: Firmware extraction and analysis
- `ghidra`: Binary decompilation (via Ghidra headless)

See `scripts/setup.sh` for environment initialization.

## Attribution

Vulnhunter builds on staged-validation, JSON-artifact-handoff, sandboxing, and attack-surface-mapping patterns from [RAPTOR](https://github.com/gadievron/raptor) (MIT license). Credit to gadievron for research infrastructure design.
