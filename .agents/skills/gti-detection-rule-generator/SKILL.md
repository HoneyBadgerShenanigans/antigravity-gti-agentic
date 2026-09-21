---
name: gti-detection-rule-generator
description: Generate high-fidelity detection rules (YARA, Google SecOps YARA-L 2.0, SIGMA, and KQL) for threat actors, malware samples, and attack behaviors using Google Threat Intelligence.
category: security
personas:
  - detection_engineer
  - soc_analyst
  - threat_hunter
---

# GTI Detection Rule Generator

This skill automates the creation of high-fidelity detection rules across multiple SIEM, EDR, and scanning platforms using Google Threat Intelligence.

---

## When to Use This Skill

Activate this skill when:
- Writing new standard **YARA** rules to detect malware binaries, scripts, or suspicious file structures.
- Writing **YARA-L 2.0** detection rules for Google SecOps / Chronicle SIEM based on UDM events or threat actor TTPs.
- Writing **SIGMA** rules for cross-platform log-based detection of attack techniques.
- Writing **KQL** (Kusto Query Language) queries for Microsoft Sentinel / Defender logs.
- Researching existing community or vendor detection rules (`detection_rule_research`) for a known malware family or threat actor.

---

## Core GTI Skills Activated

This skill targets the following underlying GTI Agentic engines:
- `yara_rule_generation`: Generates standard YARA rules by analyzing entity structural indicators and testing uniqueness against benign corpuses.
- `yaral_rule_generation`: Generates YARA-L 2.0 rules for Google SecOps / Chronicle SIEM.
- `sigma_rule_generation`: Generates log-based SIGMA detection rules.
- `kql_query_generation`: Generates KQL queries for log analysis.
- `detection_rule_research`: Finds existing community and GTI detection rules.

---

## Workflow & Query Examples

1. **YARA-L 2.0 for Google SecOps**:
   ```python
   ask_gti_agent(query="Generate a YARA-L 2.0 rule for Google SecOps detecting lateral movement via PsExec utilizing suspicious service creation events.")
   ```

2. **Standard YARA Rule Generation**:
   ```python
   ask_gti_agent(query="Generate a robust YARA rule for hash 1e806ce2fe77671b20c433f6f2088604d7e6addb6dbbb707e7f8bd86c7f573fb with measurable strings that avoid false positives on clean files.")
   ```

3. **SIGMA Rule for Behavioral TTPs**:
   ```python
   ask_gti_agent(query="Generate a SIGMA rule detecting scheduled task creation used for persistence by threat actor Volt Typhoon.")
   ```

4. **Rule Research**:
   ```python
   ask_gti_agent(query="Find existing YARA and Sigma rules in GTI for detecting Cobalt Strike Beacon version 4.9.")
   ```
