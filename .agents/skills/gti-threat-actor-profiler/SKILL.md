---
name: gti-threat-actor-profiler
description: Threat actor attribution, intrusion set tracking, campaign timelines, ransomware extortion trends, and sector threat landscape analysis using Google Threat Intelligence.
category: security
personas:
  - cti_analyst
  - threat_hunter
  - security_leader
---

# GTI Threat Actor Profiler & Landscape Intelligence

This skill structures investigations into nation-state intrusion sets, cybercrime syndicates, ransomware operations, and industry threat profiles using Google Threat Intelligence.

---

## When to Use This Skill

Activate this skill when:
- Building an intelligence dossier on a specific threat actor (e.g. APT28, APT29, UNC3886, FIN7, Volt Typhoon, Scattered Spider).
- Comparing two threat actors (TTP overlap, tooling, infrastructure, targeted verticals).
- Tracking ransomware trends, active extortion syndicates, and targeted victim demographics.
- Generating regional or industry sector threat landscape reports (e.g., Financial Services, Defense Industrial Base, Healthcare).
- Investigating high-profile third-party breaches, supply chain attacks, or major infrastructure outages.

---

## Core GTI Skills Activated

This skill targets the following underlying GTI Agentic engines:
- `threat_actor_analysis`: In-depth actor profile, TTPs, tooling, and campaign timelines.
- `profile_threat_landscape`: Comprehensive sector and geographic threat landscapes.
- `ransomware_analysis`: Extortion group tracking, leak site monitoring, and victim statistics.
- `third_party_incident_investigation`: Third-party breach and supply chain investigations.
- `daily_report_digest`: Synthesize recent intelligence feeds and reports.
- `ttp_to_entities`: Map MITRE techniques to threat groups.

---

## Workflow & Query Examples

1. **Threat Actor Profile & Tooling**:
   ```python
   ask_gti_agent(query="Provide a comprehensive profile of threat actor Volt Typhoon, including known C2 infrastructure patterns, living-off-the-land techniques, and recent operational campaigns.")
   ```

2. **Actor Comparison**:
   ```python
   ask_gti_agent(query="Compare APT29 and APT28 in terms of targeted sectors, spearphishing methodologies, and credential access techniques.")
   ```

3. **Ransomware Landscape**:
   ```python
   ask_gti_agent(query="What ransomware groups have been most active in the semiconductor manufacturing sector over the past 90 days? Summarize their primary initial access vectors.")
   ```

4. **Industry Threat Landscape**:
   ```python
   ask_gti_agent(query="Generate an executive threat landscape overview for the Energy and Critical Infrastructure sector in North America.")
   ```
