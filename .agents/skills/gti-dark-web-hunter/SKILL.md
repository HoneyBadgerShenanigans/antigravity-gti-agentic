---
name: gti-dark-web-hunter
description: Autonomous deep and dark web (DDW) threat intelligence investigations using Google Threat Intelligence across cybercrime forums, instant messaging channels (Telegram, Discord, Jabber), and paste sites.
category: security
personas:
  - threat_hunter
  - dark_web_analyst
  - incident_responder
---

# GTI Dark Web & Underground Intelligence Hunter

This skill orchestrates deep and dark web (DDW) threat intelligence investigations using Google Threat Intelligence.

---

## When to Use This Skill

Activate this skill when:
- Searching cybercrime forums, underground marketplaces, leak posts, and database dump discussions.
- Tracking threat actor chatter across instant messaging platforms (Telegram, Discord, Jabber/XMPP, WhatsApp, Matrix).
- Monitoring paste sites (Pastebin, Doxbin, GitHub/Gist snippets) and text sources (Reddit) for credential leaks or code drops.
- Correlating threat actor personas across multiple forums using shared identifiers (usernames, TOX IDs, Jabber handles, crypto wallet addresses, email addresses).
- Investigating brand mentions, executive threats, or unauthorized data exposures on the dark web.

---

## Core GTI Skills Activated

This skill targets the following underlying GTI Agentic engines:
- `ddw_dark_web_forums`: Forum posts, threads, and actor persona cross-correlation.
- `ddw_messenger`: Instant messaging platforms (Telegram channels, Discord servers, Jabber drops).
- `ddw_paste_web_content`: Paste-sites (Pastebin, Doxbin, Gists) and Reddit leaks.
- `digital_threat_monitoring`: Mentions of corporate brands, VIPs, or vulnerabilities.

---

## Workflow & Query Examples

1. **Cybercrime Forum Persona Tracking**:
   ```python
   ask_gti_agent(query="Search dark web forums for threat actor 'BravoHacker' and correlate their activity across forums using any observed Jabber or TOX handles.")
   ```

2. **Telegram / Discord Channel Chatter**:
   ```python
   ask_gti_agent(query="Search dark web Telegram channels and Discord drops for recent chatter regarding ransomware leaks targeting healthcare organizations.")
   ```

3. **Paste & Leak Dump Surveillance**:
   ```python
   ask_gti_agent(query="Search paste sites and Doxbin snippets for leaked credentials or API keys associated with domain 'company-target.com'.")
   ```

4. **Follow-Up Pivoting**:
   Use `continue_chat(session_id=..., message="What cryptocurrency wallet addresses or payment methods did this actor provide in these posts?")`.
