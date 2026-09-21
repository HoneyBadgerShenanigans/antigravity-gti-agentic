# Google Threat Intelligence (GTI) Agentic Integration

This repository provides a unified integration for **Google Threat Intelligence (GTI) Agentic Chat Sessions**, enabling interactive, multi-turn AI threat investigations through both **Antigravity (via Remote MCP)** and a **standalone terminal CLI/TUI (`gti_agentic_lite`)**.

---

## Architecture Overview

```
                       ┌──────────────────────────────────────────────┐
                       │ Google Threat Intelligence (GTI) Agentspace  │
                       │    https://www.virustotal.com/api/v3/        │
                       └──────────────────────┬───────────────────────┘
                                              │
                     ┌────────────────────────┴────────────────────────┐
                     ▼                                                 ▼
      Remote MCP Server Endpoint                        REST Sessions API Endpoint
      /api/v3/agentspace/mcp/                           /api/v3/agentspace/sessions
                     │                                                 │
                     ▼                                                 ▼
      ┌─────────────────────────────┐                  ┌──────────────────────────────┐
      │   Antigravity AI Assistant  │                  │   gti_agentic_lite (CLI/TUI) │
      │  (Interactive Pair Chat &   │                  │  (Local Terminal, Automation,│
      │   Autonomous Investigation) │                  │   Piping, Scripted Scans)    │
      └──────────────┬──────────────┘                  └───────────────┬──────────────┘
                     │                                                 │
                     └──────────────── Shared Session ID ──────────────┘
```

Both integration methods communicate with the same underlying VirusTotal / GTI Agentic backend. A session created inside Antigravity can be inspected or resumed in `gti_agentic_lite`, and vice versa.

---

## Requirements

1. **Google Threat Intelligence License**: Enterprise or Enterprise Plus license enrolled in the Agentic Platform preview program.
2. **GTI / VirusTotal API Key**: Your personal or service account API key.
3. **Python 3.8+** (for local CLI tooling).

---

## Quickstart

### 1. Configure Your API Key
Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```
Edit `.env` and set your API key:
```bash
VT_APIKEY="your-virustotal-or-gti-api-key-here"
```
*(Alternatively, you can export `export VT_APIKEY="your-key"` in your shell or use `~/.gtirc`)*.

### 2. Connect Antigravity to the Remote MCP Server
Run the setup script to register the GTI Agentic MCP server with Antigravity:
```bash
python3 setup_mcp.py
```
This merges the following configuration into your Antigravity MCP settings:
```json
{
  "mcpServers": {
    "gti-agentic": {
      "serverUrl": "https://www.virustotal.com/api/v3/agentspace/mcp/",
      "headers": {
        "x-apikey": "<YOUR_API_KEY>"
      }
    }
  }
}
```

Once reloaded, Antigravity has native access to the GTI Agentic tool suite:
* `ask_gti_agent`: Start a new investigation in natural language.
* `continue_chat`: Follow up within an active investigation session.
* `list_sessions`: List active and historical investigation sessions.
* `get_session_history`: Retrieve full event transcripts and widgets.
* `delete_session`: Delete sessions.
* `share_session` / `copy_shared_session`: Share or fork investigation sessions.

### 3. Install Python CLI Dependencies
```bash
pip install -r gti_agentic_lite/requirements.txt
```

---

## Usage

### Mode A: In Antigravity (Interactive Agentic Pair Chat)
You can prompt Antigravity directly in the chat with natural language security investigations:

- **Threat Hunting & File Queries**:
  - *"Show me the 5 most recent files submitted to VirusTotal with more than 50 detections."*
  - *"Analyze the file hash `1e806ce2fe77671b20c433f6f2088604d7e6addb6dbbb707e7f8bd86c7f573fb` with VirusTotal MCP and summarize detections and behavior."*
- **Domain & Infrastructure Intelligence**:
  - *"Get the domain report for `example-malicious-domain.com` using the GTI MCP server."*
  - *"Investigate domain `update-check-service.com` with GTI and check if it's tied to any known C2 profiles."*
- **Threat Actor & Campaign Deep Dives**:
  - *"Ask GTI agent about the latest infrastructure and campaigns associated with threat actor APT29."*
  - *"Pivot on the IP address returned in that session and ask GTI for other observed certificates or communicating files."* (Antigravity will automatically use `continue_chat` with the session ID).


### Mode B: Standalone Terminal Manager (`gti_agentic_lite`)
Launch the interactive terminal session manager:
```bash
python3 gti_agentic_lite/gti_agentic_lite.py
```

Or run non-interactive CLI commands:
```bash
# List recent sessions
python3 gti_agentic_lite/gti_agentic_lite.py list --limit 10

# Start a new session with an initial prompt
python3 gti_agentic_lite/gti_agentic_lite.py create -m "Analyze malicious hash 4a2b..."

# Continue an existing session
python3 gti_agentic_lite/gti_agentic_lite.py post <session_id> -m "What are the related domains?"

# Retrieve details of a session
python3 gti_agentic_lite/gti_agentic_lite.py get <session_id>

# Export / generate a share token
python3 gti_agentic_lite/gti_agentic_lite.py get-token <session_id>
```

---

## Repository Structure

```
.
├── .env.example                                  # Environment variables template
├── .gitignore                                    # Git exclusion rules
├── mcp_config.template.json                      # Antigravity MCP server template
├── setup_mcp.py                                  # Helper script to configure Antigravity MCP
├── .agents/
│   └── skills/
│       ├── gti-agentic-investigator/             # Master capability orchestrator (43 GTI skills)
│       ├── gti-dark-web-hunter/                  # Deep & dark web (DDW), forums, messaging, leaks
│       ├── gti-detection-rule-generator/         # YARA, YARA-L 2.0 (SecOps), SIGMA, KQL rules
│       ├── gti-malware-reverse-engineer/         # Binary reversing, PowerShell emulation, APK, .NET
│       └── gti-threat-actor-profiler/            # Actor profiles, campaigns, ransomware, landscapes
├── gti_agentic_lite/                             # Standalone Python CLI & TUI
│   ├── gti_agentic_lite.py                       # CLI script supporting all 8 session endpoints
│   ├── requirements.txt                          # Minimal dependencies (requests)
│   └── README.md                                 # gti_agentic_lite detailed docs
└── README.md                                     # Project overview and quickstart guide
```

---

## Troubleshooting

- **HTTP 401 Unauthorized**: Ensure your API key is valid and has been enrolled in the GTI Agentic Platform preview program.
- **MCP Server Connection**: Verify that your Antigravity client can reach `https://www.virustotal.com/api/v3/agentspace/mcp/` and that the `x-apikey` header is set properly.
- **Session Continuity**: When conducting a multi-turn investigation, ensure you pass the same `session_id` using `continue_chat` (in Antigravity) or `post <session_id>` (in CLI).
