# GTI Agentic Sessions Lite (`gti_agentic_lite`)

A standalone, lightweight Python CLI tool for interacting with VirusTotal Google Threat Intelligence (GTI) Agentic Chat Sessions (`/api/v3/agentspace/sessions`).

> [!NOTE]
> **Public Preview Feature**: The Google Threat Intelligence Agentic Chat Sessions API (`/api/v3/agentspace/sessions`) is currently in Public Preview. Your VirusTotal / GTI account or API key must be enrolled in the Agentic Platform preview program to access these endpoints. An `HTTP 401 Unauthorized` error indicates that the provided API key does not yet have preview access enabled.

---

## Installation

Ensure Python 3.8+ is installed. Install the minimal dependencies:

```bash
pip install -r requirements.txt
```

---

## Setup API Key

You can provide your VirusTotal / Google Threat Intelligence API key in any of the following ways:
1. `--key KEY` or `-k KEY` flag on the command line (can be placed before or after subcommands, e.g. `python3 gti_agentic_lite.py list --key KEY`). Passing `--key` without a value triggers a secure interactive terminal password prompt.
2. Set the `VT_APIKEY` or `GTI_APIKEY` environment variable:
   ```bash
   export VT_APIKEY="your-api-key-here"
   ```
3. A standard `.gtirc` or `.api-credentials/googleti-api-credentials.json` file in your home directory or project directory.

---

## 🖥️ Interactive Session Manager

Run the script with no arguments (or run `list` without `--no-interactive`) to launch the full **Interactive Session Manager**:

```bash
python3 gti_agentic_lite.py
```

### Main Console Menu
From the interactive session list, you can choose:
* **`[1-N]` Select a Session**: View full session details and conversation event history (`USER_MESSAGE` and `AGENT_FINAL_RESPONSE` widgets).
* **`[n]` Post a Message to Create a New Session**: Interactively prompt for a message and optional file attachments (`multipart/form-data`) to start a brand-new agentic conversation.
* **`[r]` Refresh**: Reload the list of active sessions.
* **`[q]` Quit**: Exit the interactive console.

### Selected Session Sub-Menu
When inspecting a session (`[1-N]`), you can perform in-session operations:
* **`[c]` Continue Session**: Post a follow-up message and optional attachments directly to this session.
* **`[d]` Delete Session**: Interactively confirm and permanently delete the session.
* **`[t]` Get Share Token**: Retrieve the session share token.
* **`[b]` Back**: Return to the session list console.

---

## ⚡ Non-Interactive CLI Commands

All 8 API operations can also be executed directly via command-line arguments:

| Command | Description | Example |
| :--- | :--- | :--- |
| `list` | List chat sessions (launches interactive manager unless `--no-interactive` or `--raw` is set) | `python3 gti_agentic_lite.py list --limit 10` |
| `get` | Get session details by ID directly | `python3 gti_agentic_lite.py get <session_id>` |
| `get-token` | Get a share token for a session | `python3 gti_agentic_lite.py get-token <session_id>` |
| `create-from-token` | Import/create a session from a shared token | `python3 gti_agentic_lite.py create-from-token --token <token>` |
| `create` | Post a message to create a new session | `python3 gti_agentic_lite.py create -m "Analyze hash..." -f ./sample.exe` |
| `post` | Continue an existing chat session with a message | `python3 gti_agentic_lite.py post <session_id> -m "What are the IOCs?"` |
| `update` | Patch session view state (`--seen` or `--unseen`) | `python3 gti_agentic_lite.py update <session_id> --seen` |
| `delete` | Delete a session by ID | `python3 gti_agentic_lite.py delete <session_id>` |

---

## Global Options

* `--key [KEY]`, `-k [KEY]`: API Key (overrides env/file credentials). Can be placed before or after subcommand. Omit value for secure interactive prompt.
* `--no-interactive`: Disable the interactive session selection prompt when running `list`.
* `--raw`: Output compact, unformatted JSON (ideal for piping to `jq`).
* `--debug`: Enable verbose request logging.
* `-h, --help`: Display help and usage information.
