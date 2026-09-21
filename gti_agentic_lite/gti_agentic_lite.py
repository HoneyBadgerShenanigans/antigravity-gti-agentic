#!/usr/bin/env python3
"""
GTI Agentic Sessions Lite (`gti_agentic_lite.py`)
=================================================
A zero-config, standalone lightweight Python script to interact with the
Google Threat Intelligence (GTI) Agentic Chat Sessions API.

Supports all 8 Session capabilities both via CLI subcommands and an interactive menu:
  1. List sessions (GET /api/v3/agentspace/sessions) with interactive menu
  2. Get a session (GET /api/v3/agentspace/sessions/{session_id})
  3. Get a session share token (GET /api/v3/agentspace/sessions/{session_id}/token)
  4. Create a session from a shared token (POST /api/v3/agentspace/sessions/token)
  5. Post a message to a new session (POST /api/v3/agentspace/sessions)
  6. Post a message to an existing session (POST /api/v3/agentspace/sessions/{session_id})
  7. Update a session view state (PATCH /api/v3/agentspace/sessions/{session_id})
  8. Delete a session (DELETE /api/v3/agentspace/sessions/{session_id})

Usage:
  python3 gti_agentic_lite.py                           # Interactive Session Manager
  python3 gti_agentic_lite.py list [--limit 5]          # List & interactive menu
  python3 gti_agentic_lite.py get <session_id>
  python3 gti_agentic_lite.py get-token <session_id>
  python3 gti_agentic_lite.py create-from-token --token <token>
  python3 gti_agentic_lite.py create -m "Analyze hash 4a2b..." [-f file1]
  python3 gti_agentic_lite.py post <session_id> -m "What are the IOCs?" [-f file1]
  python3 gti_agentic_lite.py update <session_id> (--seen | --unseen)
  python3 gti_agentic_lite.py delete <session_id>
"""

import sys
import os
import json
import argparse
import time
import getpass
import requests

BASE_URL = "https://www.virustotal.com/api/v3/agentspace/sessions"


VALID_COMMANDS = {"list", "get", "get-token", "create-from-token", "create", "post", "update", "delete"}


def get_api_key(key_override=None):
    """Resolve API key from override flag, environment variables, or standard credential files."""
    if isinstance(key_override, str) and key_override.strip() and key_override.strip() not in VALID_COMMANDS:
        return key_override.strip()

    for env_var in ["VT_APIKEY", "VT_API_KEY", "GTI_APIKEY", "GTI_API_KEY"]:
        val = os.environ.get(env_var)
        if val:
            return val.strip()

    # Try .env file
    for env_path in [".env", os.path.join(os.path.dirname(__file__), ".env"), os.path.join(os.path.dirname(__file__), "..", ".env")]:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or not line or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        if k.strip() in ["VT_APIKEY", "VT_API_KEY", "GTI_APIKEY", "GTI_API_KEY"]:
                            return v.strip().strip("'\"")
            except Exception:
                pass
    
    # Try local credentials file
    creds_paths = [
        os.path.expanduser("~/.gtirc"),
        ".api-credentials/googleti-api-credentials.json",
        os.path.expanduser("~/.api-credentials/googleti-api-credentials.json")
    ]
    for p in creds_paths:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        key = data.get("api_key") or data.get("apikey") or data.get("VT_APIKEY")
                        if key:
                            return key.strip()
            except Exception:
                pass

    if key_override is True or (isinstance(key_override, str) and key_override.strip() in VALID_COMMANDS):
        try:
            val = getpass.getpass("Enter VirusTotal / GTI API Key: ").strip()
            if val:
                return val
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(1)

    return None


def print_output(data, raw=False):
    """Format and display raw/pretty output."""
    if raw:
        print(json.dumps(data))
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


def print_session_details(data, raw=False):
    """Format and display human-readable details and event history of a session."""
    if raw:
        print_output(data, raw=True)
        return
    
    session_data = data.get("data", {})
    if isinstance(session_data, list) and len(session_data) > 0:
        session_data = session_data[0]
    
    sess_id = session_data.get("id", "Unknown")
    attrs = session_data.get("attributes", {})
    title = attrs.get("title", "Untitled Session")
    created = attrs.get("creation_date", "N/A")
    last_mod = attrs.get("last_modification_date", "N/A")
    seen = attrs.get("seen", "N/A")
    events = attrs.get("events", [])

    print(f"\n{'='*80}")
    print(f"SESSION DETAILS: {title}")
    print(f"{'='*80}")
    print(f"ID                     : {sess_id}")
    print(f"Created Date           : {created}")
    print(f"Last Modification Date : {last_mod}")
    print(f"Seen Status            : {seen}")
    print(f"{'-'*80}")
    print("CONVERSATION EVENTS:")
    print(f"{'-'*80}")

    if not events:
        print("  (No events recorded in this session)")
    else:
        for idx, event in enumerate(events, 1):
            msg_type = event.get("message_type", "EVENT")
            user_msg = event.get("user_message", {})
            agent_resp = event.get("agent_final_response", {})
            
            if msg_type == "USER_MESSAGE" or user_msg:
                widgets = user_msg.get("widgets", [])
                text_list = []
                for w in widgets:
                    text_list.append(w.get("markdown_text_widget", {}).get("text", ""))
                text_str = "\n".join(text_list) or "(Empty message)"
                print(f"\n[{idx}] USER MESSAGE:")
                print(f"    {text_str.replace('\n', '\n    ')}")
            
            elif msg_type == "AGENT_FINAL_RESPONSE" or agent_resp:
                agent_id = agent_resp.get("agent_id", "agent")
                widgets = agent_resp.get("widgets", [])
                text_list = []
                for w in widgets:
                    text_list.append(w.get("markdown_text_widget", {}).get("text", ""))
                text_str = "\n".join(text_list) or "(Empty response)"
                print(f"\n[{idx}] AGENT RESPONSE ({agent_id}):")
                print(f"    {text_str.replace('\n', '\n    ')}")
            
            else:
                print(f"\n[{idx}] [{msg_type}]: {json.dumps(event)}")

    print(f"\n{'='*80}\n")


SENSITIVE_FILE_PATTERNS = {".env", "id_rsa", "id_ed25519", "credentials.json"}
SENSITIVE_FILE_EXTENSIONS = {".key", ".pem", ".p12", ".pfx", ".secret"}


def prepare_files_payload(message, file_paths):
    """Helper to construct multipart form data for message and optional file attachments."""
    open_files = []
    files_payload = [('message', (None, message))]
    if file_paths:
        for fp in file_paths:
            fp = fp.strip()
            if not fp:
                continue
            base = os.path.basename(fp).lower()
            if base in SENSITIVE_FILE_PATTERNS or any(base.endswith(ext) for ext in SENSITIVE_FILE_EXTENSIONS) or "credential" in base:
                raise ValueError(f"Security Protection: Refusing to upload sensitive file '{fp}' to an external service.")
            if not os.path.exists(fp):
                raise FileNotFoundError(f"File not found: {fp}")
            f_obj = open(fp, "rb")
            open_files.append(f_obj)
            files_payload.append(('files', (os.path.basename(fp), f_obj)))
    return files_payload, open_files



def interactive_create_new_session(headers):
    """Interactive flow to post a message and create a new session."""
    print("\n--- [1] CREATE A NEW CHAT SESSION ---")
    message = input("Enter your message to start the new session: ").strip()
    if not message:
        print("Message cannot be empty. Operation cancelled.")
        return None
    
    files_input = input("Attach file path(s) (optional, comma-separated, or press Enter to skip): ").strip()
    file_paths = [x for x in files_input.split(",") if x.strip()] if files_input else []
    
    print("\nSending message to create new agentic session... (waiting for response)")
    open_files = []
    try:
        files_payload, open_files = prepare_files_payload(message, file_paths)
        resp = requests.post(BASE_URL, headers=headers, files=files_payload)
        resp.raise_for_status()
        data = resp.json()
        print("\nSession created successfully!")
        print_session_details(data)
        return data
    except Exception as e:
        print(f"Error creating new session: {e}", file=sys.stderr)
        return None
    finally:
        for f_obj in open_files:
            f_obj.close()


def interactive_continue_session(session_id, headers):
    """Interactive flow to continue an existing session by sending a new message."""
    print(f"\n--- [2] CONTINUE SESSION [{session_id}] ---")
    message = input("Enter your message: ").strip()
    if not message:
        print("Message cannot be empty. Operation cancelled.")
        return None
    
    files_input = input("Attach file path(s) (optional, comma-separated, or press Enter to skip): ").strip()
    file_paths = [x for x in files_input.split(",") if x.strip()] if files_input else []
    
    url = f"{BASE_URL}/{session_id}"
    print(f"\nSending message to session {session_id}... (waiting for response)")
    open_files = []
    try:
        files_payload, open_files = prepare_files_payload(message, file_paths)
        resp = requests.post(url, headers=headers, files=files_payload)
        resp.raise_for_status()
        data = resp.json()
        print("\nMessage delivered and response received!")
        print_session_details(data)
        return data
    except Exception as e:
        print(f"Error continuing session: {e}", file=sys.stderr)
        return None
    finally:
        for f_obj in open_files:
            f_obj.close()


def interactive_delete_session(session_id, headers):
    """Interactive flow to delete a session."""
    print(f"\n--- [3] DELETE SESSION [{session_id}] ---")
    confirm = input(f"Are you sure you want to permanently delete session {session_id}? (y/N): ").strip().lower()
    if confirm == 'y':
        url = f"{BASE_URL}/{session_id}"
        try:
            resp = requests.delete(url, headers=headers)
            resp.raise_for_status()
            print(f"\nSession {session_id} deleted successfully.")
            return True
        except Exception as e:
            print(f"Error deleting session: {e}", file=sys.stderr)
            return False
    else:
        print("Deletion cancelled.")
        return False


def run_interactive_session_menu(headers, limit=5):
    """Full-featured interactive session manager."""
    while True:
        url = BASE_URL
        params = {"limit": limit}
        try:
            resp = requests.get(url, headers=headers, params=params)
            resp.raise_for_status()
            res_data = resp.json()
        except Exception as e:
            print(f"Error fetching sessions: {e}", file=sys.stderr)
            return

        sessions_list = res_data.get("data", [])

        print(f"\n{'='*80}")
        print(f"GTI AGENTIC CHAT SESSIONS MANAGER ({len(sessions_list)} sessions listed)")
        print(f"{'='*80}")
        if not sessions_list:
            print("  (No sessions found)")
        else:
            for idx, sess in enumerate(sessions_list, 1):
                s_id = sess.get("id", "N/A")
                attrs = sess.get("attributes", {})
                title = attrs.get("title", "Untitled Session")
                created = attrs.get("creation_date", "N/A")
                seen = attrs.get("seen", "N/A")
                print(f"[{idx}] ID: {s_id}")
                print(f"    Title   : {title}")
                print(f"    Created : {created} | Seen: {seen}")
                print()
        print(f"{'='*80}")
        print("INTERACTIVE ACTIONS:")
        print("  [1-N] Select a session to view details / continue / delete")
        print("  [n]   Post a message to CREATE a NEW session")
        print("  [r]   Refresh session list")
        print("  [q]   Quit")
        print(f"{'-'*80}")

        try:
            choice = input("Choose an option: ").strip()
            if choice.lower() in ['q', 'quit', 'exit']:
                print("Exiting Session Manager.")
                break
            elif choice.lower() in ['r', 'refresh']:
                continue
            elif choice.lower() in ['n', 'new', 'create']:
                interactive_create_new_session(headers)
                input("\nPress Enter to return to the session list...")
                continue
            
            # Numeric choice: select existing session
            try:
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(sessions_list):
                    selected_sess = sessions_list[choice_idx]
                    selected_id = selected_sess.get("id")
                    
                    # Fetch and show details
                    detail_url = f"{BASE_URL}/{selected_id}"
                    detail_resp = requests.get(detail_url, headers=headers)
                    detail_resp.raise_for_status()
                    print_session_details(detail_resp.json())

                    # Sub-menu for selected session
                    while True:
                        print(f"SESSION MENU [{selected_id}]:")
                        print("  [c] Continue this session (post a new message)")
                        print("  [d] Delete this session")
                        print("  [t] Get share token")
                        print("  [b] Back to session list")
                        print("  [q] Quit")
                        sub_choice = input("Select action: ").strip().lower()
                        if sub_choice == 'c':
                            interactive_continue_session(selected_id, headers)
                        elif sub_choice == 'd':
                            if interactive_delete_session(selected_id, headers):
                                break # session deleted, back to main list
                        elif sub_choice == 't':
                            tok_resp = requests.get(f"{BASE_URL}/{selected_id}/token", headers=headers)
                            tok_resp.raise_for_status()
                            print("\nSHARE TOKEN RESPONSE:")
                            print_output(tok_resp.json())
                        elif sub_choice == 'b':
                            break
                        elif sub_choice in ['q', 'quit']:
                            return
                        else:
                            print("Invalid choice.")
                else:
                    print("Invalid session number.")
            except ValueError:
                print("Invalid input choice.")

        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break


def main():
    # Parent parser so common options (--key, --raw, --debug) work before or after subcommands
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--key", "-k", nargs="?", const=True,
        help="VirusTotal / GTI API Key (or set VT_APIKEY env var). Pass without a value for interactive prompt."
    )
    parent_parser.add_argument("--raw", action="store_true", help="Output compact raw JSON (ideal for piping to jq)")
    parent_parser.add_argument("--debug", action="store_true", help="Enable debug request logging")

    parser = argparse.ArgumentParser(
        description="GTI Agentic Sessions Lite - Standalone CLI for VirusTotal Google Threat Intelligence Agentic Chat Sessions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        parents=[parent_parser]
    )

    subparsers = parser.add_subparsers(dest="command", title="Commands", required=False)

    # 1. list
    list_parser = subparsers.add_parser("list", parents=[parent_parser], help="List agentic chat sessions with interactive menu")
    list_parser.add_argument("--limit", type=int, default=5, help="Maximum number of sessions per page (default: 5)")
    list_parser.add_argument("--cursor", type=str, help="Cursor token for pagination")
    list_parser.add_argument("--no-interactive", action="store_true", help="Disable interactive selection prompt after listing sessions")

    # 2. get
    get_parser = subparsers.add_parser("get", parents=[parent_parser], help="Get details for a specific session")
    get_parser.add_argument("session_id", help="Session ID")

    # 3. get-token
    token_parser = subparsers.add_parser("get-token", parents=[parent_parser], help="Get a share token for a session")
    token_parser.add_argument("session_id", help="Session ID")

    # 4. create-from-token
    from_token_parser = subparsers.add_parser("create-from-token", parents=[parent_parser], help="Create a new session from a shared token")
    from_token_parser.add_argument("--token", required=True, help="Session share token")

    # 5. create
    create_parser = subparsers.add_parser("create", parents=[parent_parser], help="Post a message to create a new agentic session")
    create_parser.add_argument("--message", "-m", required=True, help="User message to send to the agent")
    create_parser.add_argument("--file", "-f", action="append", dest="files", help="Optional file attachment(s) (can be repeated)")

    # 6. post
    post_parser = subparsers.add_parser("post", parents=[parent_parser], help="Post a message to an existing session")
    post_parser.add_argument("session_id", help="Session ID")
    post_parser.add_argument("--message", "-m", required=True, help="User message to send to the agent")
    post_parser.add_argument("--file", "-f", action="append", dest="files", help="Optional file attachment(s) (can be repeated)")

    # 7. update
    update_parser = subparsers.add_parser("update", parents=[parent_parser], help="Update session view state (seen/unseen)")
    update_parser.add_argument("session_id", help="Session ID")
    group = update_parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--seen", action="store_true", help="Mark session as seen")
    group.add_argument("--unseen", action="store_true", help="Mark session as unseen")

    # 8. delete
    delete_parser = subparsers.add_parser("delete", parents=[parent_parser], help="Delete a session by ID")
    delete_parser.add_argument("session_id", help="Session ID")

    args = parser.parse_args()

    if args.command is None and isinstance(args.key, str) and args.key in VALID_COMMANDS:
        args.command = args.key
        args.key = True

    api_key = get_api_key(args.key)
    if not api_key:
        print("ERROR: API Key is required. Provide via --key or VT_APIKEY environment variable.", file=sys.stderr)
        sys.exit(1)

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "x-tool": "gti-agentic-lite"
    }

    # If no subcommand is specified, default to full interactive Session Manager!
    if not args.command:
        run_interactive_session_menu(headers)
        return

    url = BASE_URL
    method = "GET"
    params = None
    json_data = None
    files_payload = None
    open_files = []

    try:
        if args.command == "list":
            if not getattr(args, 'no_interactive', False) and not args.raw:
                run_interactive_session_menu(headers, limit=getattr(args, 'limit', 5) or 5)
                return

            url = BASE_URL
            method = "GET"
            params = {}
            if getattr(args, 'limit', None):
                params["limit"] = args.limit
            if getattr(args, 'cursor', None):
                params["cursor"] = args.cursor

            if args.debug:
                print(f"DEBUG: {method} {url} Params: {params}", file=sys.stderr)

            resp = requests.get(url, headers=headers, params=params)
            resp.raise_for_status()
            res_data = resp.json()

            if args.raw:
                print_output(res_data, raw=True)
                return

            sessions_list = res_data.get("data", [])
            if not sessions_list:
                print("\nNo agentic chat sessions found.")
                return

            print(f"\n{'='*80}")
            print(f"AVAILABLE AGENTIC CHAT SESSIONS ({len(sessions_list)} retrieved)")
            print(f"{'='*80}")
            for idx, sess in enumerate(sessions_list, 1):
                s_id = sess.get("id", "N/A")
                attrs = sess.get("attributes", {})
                title = attrs.get("title", "Untitled Session")
                created = attrs.get("creation_date", "N/A")
                seen = attrs.get("seen", "N/A")
                print(f"[{idx}] ID: {s_id}")
                print(f"    Title   : {title}")
                print(f"    Created : {created} | Seen: {seen}")
                print()
            print(f"{'='*80}")
            return

        elif args.command == "get":
            url = f"{BASE_URL}/{getattr(args, 'session_id', '')}"
            method = "GET"

        elif args.command == "get-token":
            url = f"{BASE_URL}/{getattr(args, 'session_id', '')}/token"
            method = "GET"

        elif args.command == "create-from-token":
            url = f"{BASE_URL}/token"
            method = "POST"
            headers["Content-Type"] = "application/json"
            json_data = {"token": getattr(args, 'token', '')}

        elif args.command == "create":
            url = BASE_URL
            method = "POST"
            files_payload = [('message', (None, getattr(args, 'message', '')))]
            if getattr(args, 'files', None):
                for fp in args.files:
                    if not os.path.exists(fp):
                        print(f"ERROR: File not found: {fp}", file=sys.stderr)
                        sys.exit(1)
                    f_obj = open(fp, "rb")
                    open_files.append(f_obj)
                    files_payload.append(('files', (os.path.basename(fp), f_obj)))

        elif args.command == "post":
            url = f"{BASE_URL}/{getattr(args, 'session_id', '')}"
            method = "POST"
            files_payload = [('message', (None, getattr(args, 'message', '')))]
            if getattr(args, 'files', None):
                for fp in args.files:
                    if not os.path.exists(fp):
                        print(f"ERROR: File not found: {fp}", file=sys.stderr)
                        sys.exit(1)
                    f_obj = open(fp, "rb")
                    open_files.append(f_obj)
                    files_payload.append(('files', (os.path.basename(fp), f_obj)))

        elif args.command == "update":
            url = f"{BASE_URL}/{getattr(args, 'session_id', '')}"
            method = "PATCH"
            headers["Content-Type"] = "application/json"
            seen_val = False if getattr(args, 'unseen', False) else True
            json_data = {"data": {"seen": seen_val}}

        elif args.command == "delete":
            url = f"{BASE_URL}/{getattr(args, 'session_id', '')}"
            method = "DELETE"

        if args.debug:
            print(f"DEBUG: {method} {url}", file=sys.stderr)
            if params:
                print(f"DEBUG: Params: {params}", file=sys.stderr)
            if json_data:
                print(f"DEBUG: Payload: {json_data}", file=sys.stderr)

        if method == "GET":
            resp = requests.get(url, headers=headers, params=params)
        elif method == "POST":
            if files_payload is not None:
                resp = requests.post(url, headers=headers, files=files_payload)
            else:
                resp = requests.post(url, headers=headers, json=json_data)
        elif method == "PATCH":
            resp = requests.patch(url, headers=headers, json=json_data)
        elif method == "DELETE":
            resp = requests.delete(url, headers=headers)

        resp.raise_for_status()

        if method != "DELETE":
            if args.command == "get":
                print_session_details(resp.json(), raw=args.raw)
            else:
                print_output(resp.json(), raw=args.raw)
        else:
            if args.raw:
                print(json.dumps({"status": "deleted", "session_id": getattr(args, 'session_id', '')}))
            else:
                print(f"Successfully deleted session {args.session_id}")

    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "Unknown"
        print(f"HTTP Error ({status_code}): {e}", file=sys.stderr)
        if status_code == 401:
            print("\n[!] Authentication / Preview Access Error (HTTP 401):", file=sys.stderr)
            print("    1. Verify your API key is valid and entered accurately.", file=sys.stderr)
            print("    2. Google Threat Intelligence Agentic Chat Sessions (/api/v3/agentspace/sessions)", file=sys.stderr)
            print("       is currently in Public Preview. Your account or API key must be enrolled", file=sys.stderr)
            print("       in the Agentic Platform preview to access these endpoints.", file=sys.stderr)
        if e.response is not None and e.response.text:
            print(f"Response: {e.response.text}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error executing request: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for f_obj in open_files:
            f_obj.close()


if __name__ == "__main__":
    main()
