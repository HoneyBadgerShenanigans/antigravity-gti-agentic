#!/usr/bin/env python3
"""
Setup script to configure Google Threat Intelligence (GTI) Agentic Remote MCP Server
in Antigravity configuration.
"""

import os
import sys
import json
import argparse
import getpass
from pathlib import Path


DEFAULT_SERVER_URL = "https://www.virustotal.com/api/v3/agentspace/mcp/"

CONFIG_LOCATIONS = [
    Path.home() / ".gemini" / "antigravity" / "mcp_config.json",
    Path.home() / ".gemini" / "config" / "mcp_config.json",
]


def resolve_api_key(key_override=None):
    if key_override:
        return key_override.strip()

    # Check env variables
    for var in ["VT_APIKEY", "GTI_APIKEY", "VT_API_KEY", "GTI_API_KEY"]:
        val = os.environ.get(var)
        if val:
            return val.strip()

    # Check .env file in current or parent dirs
    env_file = Path(".env")
    if env_file.exists():
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'\"")
                    if k in ["VT_APIKEY", "GTI_APIKEY", "VT_API_KEY", "GTI_API_KEY"]:
                        return v

    # Check ~/.gtirc
    gtirc = Path.home() / ".gtirc"
    if gtirc.exists():
        try:
            with open(gtirc, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    key = data.get("api_key") or data.get("apikey") or data.get("VT_APIKEY")
                    if key:
                        return key.strip()
        except Exception:
            pass

    return None


def main():
    parser = argparse.ArgumentParser(description="Configure GTI Agentic MCP Server for Antigravity")
    parser.add_argument("--key", "-k", help="Google Threat Intelligence / VirusTotal API Key")
    parser.add_argument("--server-url", default=DEFAULT_SERVER_URL, help="MCP Server URL")
    parser.add_argument("--target", help="Specific path to mcp_config.json")
    parser.add_argument("--dry-run", action="store_true", help="Print config without writing to disk")
    args = parser.parse_args()

    api_key = resolve_api_key(args.key)
    if not api_key:
        print("GTI API key not found in environment or .env.")
        try:
            api_key = getpass.getpass("Enter your GTI / VirusTotal API key: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not api_key:
        print("Error: API key is required.", file=sys.stderr)
        sys.exit(1)

    gti_mcp_entry = {
        "serverUrl": args.server_url,
        "headers": {
            "x-apikey": api_key
        }
    }

    # Determine target config path
    target_path = None
    if args.target:
        target_path = Path(args.target).expanduser().resolve()
    else:
        for loc in CONFIG_LOCATIONS:
            if loc.parent.exists():
                target_path = loc
                break
        if not target_path:
            target_path = CONFIG_LOCATIONS[0]

    # Load existing or create fresh
    existing_config = {"mcpServers": {}}
    if target_path.exists():
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, dict) and "mcpServers" in content:
                    existing_config = content
        except Exception as e:
            print(f"Warning: Could not read existing {target_path}: {e}")

    # Merge
    existing_config.setdefault("mcpServers", {})["gti-agentic"] = gti_mcp_entry

    formatted_json = json.dumps(existing_config, indent=2)

    if args.dry_run:
        print(f"[Dry Run] Target: {target_path}")
        print(formatted_json)
        return

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(formatted_json + "\n")

    print(f"✅ Successfully configured 'gti-agentic' in {target_path}")
    print(f"   Server URL: {args.server_url}")
    print("   Antigravity will have access to the GTI Agentic tools upon session restart/reload:")
    print("     - ask_gti_agent")
    print("     - continue_chat")
    print("     - list_sessions")
    print("     - get_session_history")
    print("     - delete_session")
    print("     - share_session / copy_shared_session")


if __name__ == "__main__":
    main()
