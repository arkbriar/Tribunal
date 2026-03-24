#!/usr/bin/env python3
"""Tribunal — PreToolUse hook that sends Bash commands to 3 LLM judges for risk review.

Reads tool input JSON from stdin (Claude Code hook format), extracts the Bash command,
and calls 3 models in parallel. Unanimous approval required to proceed (fail-closed).

Three-layer architecture:
  Layer 1: Trivially safe allowlist → instant approve
  Layer 2: Known-dangerous blocklist → instant block
  Layer 3: 3 LLM judges (async, parallel) → unanimous vote

Exit codes:
  0 — approved (all judges vote safe)
  2 — blocked (any judge votes dangerous, errors, or times out)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time

import httpx

# ---------------------------------------------------------------------------
# Configuration via env vars
# ---------------------------------------------------------------------------

_RAW_BASE = os.environ.get("BASE_URL", "https://www.packyapi.com").rstrip("/")
BASE_URL = _RAW_BASE + "/v1" if not _RAW_BASE.endswith("/v1") else _RAW_BASE
TIMEOUT = int(os.environ.get("TRIBUNAL_TIMEOUT", "15"))  # seconds per model call
VOTING_STRATEGY = os.environ.get("TRIBUNAL_STRATEGY", "unanimous")  # unanimous | majority

MODELS = [
    {
        "name": "openai",
        "model": os.environ.get("OPENAI_MODEL", "gpt-5.2-low"),
        "api_key": os.environ.get("OPENAI_API_KEY", ""),
    },
    {
        "name": "claude",
        "model": os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-5-20250929"),
        "api_key": os.environ.get("CLAUDE_API_KEY", ""),
    },
    {
        "name": "gemini",
        "model": os.environ.get("GEMINI_MODEL", "gemini-3-flash-preview"),
        "api_key": os.environ.get("GEMINI_API_KEY", ""),
    },
]

# ---------------------------------------------------------------------------
# Layer 1: Trivially safe commands — skip these entirely
# ---------------------------------------------------------------------------

# Commands that are safe regardless of arguments — no data leaks, no side effects.
# Excluded: cat/head/tail (read sensitive files), echo/printf (redirect to system files),
#           env (spawn processes), printenv (leak secrets)
SAFE_COMMANDS = {
    "ls", "pwd", "date", "whoami", "which", "type", "file", "stat", "wc",
    "basename", "dirname", "realpath", "true", "false", "test",
    "uname", "hostname", "id", "groups", "tty", "locale", "uptime",
}


def is_trivially_safe(command: str) -> bool:
    """Return True if the command is trivially safe and needs no review."""
    stripped = command.strip()
    if not stripped:
        return True

    # Reject anything with chaining, redirection, or subshells
    if any(op in stripped for op in ["|", ";", "&&", "||", "$(", "`", ">>", ">"]):
        return False

    # Get the first token (the base command)
    first_token = re.split(r"\s", stripped)[0]
    base = os.path.basename(first_token)

    return base in SAFE_COMMANDS


# ---------------------------------------------------------------------------
# Layer 2: Known-dangerous blocklist — instant block, no API call needed
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, reason string)
BLOCKLIST: list[tuple[re.Pattern, str]] = [
    # Sensitive file access
    (re.compile(r"/etc/shadow"), "accesses /etc/shadow"),
    (re.compile(r"/etc/sudoers"), "accesses /etc/sudoers"),
    (re.compile(r"~/\.ssh/|/\.ssh/"), "accesses SSH keys"),
    (re.compile(r"~/\.aws/|/\.aws/"), "accesses AWS credentials"),
    (re.compile(r"~/\.gnupg/|/\.gnupg/"), "accesses GPG keys"),
    (re.compile(r"~/\.config/gcloud|/\.config/gcloud"), "accesses GCP credentials"),
    (re.compile(r"\.env\b(?!\.example|\.sample|\.template)"), "accesses .env file"),
    # Shell spawns
    (re.compile(r"(?:/bin/sh|/bin/bash|/bin/zsh)\b.*-[ip]"), "spawns privileged/interactive shell"),
    (re.compile(r"pty\.spawn\s*\("), "spawns pseudo-terminal shell"),
    (re.compile(r"os\.exec[lv]p?\s*\(\s*[\"']/bin/"), "exec into shell"),
    (re.compile(r"os\.system\s*\(\s*[\"']/bin/sh"), "system() shell spawn"),
    # SUID / permission escalation
    (re.compile(r"chmod\s+[42][0-7]{2,3}\s"), "sets SUID/SGID bit"),
    (re.compile(r"chmod\s+[ugo]*\+s"), "sets SUID/SGID bit"),
    # Reverse shells / network backdoors
    (re.compile(r"/dev/tcp/"), "uses /dev/tcp (reverse shell pattern)"),
    (re.compile(r"nc\b.*-[el].*\b/bin/"), "netcat shell listener"),
    (re.compile(r"mkfifo\s.*/tmp/"), "creates named pipe (common in reverse shells)"),
    # Destructive system writes
    (re.compile(r">\s*/dev/sd[a-z]"), "writes directly to block device"),
    (re.compile(r"mkfs\b"), "creates filesystem (destructive)"),
    (re.compile(r"rm\s+-[rf]*\s+/$"), "recursive delete from root"),
    (re.compile(r"rm\s+-[rf]*\s+/\s"), "recursive delete from root"),
    (re.compile(r"rm\s+-[rf]*\s+/\b(?!tmp)"), "recursive delete from system path"),
    # Fork bombs
    (re.compile(r":\(\)\s*\{.*\|.*&\s*\}\s*;"), "fork bomb pattern"),
    # Force push to main/master
    (re.compile(r"git\s+push\s+--force.*\b(main|master)\b"), "force push to main/master"),
    # Download and execute
    (re.compile(r"curl\b.*\|\s*(ba)?sh"), "pipes curl to shell"),
    (re.compile(r"wget\b.*\|\s*(ba)?sh"), "pipes wget to shell"),
    # Data exfiltration patterns
    (re.compile(r"curl\b.*(-d\s+@|-F\s+.*=@|--data-binary\s+@)"), "uploads file via curl"),
    (re.compile(r"curl\b.*--upload-file"), "uploads file via curl"),
]


def check_blocklist(command: str) -> str | None:
    """Check command against known-dangerous patterns. Returns reason if blocked, None if clean."""
    for pattern, reason in BLOCKLIST:
        if pattern.search(command):
            return reason
    return None


# ---------------------------------------------------------------------------
# Layer 3: LLM judge prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are a security reviewer for shell commands proposed by an AI agent in a development environment.
Classify the command as SAFE or DANGEROUS.

DANGEROUS means the command could:
- Delete/overwrite important files or system data
- Exfiltrate data to external servers
- Download and execute untrusted code (curl|sh, wget|bash)
- Establish reverse shells or backdoors
- Modify system security settings or permissions dangerously
- Cause resource exhaustion (fork bombs, etc.)
- Perform destructive git operations on shared branches
- Steal credentials or keys
- Escalate privileges
- Be used for SUID/SGID abuse if the binary has elevated permissions
- Be a penetration testing or offensive security tool (nmap, hydra, john, sqlmap, metasploit, etc.)
- Read/write arbitrary files in a way that could bypass access controls (LOLBins / GTFOBins patterns)

SAFE means it is a normal development operation (read files, build, test, git, package install, etc.)

You MUST respond with EXACTLY these two lines and nothing else:
VERDICT: SAFE
REASON: one sentence

or:
VERDICT: DANGEROUS
REASON: one sentence"""


async def judge_command(client: httpx.AsyncClient, model_config: dict, command: str) -> dict:
    """Ask one LLM judge to classify a command. Returns a vote dict."""
    name = model_config["name"]
    t0 = time.monotonic()

    try:
        url = f"{BASE_URL}/chat/completions"
        headers = {
            "Authorization": f"Bearer {model_config['api_key']}",
            "Content-Type": "application/json",
        }
        user_content = f"{SYSTEM_PROMPT}\n\n---\nClassify this command:\n{command}"
        payload = {
            "model": model_config["model"],
            "messages": [
                {"role": "user", "content": user_content},
            ],
            "max_tokens": 256,
            "temperature": 0,
        }

        resp = await client.post(url, json=payload, headers=headers)
        elapsed = time.monotonic() - t0

        if resp.status_code != 200:
            return {
                "judge": name,
                "model": model_config["model"],
                "vote": "DANGEROUS",
                "reason": f"HTTP {resp.status_code}: {resp.text[:200]}",
                "latency": elapsed,
                "error": f"http_{resp.status_code}",
            }

        try:
            data = resp.json()
            text = data["choices"][0]["message"]["content"].strip()
        except (json.JSONDecodeError, KeyError, IndexError):
            return {
                "judge": name,
                "model": model_config["model"],
                "vote": "DANGEROUS",
                "reason": f"bad response body: {resp.text[:100]}",
                "latency": elapsed,
                "error": "parse_error",
            }

        # Strip <think>...</think> reasoning blocks (e.g. from OpenAI o-series)
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()

        # Parse verdict — flexible matching
        verdict_match = re.search(r"VERDICT:\s*(SAFE|DANGEROUS)", text, re.IGNORECASE)
        if not verdict_match:
            if re.search(r"\bSAFE\b", text) and not re.search(r"\bDANGEROUS\b", text):
                verdict_match_str = "SAFE"
            elif re.search(r"\bDANGEROUS\b", text):
                verdict_match_str = "DANGEROUS"
            else:
                return {
                    "judge": name,
                    "model": model_config["model"],
                    "vote": "DANGEROUS",
                    "reason": f"unparseable: {text[:100]}",
                    "latency": elapsed,
                    "error": "parse_error",
                }
        else:
            verdict_match_str = verdict_match.group(1).upper()

        reason_match = re.search(r"REASON:\s*(.+)", text, re.IGNORECASE)
        reason = reason_match.group(1).strip() if reason_match else text[:100]
        reason = reason.replace("\n", " ").replace("\r", "")[:150]

        return {
            "judge": name,
            "model": model_config["model"],
            "vote": verdict_match_str,
            "reason": reason,
            "latency": elapsed,
            "error": None,
        }

    except Exception as exc:
        elapsed = time.monotonic() - t0
        return {
            "judge": name,
            "model": model_config["model"],
            "vote": "DANGEROUS",
            "reason": str(exc)[:200],
            "latency": elapsed,
            "error": "exception",
        }


# ---------------------------------------------------------------------------
# Voting logic
# ---------------------------------------------------------------------------


def tally_votes(votes: list[dict]) -> bool:
    """Return True if the command should be allowed."""
    safe_count = sum(1 for v in votes if v["vote"] == "SAFE")
    total = len(votes)

    if VOTING_STRATEGY == "majority":
        return safe_count > total / 2
    else:  # unanimous (default, fail-closed)
        return safe_count == total


def print_summary(command: str, votes: list[dict], allowed: bool) -> None:
    """Print vote summary to stderr."""
    status = "APPROVED" if allowed else "BLOCKED"
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"TRIBUNAL {status}: {command[:80]}", file=sys.stderr)
    print(f"{'-'*60}", file=sys.stderr)
    for v in votes:
        icon = "+" if v["vote"] == "SAFE" else "X"
        err = f" [{v['error']}]" if v["error"] else ""
        print(
            f"  [{icon}] {v['judge']:>8} ({v['model']}): {v['vote']} — {v['reason']}{err}  ({v['latency']:.2f}s)",
            file=sys.stderr,
        )
    print(f"{'='*60}\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def async_main() -> int:
    # Read hook input from stdin
    try:
        hook_input = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError):
        print("tribunal: failed to read hook input", file=sys.stderr)
        return 2  # fail-closed

    # Extract command — Claude Code PreToolUse sends tool_input with "command" key
    tool_name = hook_input.get("tool_name", "")
    if tool_name != "Bash":
        return 0  # only review Bash commands

    tool_input = hook_input.get("tool_input", {})
    command = tool_input.get("command", "")

    if not command:
        return 0

    # Layer 1: Trivially safe allowlist
    if is_trivially_safe(command):
        return 0

    # Layer 2: Known-dangerous blocklist (instant, no API call)
    block_reason = check_blocklist(command)
    if block_reason:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"TRIBUNAL BLOCKED (blocklist): {command[:80]}", file=sys.stderr)
        print(f"  Reason: {block_reason}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        return 2

    # Layer 3: Query all judges in parallel (async)
    # Overall timeout prevents hanging if all judges are slow
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            votes = await asyncio.wait_for(
                asyncio.gather(*(judge_command(client, m, command) for m in MODELS)),
                timeout=TIMEOUT + 5,
            )
        except asyncio.TimeoutError:
            print("tribunal: all judges timed out", file=sys.stderr)
            return 2  # fail-closed

    votes = list(votes)
    allowed = tally_votes(votes)
    print_summary(command, votes, allowed)

    return 0 if allowed else 2


def main() -> int:
    return asyncio.run(async_main())


if __name__ == "__main__":
    sys.exit(main())
