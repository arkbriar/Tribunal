# Tribunal

Multi-model voting risk review hook for [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Sends each Bash command to 3 LLM judges in parallel — unanimous approval required to proceed (fail-closed).

## Architecture

Three-layer defense:

```
Command → Layer 1: Allowlist (instant approve)
        → Layer 2: Blocklist (instant block)
        → Layer 3: 3 LLM Judges (async, unanimous vote)
```

- **Layer 1** — Trivially safe commands (`ls`, `pwd`, `date`, etc.) skip review entirely
- **Layer 2** — Known-dangerous patterns (credential access, shell spawns, SUID, reverse shells, `curl|sh`, etc.) are instantly blocked without API calls
- **Layer 3** — Everything else goes to 3 LLM judges in parallel. All must vote SAFE to approve; any DANGEROUS vote, error, or timeout blocks the command

## Setup

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- API keys for 3 models via an OpenAI-compatible proxy

### Configure

```bash
cp .env.example .env
# Edit .env with your API keys and model names:
#   BASE_URL, OPENAI_API_KEY, OPENAI_MODEL,
#   CLAUDE_API_KEY, CLAUDE_MODEL,
#   GEMINI_API_KEY, GEMINI_MODEL
```

### Install hook

```bash
# Automatic — adds the hook to ~/.claude/settings.json
./install.sh

# Or manual — copy the hook config from settings.example.json
# into your ~/.claude/settings.json
```

### Uninstall

Remove the Tribunal hook entry from `hooks.PreToolUse` in `~/.claude/settings.json`.

### Test it

```bash
# Safe command (should approve)
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | bash -c 'set -a && source .env && set +a && uv run python vote_review.py'

# Dangerous command (should block)
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | bash -c 'set -a && source .env && set +a && uv run python vote_review.py'
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_URL` | *(none)* | Shared base URL for all providers (optional) |
| `OPENAI_BASE_URL` | `BASE_URL` or `https://api.openai.com` | OpenAI-specific base URL |
| `CLAUDE_BASE_URL` | `BASE_URL` or `https://api.anthropic.com` | Claude-specific base URL |
| `GEMINI_BASE_URL` | `BASE_URL` or `https://generativelanguage.googleapis.com` | Gemini-specific base URL |
| `OPENAI_MODEL` | `gpt-5.2-low` | First judge model |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Second judge model |
| `GEMINI_MODEL` | `gemini-3-flash-preview` | Third judge model |
| `TRIBUNAL_TIMEOUT` | `15` | Per-judge timeout in seconds |
| `TRIBUNAL_STRATEGY` | `unanimous` | Voting strategy: `unanimous` or `majority` |
| `TRIBUNAL_AUDIT_LOG` | *(disabled)* | Path to JSONL audit log file (e.g. `~/.tribunal/audit.jsonl`) |

## Evaluation

### Build dataset

```bash
uv run python eval/build_dataset.py
```

Builds `eval/dataset.json` — 436 labeled commands from 4 sources:
- **NL2Bash** — safe dev commands from StackOverflow
- **Masaryk Cybersecurity Training** — pentest/attack commands
- **GTFOBins** — LOLBin exploit patterns (hardest cases)
- **Manual** — curated safe, dangerous, and ambiguous commands

### Run evaluation

```bash
# Source env vars first
set -a && source .env && set +a

# Full eval (8 concurrent workers, 2 retries on API errors)
uv run python eval/run_eval.py --workers=8 --retries=2

# Subset
uv run python eval/run_eval.py 20

# Filter by source
uv run python eval/run_eval.py source=gtfobins

# Resume from previous results (skips clean entries)
uv run python eval/run_eval.py --resume
```

### Generate report

```bash
uv run python eval/report.py
```

Prints: per-category precision/recall/F1, per-model accuracy, inter-model agreement (Cohen's/Fleiss' kappa), disagreement cases, latency stats, and false negative/positive lists.

## Results (latest run)

| Metric | Value |
|--------|-------|
| Accuracy | 88.1% |
| Precision | 0.908 |
| Recall | 0.914 |
| F1 | 0.911 |
| Fleiss' kappa | 0.846 |
| Latency (p50) | 8.4s |

100% recall on: reverse shells, fork bombs, credential theft, destructive commands, download+exec, data exfiltration, privilege escalation, system modification.
