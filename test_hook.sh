#!/usr/bin/env bash
# Quick test script — sources env and runs vote_review on a given command
set -a && source "$(dirname "$0")/.env" && set +a
"$(dirname "$0")/.venv/bin/python" -c "
import json, sys
print(json.dumps({'tool_name': 'Bash', 'tool_input': {'command': sys.argv[1]}}))
" "$1" | \
  "$(dirname "$0")/.venv/bin/python" "$(dirname "$0")/vote_review.py"
