#!/usr/bin/env bash
# Tribunal — Install script
# Installs the PreToolUse hook into Claude Code settings.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK_SCRIPT="$SCRIPT_DIR/vote_review.py"
ENV_FILE="$SCRIPT_DIR/.env"
SETTINGS_DIR="$HOME/.claude"
SETTINGS_FILE="$SETTINGS_DIR/settings.json"

echo "Tribunal Installer"
echo "==================="

# Check that vote_review.py exists
if [[ ! -f "$HOOK_SCRIPT" ]]; then
    echo "ERROR: vote_review.py not found at $HOOK_SCRIPT"
    exit 1
fi

# Check that .env exists
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: .env not found at $ENV_FILE"
    echo "Copy .env.example and fill in your API keys."
    exit 1
fi

# Ensure .claude directory exists
mkdir -p "$SETTINGS_DIR"

# Build the hook command — sources .env for API keys
HOOK_CMD="bash -c 'set -a && source \"$SCRIPT_DIR/.env\" && set +a && uv run --directory \"$SCRIPT_DIR\" python vote_review.py'"

# Read existing settings or start fresh
if [[ -f "$SETTINGS_FILE" ]]; then
    SETTINGS=$(cat "$SETTINGS_FILE")
else
    SETTINGS="{}"
fi

# Use python to merge the hook into settings (handles JSON properly)
NEW_SETTINGS=$(uv run --directory "$SCRIPT_DIR" python3 -c "
import json, sys

settings = json.loads(sys.argv[1])
hook_cmd = sys.argv[2]

hooks = settings.setdefault('hooks', {})
pre_hooks = hooks.setdefault('PreToolUse', [])

# Remove any existing tribunal hook entry
pre_hooks = [h for h in pre_hooks if 'vote_review.py' not in json.dumps(h)]

# Add the tribunal hook with matcher + hooks array structure
pre_hooks.append({
    'matcher': 'Bash',
    'hooks': [{
        'type': 'command',
        'command': hook_cmd,
        'timeout': 20000,
    }],
})

hooks['PreToolUse'] = pre_hooks
settings['hooks'] = hooks

print(json.dumps(settings, indent=2))
" "$SETTINGS" "$HOOK_CMD")

echo "$NEW_SETTINGS" > "$SETTINGS_FILE"
chmod 600 "$SETTINGS_FILE"

echo ""
echo "Hook installed to: $SETTINGS_FILE"
echo ""
echo "Required env vars (set in .env):"
echo "  BASE_URL, OPENAI_API_KEY, CLAUDE_API_KEY, GEMINI_API_KEY"
echo ""
echo "Done!"
