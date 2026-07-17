#!/usr/bin/env bash
# Run a bounded, read-only Claude Code review and emit schema-validated JSON.
set -euo pipefail

usage() {
  echo "usage: $0 <fast|integration|security> <review prompt>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage

lane="$1"
prompt="$2"

case "$lane" in
  fast)
    agent="orochi-fast-auditor"
    model="claude-haiku-4-5-20251001"
    effort="low"
    ;;
  integration)
    agent="orochi-integration-reviewer"
    model="claude-sonnet-5"
    effort="medium"
    ;;
  security)
    agent="orochi-security-reviewer"
    model="claude-sonnet-5"
    effort="high"
    ;;
  *)
    usage
    ;;
esac

schema='{
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "verdict": {"type": "string", "enum": ["pass", "findings"]},
    "summary": {"type": "string"},
    "findings": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "properties": {
          "severity": {"type": "string", "enum": ["P0", "P1", "P2", "P3"]},
          "title": {"type": "string"},
          "file": {"type": "string"},
          "line": {"type": "integer", "minimum": 1},
          "counterexample": {"type": "string"},
          "impact": {"type": "string"},
          "fix": {"type": "string"},
          "test": {"type": "string"}
        },
        "required": ["severity", "title", "file", "line", "counterexample", "impact", "fix", "test"]
      }
    }
  },
  "required": ["verdict", "summary", "findings"]
}'

full_prompt="$(printf '%s\n\n%s' \
  'Review only the explicitly named Orochi files and behavior below. Do not edit anything. Do not report style preferences. Findings must be reachable and independently evidenced. If there are no concrete issues, return verdict pass with an empty findings array.' \
  "$prompt")"

raw="$(timeout --signal=TERM --kill-after=10s 600s claude -p "$full_prompt" \
  --agent "$agent" \
  --model "$model" \
  --effort "$effort" \
  --permission-mode plan \
  --setting-sources project,local \
  --disable-slash-commands \
  --strict-mcp-config \
  --mcp-config '{"mcpServers":{}}' \
  --no-chrome \
  --no-session-persistence \
  --output-format json \
  --json-schema "$schema")"

if ! structured="$(printf '%s\n' "$raw" | jq -e '
  if .is_error == false and .structured_output != null
  then .structured_output
  else error("Claude returned no validated structured_output")
  end
')"; then
  printf '%s\n' "$raw" >&2
  exit 1
fi

printf '%s\n' "$structured"
