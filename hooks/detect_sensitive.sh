#!/bin/bash
# Detect sensitive/admin endpoints in Bash tool output and suggest 403bypasser
# PostToolUse hook for the Bash tool in Claude Code

INPUT=$(cat)

TEXT=$(echo "$INPUT" | jq -r '
  if .tool_response | type == "string" then .tool_response
  elif .tool_response | type == "object" then
    [.tool_response | to_entries[] | .value | tostring] | join("\n")
  else ""
  end
' 2>/dev/null)

[ -z "$TEXT" ] && exit 0

# Match sensitive paths (trailing / or space or end-of-word)
FOUND=$(echo "$TEXT" | grep -oiE '/(admin|administrator|wp-admin|wp-login|phpmyadmin|cpanel|webmail)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(dashboard|panel|console|portal|management|backstage|backoffice)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(heapdump|threaddump|actuator|env|configprops|mappings|beans|metrics|trace|loggers|httptrace|shutdown|jolokia)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(debug|server-status|server-info|\.env|\.git|\.htaccess|\.htpasswd)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(config|configuration|settings|setup|install|backup|dump|export)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(swagger|swagger-ui|api-docs|openapi|graphql|graphiql)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(jenkins|gitlab|jira|kibana|grafana|prometheus|nagios|splunk|sonar|nexus)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(solr|elasticsearch|_cat|_cluster|_nodes|_search)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(jmx-console|web-console|manager/html|manager/status)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(elmah\.axd|trace\.axd)' 2>/dev/null
echo "$TEXT" | grep -oiE '/(internal|private|restricted|secret|hidden|staging)(/| |$)' 2>/dev/null
echo "$TEXT" | grep -oiE '/api/v[0-9]+/(admin|users|internal|private|config|system)' 2>/dev/null)

# Also catch URLs next to 403/401 status codes
FOUND_403=$(echo "$TEXT" | grep -iE '(403|401|forbidden|unauthorized)' 2>/dev/null | grep -oiE 'https?://[^ "'"'"'>]+' 2>/dev/null)

ALL_FOUND=$(printf '%s\n%s' "$FOUND" "$FOUND_403" | sed 's/[[:space:]]*$//' | sed '/^$/d' | sort -u | head -5)

[ -z "$ALL_FOUND" ] && exit 0

ENDPOINTS=$(echo "$ALL_FOUND" | sed 's/"/\\"/g' | tr '\n' ', ' | sed 's/,$//' | sed 's/,/, /g')

cat <<HOOKJSON
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": "SENSITIVE ENDPOINT DETECTED in command output. Paths found: ${ENDPOINTS} -- Consider running: python3 /Users/gankd/tools/403bypasser/403bypasser.py <base_url> <path> --skip ip-spoof -- This is from the 403bypasser auto-detect hook."
  }
}
HOOKJSON
