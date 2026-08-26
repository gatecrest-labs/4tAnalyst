#!/usr/bin/env bash
# Blocks reintroduction of a redacted former-employer name/domain. The target
# strings are base64-encoded here on purpose: this repo is public, and the
# strings themselves must never appear in plaintext in source, commit
# messages, or CI logs.
#
# Usage:
#   scripts/check-sensitive-strings.sh           scan git-tracked files
#   scripts/check-sensitive-strings.sh --staged  scan the git index (pre-commit hook)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

t1=$(printf 'eGNlbGVuZXJneQ==' | base64 -d)
t2=$(printf 'eGNlbA==' | base64 -d)
pattern="\\b${t2}\\b|${t1}"

if [ "${1:-}" = "--staged" ]; then
    matches=$(git grep -InE --cached "$pattern" -- . || true)
else
    matches=$(git grep -InE "$pattern" -- . || true)
fi

if [ -n "$matches" ]; then
    echo "ERROR: a blocked reference was found (content redacted from this output):" >&2
    echo "$matches" | cut -d: -f1,2 >&2
    exit 1
fi
