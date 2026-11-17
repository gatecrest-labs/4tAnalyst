#!/usr/bin/env bash
# Blocks reintroduction of a redacted former-employer name/domain. This repo is
# public, so the blocked words are stored only as SHA-256 hashes: the script
# splits each tracked text file into alphanumeric words, lowercases them, and
# compares each word's hash against the list below. The words themselves never
# appear in source, commit messages, or CI logs, and can't be decoded from here.
#
# To block another word, add the output of:
#   printf '%s' 'word' | tr '[:upper:]' '[:lower:]' | sha256sum
#
# Usage:
#   scripts/check-sensitive-strings.sh           scan git-tracked files
#   scripts/check-sensitive-strings.sh --staged  scan the git index (pre-commit hook)
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

python3 - "${1:-}" <<'PY'
import hashlib
import re
import subprocess
import sys

BLOCKED = {
    "d74801e724ccdfcdf7a9b349c5214221bc82fba4ec8b9b94d8d9dad7a2bf8ba1",
    "573ef7a1380afff0f77f4ce9b60fbf6bc5c948bee70667332af6d1416495a1ac",
}
WORD = re.compile(rb"[A-Za-z0-9]+")
staged = sys.argv[1] == "--staged"

paths = subprocess.run(
    ["git", "ls-files", "-z"], check=True, capture_output=True
).stdout.split(b"\0")

hits = []
for raw in filter(None, paths):
    path = raw.decode("utf-8", "surrogateescape")
    try:
        if staged:
            data = subprocess.run(
                ["git", "show", f":{path}"], check=True, capture_output=True
            ).stdout
        else:
            with open(raw, "rb") as fh:
                data = fh.read()
    except (OSError, subprocess.CalledProcessError):
        continue  # deleted in the working tree, or not a regular file
    if b"\0" in data:
        continue  # binary
    for lineno, line in enumerate(data.splitlines(), 1):
        for word in WORD.findall(line):
            if hashlib.sha256(word.lower()).hexdigest() in BLOCKED:
                hits.append(f"{path}:{lineno}")
                break

if hits:
    print(
        "ERROR: a blocked reference was found (content redacted from this output):",
        file=sys.stderr,
    )
    print("\n".join(hits), file=sys.stderr)
    sys.exit(1)
PY
