#!/usr/bin/env bash
# deploy-install.sh — sync the production venv to the pinned dependencies.
#
# Called by the GitLab `deploy` job after `git pull`, before the service restart:
#   sudo -u 4tanalyst /opt/4tanalyst/scripts/deploy-install.sh
#
# Runs as the 4tanalyst user. It sets HOME/UV_NO_CONFIG itself so uv ignores
# the invoking user's config files (the reason `sudo -u 4tanalyst uv ...` fails
# with "failed to open file ~/uv.toml"). Keeping the commands here means the
# sudoers rule only needs to allow this one script.

set -euo pipefail

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$APP_DIR"

export HOME="$APP_DIR"
export UV_NO_CONFIG=1

/usr/local/bin/uv pip install \
    --python "$APP_DIR/.venv/bin/python" \
    -c constraints.txt \
    -e mcp_common/ -e standards_mcp/ -e fortimanager_mcp/ -e feedback_mcp/ \
    -e intake_mcp/ -e zone_mcp/ -e planner/ -e psirt/ -e psirt_mcp/ \
    -e hygiene/ -e hygiene_mcp/ -e fwanalyst_server/
