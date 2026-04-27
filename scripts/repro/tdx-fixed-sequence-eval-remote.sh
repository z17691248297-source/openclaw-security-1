#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}"
EVAL_ROOT="${OPENCLAW_TDX_EVAL_ROOT:-/tmp/openclaw-tdx-eval}"
WORKSPACE_SNAPSHOT="${OPENCLAW_TDX_EVAL_WORKSPACE_SNAPSHOT:-$EVAL_ROOT/workspaces/django}"
SOURCE_TARBALL="${OPENCLAW_TDX_EVAL_SOURCE_TARBALL:-$EVAL_ROOT/dist/Django-5.1.7.tar.gz}"
OUTPUT_DIR="${OPENCLAW_TDX_EVAL_REMOTE_OUTPUT_DIR:-$EVAL_ROOT/remote-report-$(date +%Y-%m-%d-%H%M%S)}"
REMOTE_FIXTURE_ROOT="${OPENCLAW_TDX_EVAL_REMOTE_FIXTURE_ROOT:-/tmp/openclaw-tdx-eval-remote}"
REMOTE_TARGET_NAME="${OPENCLAW_TDX_EVAL_REMOTE_TARGET_NAME:-remote-target}"
REMOTE_SSH_USER="${OPENCLAW_TDX_EVAL_REMOTE_SSH_USER:-}"
REMOTE_SSH_HOST="${OPENCLAW_TDX_EVAL_REMOTE_SSH_HOST:-}"
REMOTE_SSH_PORT="${OPENCLAW_TDX_EVAL_REMOTE_SSH_PORT:-22}"
REMOTE_SSH_PASSWORD="${OPENCLAW_TDX_EVAL_REMOTE_SSH_PASSWORD:-}"
REMOTE_SSH_IDENTITY_FILE="${OPENCLAW_TDX_EVAL_REMOTE_SSH_IDENTITY_FILE:-}"
TDX_BACKEND_BASE_URL="${OPENCLAW_TDX_BACKEND_BASE_URL:-}"
REMOTE_BACKEND_BASE_URL="${OPENCLAW_TDX_EVAL_REMOTE_BACKEND_BASE_URL:-}"
REMOTE_PLATFORM="${OPENCLAW_TDX_EVAL_REMOTE_PLATFORM:-keystone}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage:
  OPENCLAW_CONFIG_DIR="$HOME/.openclaw" \
  OPENCLAW_TDX_EVAL_ROOT=/tmp/openclaw-tdx-eval \
  OPENCLAW_TDX_BACKEND_BASE_URL=http://<local-tdx-backend>:19090 \
  OPENCLAW_TDX_EVAL_REMOTE_BACKEND_BASE_URL=http://<remote-tee-backend>:19090 \
  OPENCLAW_TDX_EVAL_REMOTE_SSH_USER=<user> \
  OPENCLAW_TDX_EVAL_REMOTE_SSH_HOST=<host> \
  OPENCLAW_TDX_EVAL_REMOTE_SSH_PASSWORD=<password> \
  ./scripts/repro/tdx-fixed-sequence-eval-remote.sh

Optional environment variables:
  OPENCLAW_TDX_EVAL_REMOTE_PLATFORM
  OPENCLAW_TDX_EVAL_REMOTE_SSH_PORT
  OPENCLAW_TDX_EVAL_REMOTE_SSH_IDENTITY_FILE
  OPENCLAW_TDX_EVAL_REMOTE_TARGET_NAME
  OPENCLAW_TDX_EVAL_REMOTE_FIXTURE_ROOT
  OPENCLAW_TDX_EVAL_REMOTE_OUTPUT_DIR
  OPENCLAW_TDX_EVAL_WORKSPACE_SNAPSHOT
  OPENCLAW_TDX_EVAL_SOURCE_TARBALL

Extra CLI args are forwarded to scripts/repro/tdx-fixed-sequence-eval-remote.ts.
EOF
  exit 0
fi

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Missing dependency: $1"
  fi
}

require_dir() {
  if [[ ! -d "$1" ]]; then
    fail "Required directory not found: $1"
  fi
}

require_file() {
  if [[ ! -f "$1" ]]; then
    fail "Required file not found: $1"
  fi
}

require_cmd node
require_cmd ssh
require_dir "$CONFIG_DIR"
require_file "$CONFIG_DIR/openclaw.json"
require_dir "$WORKSPACE_SNAPSHOT"
require_file "$SOURCE_TARBALL"

if [[ -z "$REMOTE_SSH_USER" || -z "$REMOTE_SSH_HOST" ]]; then
  fail "Set OPENCLAW_TDX_EVAL_REMOTE_SSH_USER and OPENCLAW_TDX_EVAL_REMOTE_SSH_HOST"
fi
if [[ -z "$REMOTE_BACKEND_BASE_URL" ]]; then
  fail "Set OPENCLAW_TDX_EVAL_REMOTE_BACKEND_BASE_URL"
fi

if [[ -n "$REMOTE_SSH_PASSWORD" ]]; then
  require_cmd sshpass
fi

if [[ -n "$REMOTE_SSH_IDENTITY_FILE" ]]; then
  require_file "$REMOTE_SSH_IDENTITY_FILE"
fi

mkdir -p "$OUTPUT_DIR"

extra_args=()
if [[ -n "$TDX_BACKEND_BASE_URL" ]]; then
  extra_args+=(--local-backend-base-url "$TDX_BACKEND_BASE_URL")
fi
extra_args+=(--remote-backend-base-url "$REMOTE_BACKEND_BASE_URL")
extra_args+=(--remote-platform "$REMOTE_PLATFORM")
if [[ -n "$REMOTE_SSH_PASSWORD" ]]; then
  extra_args+=(--ssh-password "$REMOTE_SSH_PASSWORD")
fi
if [[ -n "$REMOTE_SSH_IDENTITY_FILE" ]]; then
  extra_args+=(--ssh-identity-file "$REMOTE_SSH_IDENTITY_FILE")
fi

echo "==> Run TDX fixed-sequence remote evaluation"
echo "    Config dir: $CONFIG_DIR"
echo "    Eval root: $EVAL_ROOT"
echo "    Workspace snapshot: $WORKSPACE_SNAPSHOT"
echo "    Output dir: $OUTPUT_DIR"
echo "    Local backend: ${TDX_BACKEND_BASE_URL:-<from-config>}"
echo "    Remote backend: $REMOTE_BACKEND_BASE_URL"
echo "    Remote platform: $REMOTE_PLATFORM"
echo "    Remote target: $REMOTE_TARGET_NAME ($REMOTE_SSH_USER@$REMOTE_SSH_HOST:$REMOTE_SSH_PORT)"
echo "    Remote fixture root: $REMOTE_FIXTURE_ROOT"

cd "$ROOT_DIR"
node --import tsx scripts/repro/tdx-fixed-sequence-eval-remote.ts \
  --config-path "$CONFIG_DIR/openclaw.json" \
  --workspace-snapshot "$WORKSPACE_SNAPSHOT" \
  --source-tarball "$SOURCE_TARBALL" \
  --output-dir "$OUTPUT_DIR" \
  --target-name "$REMOTE_TARGET_NAME" \
  --remote-fixture-root "$REMOTE_FIXTURE_ROOT" \
  --ssh-user "$REMOTE_SSH_USER" \
  --ssh-host "$REMOTE_SSH_HOST" \
  --ssh-port "$REMOTE_SSH_PORT" \
  "${extra_args[@]}" \
  "$@"

echo "==> Remote evaluation finished"
echo "    JSON: $OUTPUT_DIR/results.json"
echo "    Markdown: $OUTPUT_DIR/report.md"
