#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-$HOME/.openclaw}"
EVAL_ROOT="${OPENCLAW_TDX_EVAL_ROOT:-/tmp/openclaw-tdx-eval}"
WORKSPACE_SNAPSHOT="${OPENCLAW_TDX_EVAL_WORKSPACE_SNAPSHOT:-$EVAL_ROOT/workspaces/django}"
SOURCE_TARBALL="${OPENCLAW_TDX_EVAL_SOURCE_TARBALL:-$EVAL_ROOT/dist/Django-5.1.7.tar.gz}"
OUTPUT_DIR="${OPENCLAW_TDX_EVAL_OUTPUT_DIR:-$EVAL_ROOT/container-report-2026-04-16}"
PROTECTED_HOME="${OPENCLAW_TDX_EVAL_PROTECTED_HOME:-$EVAL_ROOT/protected-home}"
IMAGE_NAME="${OPENCLAW_TDX_EVAL_IMAGE:-openclaw:tdx-eval-build}"
TDX_BACKEND_BASE_URL="${OPENCLAW_TDX_BACKEND_BASE_URL:-}"
DOCKER_CMD_RAW="${OPENCLAW_TDX_EVAL_DOCKER_CMD:-docker}"
CONTAINER_UID_GID="${OPENCLAW_TDX_EVAL_CONTAINER_UID_GID:-$(id -u):$(id -g)}"

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

read -r -a DOCKER_CMD <<<"$DOCKER_CMD_RAW"
if [[ "${#DOCKER_CMD[@]}" -eq 0 ]]; then
  fail "OPENCLAW_TDX_EVAL_DOCKER_CMD cannot be empty"
fi

require_cmd "${DOCKER_CMD[0]}"
require_dir "$CONFIG_DIR"
require_dir "$EVAL_ROOT"
require_dir "$WORKSPACE_SNAPSHOT"
require_file "$SOURCE_TARBALL"

case "$WORKSPACE_SNAPSHOT" in
  "$EVAL_ROOT"/*) WORKSPACE_SNAPSHOT_REL="${WORKSPACE_SNAPSHOT#"$EVAL_ROOT"/}" ;;
  *) fail "OPENCLAW_TDX_EVAL_WORKSPACE_SNAPSHOT must live under $EVAL_ROOT" ;;
esac

case "$SOURCE_TARBALL" in
  "$EVAL_ROOT"/*) SOURCE_TARBALL_REL="${SOURCE_TARBALL#"$EVAL_ROOT"/}" ;;
  *) fail "OPENCLAW_TDX_EVAL_SOURCE_TARBALL must live under $EVAL_ROOT" ;;
esac

case "$OUTPUT_DIR" in
  "$EVAL_ROOT") OUTPUT_DIR_REL="" ;;
  "$EVAL_ROOT"/*) OUTPUT_DIR_REL="${OUTPUT_DIR#"$EVAL_ROOT"/}" ;;
  *) fail "OPENCLAW_TDX_EVAL_OUTPUT_DIR must live under $EVAL_ROOT" ;;
esac

case "$PROTECTED_HOME" in
  "$EVAL_ROOT") PROTECTED_HOME_REL="" ;;
  "$EVAL_ROOT"/*) PROTECTED_HOME_REL="${PROTECTED_HOME#"$EVAL_ROOT"/}" ;;
  *) fail "OPENCLAW_TDX_EVAL_PROTECTED_HOME must live under $EVAL_ROOT" ;;
esac

CONTAINER_WORKSPACE_SNAPSHOT="/eval-root/$WORKSPACE_SNAPSHOT_REL"
CONTAINER_SOURCE_TARBALL="/eval-root/$SOURCE_TARBALL_REL"
if [[ -n "$OUTPUT_DIR_REL" ]]; then
  CONTAINER_OUTPUT_DIR="/eval-root/$OUTPUT_DIR_REL"
else
  CONTAINER_OUTPUT_DIR="/eval-root"
fi
if [[ -n "$PROTECTED_HOME_REL" ]]; then
  CONTAINER_PROTECTED_HOME="/eval-root/$PROTECTED_HOME_REL"
else
  CONTAINER_PROTECTED_HOME="/eval-root"
fi

read -r -d '' CONTAINER_CMD <<'EOF' || true
set -euo pipefail
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
tar -C /src \
  --exclude=.git \
  --exclude=node_modules \
  --exclude=dist \
  --exclude=ui/dist \
  --exclude=ui/node_modules \
  -cf - . | tar -C "$tmp_dir" -xf -
ln -s /app/node_modules "$tmp_dir/node_modules"
ln -s /app/dist "$tmp_dir/dist"
cd "$tmp_dir"
extra_args=()
if [[ -n "${TDX_BACKEND_BASE_URL:-}" ]]; then
  extra_args+=(--backend-base-url "$TDX_BACKEND_BASE_URL")
fi
node --import tsx scripts/repro/tdx-fixed-sequence-eval.ts \
  --config-path /home/node/.openclaw/openclaw.json \
  --workspace-snapshot "$EVAL_WORKSPACE_SNAPSHOT" \
  --source-tarball "$EVAL_SOURCE_TARBALL" \
  --protected-home "$EVAL_PROTECTED_HOME" \
  --output-dir "$EVAL_OUTPUT_DIR" \
  "${extra_args[@]}"
EOF

echo "==> Build evaluation image (target=build): $IMAGE_NAME"
DOCKER_BUILDKIT=1 "${DOCKER_CMD[@]}" build --target build -t "$IMAGE_NAME" -f "$ROOT_DIR/Dockerfile" "$ROOT_DIR"

mkdir -p "$OUTPUT_DIR"

echo "==> Run TDX fixed-sequence evaluation inside container"
echo "    Config dir: $CONFIG_DIR"
echo "    Eval root: $EVAL_ROOT"
echo "    Output dir: $OUTPUT_DIR"
echo "    Protected fixture home: $PROTECTED_HOME"
echo "    Docker cmd: ${DOCKER_CMD[*]}"
echo "    Container uid:gid: $CONTAINER_UID_GID"

"${DOCKER_CMD[@]}" run --rm -t \
  -u "$CONTAINER_UID_GID" \
  --entrypoint bash \
  -e COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
  -e HOME=/home/node \
  -e NODE_OPTIONS=--disable-warning=ExperimentalWarning \
  -e TDX_BACKEND_BASE_URL="$TDX_BACKEND_BASE_URL" \
  -e EVAL_WORKSPACE_SNAPSHOT="$CONTAINER_WORKSPACE_SNAPSHOT" \
  -e EVAL_SOURCE_TARBALL="$CONTAINER_SOURCE_TARBALL" \
  -e EVAL_PROTECTED_HOME="$CONTAINER_PROTECTED_HOME" \
  -e EVAL_OUTPUT_DIR="$CONTAINER_OUTPUT_DIR" \
  -v "$ROOT_DIR":/src:ro \
  -v "$CONFIG_DIR":/home/node/.openclaw \
  -v "$EVAL_ROOT":/eval-root \
  "$IMAGE_NAME" \
  -lc "$CONTAINER_CMD"

echo "==> Container evaluation finished"
echo "    JSON: $OUTPUT_DIR/results.json"
echo "    Markdown: $OUTPUT_DIR/report.md"
