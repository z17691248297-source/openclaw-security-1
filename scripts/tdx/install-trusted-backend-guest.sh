#!/usr/bin/env bash

set -euo pipefail

readonly SERVICE_USER="openclaw-trusted"
readonly SERVICE_GROUP="openclaw-trusted"
readonly SERVICE_NAME="openclaw-trusted-backend"
readonly INSTALL_DIR="/opt/openclaw-trusted-backend"
readonly CONFIG_DIR="/etc/openclaw-trusted-backend"
readonly STATE_DIR="/var/lib/openclaw-trusted-backend"
readonly ENV_FILE="${CONFIG_DIR}/openclaw-trusted-backend.env"
readonly SERVICE_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
readonly DEFAULT_TDX_ATTESTATION_COMMAND="/usr/local/bin/openclaw-tdx-attest"
readonly DEFAULT_TDX_ATTESTATION_SOURCE="openclaw-tdx-attest.c"
readonly TDX_DEVICE_UDEV_RULE="/etc/udev/rules.d/90-openclaw-tdx-attest.rules"
readonly TDX_ATTEST_CONF="/etc/tdx-attest.conf"
readonly DEFAULT_QGS_PORT="4050"

BACKEND_TAR=""
BACKEND_PORT="19090"
VERIFY_MODE="ed25519"
TDX_GUEST_ID=""
ATTESTATION_COMMAND=""
ATTESTATION_FILE=""
NODE_PATH=""

usage() {
  cat <<'EOF'
Usage: install-trusted-backend-guest.sh --backend-tar PATH [options]

Install the standalone OpenClaw trusted backend into an Ubuntu guest image or
running guest.

Options:
  --backend-tar PATH          Path to openclaw-trusted-backend.tgz
  --backend-port PORT         Backend listen port (default: 19090)
  --verify-mode MODE          Verify mode: ed25519 (default)
  --tdx-guest-id ID           Optional TRUSTED_TDX_GUEST_ID override
  --attestation-command CMD   Optional TRUSTED_TDX_ATTESTATION_COMMAND
                              If set to /usr/local/bin/openclaw-tdx-attest,
                              compile the bundled libtdx_attest helper
  --attestation-file PATH     Optional JSON attestation payload copied into guest
  -h, --help                  Show this help
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run this installer as root"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --backend-tar)
        BACKEND_TAR="${2:-}"
        shift 2
        ;;
      --backend-port)
        BACKEND_PORT="${2:-}"
        shift 2
        ;;
      --verify-mode)
        VERIFY_MODE="${2:-}"
        shift 2
        ;;
      --tdx-guest-id)
        TDX_GUEST_ID="${2:-}"
        shift 2
        ;;
      --attestation-command)
        ATTESTATION_COMMAND="${2:-}"
        shift 2
        ;;
      --attestation-file)
        ATTESTATION_FILE="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done

  if [[ -z "${BACKEND_TAR}" ]]; then
    die "--backend-tar is required"
  fi
  if [[ ! -f "${BACKEND_TAR}" ]]; then
    die "backend tarball not found: ${BACKEND_TAR}"
  fi
  if [[ "${VERIFY_MODE}" != "ed25519" ]]; then
    die "only --verify-mode ed25519 is supported by this installer"
  fi
  if [[ ! "${BACKEND_PORT}" =~ ^[0-9]+$ ]]; then
    die "--backend-port must be numeric"
  fi
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
}

ensure_tdx_attestation_build_deps() {
  if command -v cc >/dev/null 2>&1 && [[ -f /usr/include/tdx_attest.h ]]; then
    return
  fi
  apt_install build-essential libtdx-attest-dev
}

node_major() {
  if ! command -v node >/dev/null 2>&1; then
    return 1
  fi
  node -p 'Number(process.versions.node.split(".")[0])' 2>/dev/null
}

ensure_node() {
  if major="$(node_major 2>/dev/null)" && [[ -n "${major}" ]] && (( major >= 22 )); then
    NODE_PATH="$(command -v node)"
    return
  fi

  apt_install ca-certificates curl gnupg openssl
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  chmod 0644 /etc/apt/keyrings/nodesource.gpg
  cat > /etc/apt/sources.list.d/nodesource.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main
EOF
  apt_install nodejs openssl

  if ! major="$(node_major 2>/dev/null)" || [[ -z "${major}" ]] || (( major < 22 )); then
    die "node >= 22 is required after installation"
  fi
  NODE_PATH="$(command -v node)"
}

ensure_service_account() {
  if ! getent group "${SERVICE_GROUP}" >/dev/null; then
    groupadd --system "${SERVICE_GROUP}"
  fi
  if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd \
      --system \
      --gid "${SERVICE_GROUP}" \
      --home-dir "${STATE_DIR}" \
      --no-create-home \
      --shell /usr/sbin/nologin \
      "${SERVICE_USER}"
  fi
}

prepare_runtime_dirs() {
  install -d -m 0755 "${INSTALL_DIR}"
  install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${CONFIG_DIR}"
  install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${STATE_DIR}"
}

install_backend_payload() {
  find "${INSTALL_DIR}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
  tar -xzf "${BACKEND_TAR}" -C "${INSTALL_DIR}"
  chmod -R a+rX "${INSTALL_DIR}"
}

quote_env_value() {
  local value="${1//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//\$/\\$}"
  value="${value//\`/\\\`}"
  printf '"%s"' "${value}"
}

install_attestation_file() {
  if [[ -z "${ATTESTATION_FILE}" ]]; then
    return
  fi
  if [[ ! -f "${ATTESTATION_FILE}" ]]; then
    die "attestation file not found: ${ATTESTATION_FILE}"
  fi
  local final_path="${CONFIG_DIR}/tdx-attestation.json"
  install -D -m 0640 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" \
    "${ATTESTATION_FILE}" \
    "${final_path}"
  ATTESTATION_FILE="${final_path}"
}

install_default_attestation_command() {
  if [[ "${ATTESTATION_COMMAND}" != "${DEFAULT_TDX_ATTESTATION_COMMAND}" ]]; then
    return
  fi

  local script_dir helper_source
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  helper_source="${script_dir}/${DEFAULT_TDX_ATTESTATION_SOURCE}"
  [[ -f "${helper_source}" ]] || die "attestation helper source not found: ${helper_source}"

  ensure_tdx_attestation_build_deps
  install -d -m 0755 /usr/local/bin
  cc -O2 -Wall -Wextra -std=c11 \
    "${helper_source}" \
    -ltdx_attest \
    -o "${DEFAULT_TDX_ATTESTATION_COMMAND}"
  chmod 0755 "${DEFAULT_TDX_ATTESTATION_COMMAND}"
}

install_tdx_device_access_rule() {
  if [[ "${ATTESTATION_COMMAND}" != "${DEFAULT_TDX_ATTESTATION_COMMAND}" ]]; then
    return
  fi

  cat > "${TDX_DEVICE_UDEV_RULE}" <<EOF
SUBSYSTEM=="misc",KERNEL=="tdx-guest",GROUP="${SERVICE_GROUP}",MODE="0660"
SUBSYSTEM=="misc",KERNEL=="tdx_guest",GROUP="${SERVICE_GROUP}",MODE="0660"
SUBSYSTEM=="misc",KERNEL=="tdx-attest",GROUP="${SERVICE_GROUP}",MODE="0660"
EOF
  chmod 0644 "${TDX_DEVICE_UDEV_RULE}"

  if command -v udevadm >/dev/null 2>&1; then
    udevadm control --reload-rules || true
    udevadm trigger --subsystem-match=misc || true
  fi

  for dev in /dev/tdx-guest /dev/tdx_guest /dev/tdx-attest; do
    if [[ -e "${dev}" ]]; then
      chgrp "${SERVICE_GROUP}" "${dev}" || true
      chmod 0660 "${dev}" || true
    fi
  done
}

write_tdx_attest_conf() {
  if [[ "${ATTESTATION_COMMAND}" != "${DEFAULT_TDX_ATTESTATION_COMMAND}" ]]; then
    return
  fi

  cat > "${TDX_ATTEST_CONF}" <<EOF
port=${DEFAULT_QGS_PORT}
EOF
  chmod 0644 "${TDX_ATTEST_CONF}"
}

ensure_signing_keys() {
  local private_key="${CONFIG_DIR}/ed25519-private.pem"
  local public_key="${CONFIG_DIR}/ed25519-public.pem"
  if [[ ! -s "${private_key}" ]]; then
    openssl genpkey -algorithm ED25519 -out "${private_key}"
  fi
  openssl pkey -in "${private_key}" -pubout -out "${public_key}"
  chown "${SERVICE_USER}:${SERVICE_GROUP}" "${private_key}" "${public_key}"
  chmod 0600 "${private_key}"
  chmod 0644 "${public_key}"
}

write_env_file() {
  cat > "${ENV_FILE}" <<EOF
TRUSTED_BACKEND_HOST=0.0.0.0
TRUSTED_BACKEND_PORT=${BACKEND_PORT}
TRUSTED_BACKEND_ADAPTOR=local-tdx
TRUSTED_POLICY_PATH=${INSTALL_DIR}/policy.json
TRUSTED_BACKEND_EVENTS_FILE=${STATE_DIR}/trusted-backend-events.jsonl
TRUSTED_VERIFY_MODE=ed25519
TRUSTED_SIGNING_PRIVATE_KEY_FILE=${CONFIG_DIR}/ed25519-private.pem
TRUSTED_TDX_SERVICE_NAME=${SERVICE_NAME}
EOF

  if [[ -n "${TDX_GUEST_ID}" ]]; then
    printf 'TRUSTED_TDX_GUEST_ID=%s\n' "$(quote_env_value "${TDX_GUEST_ID}")" >> "${ENV_FILE}"
  fi
  if [[ -n "${ATTESTATION_COMMAND}" ]]; then
    printf 'TRUSTED_TDX_ATTESTATION_COMMAND=%s\n' \
      "$(quote_env_value "${ATTESTATION_COMMAND}")" >> "${ENV_FILE}"
  fi
  if [[ -n "${ATTESTATION_FILE}" ]]; then
    printf 'TRUSTED_TDX_ATTESTATION_FILE=%s\n' \
      "$(quote_env_value "${ATTESTATION_FILE}")" >> "${ENV_FILE}"
  fi

  chown "${SERVICE_USER}:${SERVICE_GROUP}" "${ENV_FILE}"
  chmod 0640 "${ENV_FILE}"
}

install_service_unit() {
  local example_unit="${INSTALL_DIR}/openclaw-trusted-backend.service.example"
  [[ -f "${example_unit}" ]] || die "service unit template not found in backend payload"

  install -D -m 0644 "${example_unit}" "${SERVICE_UNIT_PATH}"
  if [[ -n "${NODE_PATH}" && "${NODE_PATH}" != "/usr/bin/node" ]]; then
    sed -i "s|/usr/bin/node|${NODE_PATH}|g" "${SERVICE_UNIT_PATH}"
  fi
}

enable_service() {
  install -d -m 0755 /etc/systemd/system/multi-user.target.wants
  ln -sfn "../${SERVICE_NAME}.service" \
    "/etc/systemd/system/multi-user.target.wants/${SERVICE_NAME}.service"

  if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable --now "${SERVICE_NAME}.service"
  fi
}

main() {
  parse_args "$@"
  require_root
  ensure_node
  ensure_service_account
  prepare_runtime_dirs
  install_backend_payload
  install_attestation_file
  install_default_attestation_command
  install_tdx_device_access_rule
  write_tdx_attest_conf
  ensure_signing_keys
  write_env_file
  install_service_unit
  enable_service

  echo "Installed ${SERVICE_NAME} to ${INSTALL_DIR}"
  echo "Public key: ${CONFIG_DIR}/ed25519-public.pem"
  echo "Service unit: ${SERVICE_UNIT_PATH}"
}

main "$@"
