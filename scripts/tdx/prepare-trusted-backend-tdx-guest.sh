#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(realpath -m "${SCRIPT_DIR}/../..")

ARTIFACT_DIR="${TMPDIR:-/tmp}/openclaw-tdx-trusted-backend"
CANONICAL_TDX_DIR=""
BASE_IMAGE=""
UBUNTU_VERSION="24.04"
BACKEND_PORT="19090"
TDX_GUEST_ID=""
ATTESTATION_COMMAND=""
ATTESTATION_FILE=""
FORCE="0"
USE_EXISTING_BASE_IMAGE="0"

OUTPUT_IMAGE=""
STANDALONE_DIR=""
BACKEND_TARBALL=""
PUBLIC_KEY_PATH=""
HOST_CONFIG_PATH=""

usage() {
  cat <<'EOF'
Usage: prepare-trusted-backend-tdx-guest.sh [options]

Prepare a Canonical TDX guest image with the standalone OpenClaw trusted
backend preinstalled and ed25519 signing enabled.

Options:
  --canonical-tdx-dir PATH   Path to a canonical/tdx checkout
  --base-image PATH          Existing TDX-enabled qcow2 image
  --ubuntu-version VERSION   Ubuntu guest version when auto-creating a TD image
                             (default: 24.04)
  --artifact-dir PATH        Output directory for image and exported assets
  --output-image PATH        Final prepared qcow2 path
  --backend-port PORT        Backend listen port (default: 19090)
  --tdx-guest-id ID          Optional TRUSTED_TDX_GUEST_ID override
  --attestation-command CMD  Optional guest attestation command
  --attestation-file PATH    Optional attestation JSON copied into the guest
  --force                    Recreate generated artifacts
  -h, --help                 Show this help

Examples:
  sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
    --canonical-tdx-dir /srv/tdx \
    --ubuntu-version 24.04 \
    --artifact-dir /var/tmp/openclaw-tdx

  sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
    --base-image /srv/tdx/guest-tools/image/tdx-guest-ubuntu-24.04-generic.qcow2 \
    --artifact-dir /var/tmp/openclaw-tdx
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "required command not found: $1"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --canonical-tdx-dir)
        CANONICAL_TDX_DIR="$(realpath -m "${2:-}")"
        shift 2
        ;;
      --base-image)
        BASE_IMAGE="$(realpath -m "${2:-}")"
        USE_EXISTING_BASE_IMAGE="1"
        shift 2
        ;;
      --ubuntu-version)
        UBUNTU_VERSION="${2:-}"
        shift 2
        ;;
      --artifact-dir)
        ARTIFACT_DIR="$(realpath -m "${2:-}")"
        shift 2
        ;;
      --output-image)
        OUTPUT_IMAGE="$(realpath -m "${2:-}")"
        shift 2
        ;;
      --backend-port)
        BACKEND_PORT="${2:-}"
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
        ATTESTATION_FILE="$(realpath -m "${2:-}")"
        shift 2
        ;;
      --force)
        FORCE="1"
        shift
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

  if [[ ! "${BACKEND_PORT}" =~ ^[0-9]+$ ]]; then
    die "--backend-port must be numeric"
  fi
  if [[ -n "${ATTESTATION_FILE}" && ! -f "${ATTESTATION_FILE}" ]]; then
    die "attestation file not found: ${ATTESTATION_FILE}"
  fi
}

resolve_paths() {
  install -d -m 0755 "${ARTIFACT_DIR}"
  STANDALONE_DIR="${ARTIFACT_DIR}/openclaw-trusted-backend"
  BACKEND_TARBALL="${ARTIFACT_DIR}/openclaw-trusted-backend.tgz"
  PUBLIC_KEY_PATH="${ARTIFACT_DIR}/ed25519-public.pem"
  HOST_CONFIG_PATH="${ARTIFACT_DIR}/openclaw-trusted-isolation.host.json"

  if [[ -z "${BASE_IMAGE}" ]]; then
    BASE_IMAGE="${ARTIFACT_DIR}/tdx-guest-ubuntu-${UBUNTU_VERSION}-generic.qcow2"
  fi
  if [[ -z "${OUTPUT_IMAGE}" ]]; then
    OUTPUT_IMAGE="${ARTIFACT_DIR}/openclaw-trusted-backend-tdx-ubuntu-${UBUNTU_VERSION}.qcow2"
  fi

  if [[ "${BASE_IMAGE}" == "${OUTPUT_IMAGE}" ]]; then
    die "--output-image must differ from the base image"
  fi
}

preflight() {
  require_cmd bash
  require_cmd node
  require_cmd tar
  require_cmd qemu-img
  require_cmd virt-customize
  require_cmd virt-cat

  if [[ "${USE_EXISTING_BASE_IMAGE}" != "1" ]]; then
    [[ -n "${CANONICAL_TDX_DIR}" ]] || \
      die "--canonical-tdx-dir is required when --base-image is not provided"
    if [[ "${CANONICAL_TDX_DIR}" == "/path/to/tdx" ]]; then
      die "--canonical-tdx-dir still points at the docs placeholder '/path/to/tdx'; replace it with a real canonical/tdx checkout"
    fi
    if [[ ! -d "${CANONICAL_TDX_DIR}" ]]; then
      die "canonical/tdx checkout not found at ${CANONICAL_TDX_DIR}; clone it first, for example: git clone https://github.com/canonical/tdx ${CANONICAL_TDX_DIR}"
    fi
    if [[ ! -x "${CANONICAL_TDX_DIR}/guest-tools/image/create-td-image.sh" ]]; then
      die "canonical create-td-image.sh not found under ${CANONICAL_TDX_DIR}; expected a canonical/tdx checkout with guest-tools/image/create-td-image.sh"
    fi
  fi
}

maybe_remove() {
  local target="$1"
  if [[ "${FORCE}" == "1" ]]; then
    rm -rf "${target}"
  elif [[ -e "${target}" ]]; then
    die "refusing to overwrite existing path without --force: ${target}"
  fi
}

prepare_base_image() {
  if [[ "${USE_EXISTING_BASE_IMAGE}" == "1" ]]; then
    [[ -f "${BASE_IMAGE}" ]] || die "base image not found: ${BASE_IMAGE}"
    return
  fi

  if [[ -f "${BASE_IMAGE}" && "${FORCE}" != "1" ]]; then
    return
  fi
  if [[ -z "${CANONICAL_TDX_DIR}" ]]; then
    die "base image is missing and no canonical/tdx checkout was provided"
  fi

  rm -f "${BASE_IMAGE}"
  local -a create_cmd=(
    ./create-td-image.sh
    -v "${UBUNTU_VERSION}"
    -o "${BASE_IMAGE}"
  )
  if [[ "${FORCE}" == "1" ]]; then
    create_cmd+=(-f)
  fi

  (
    cd "${CANONICAL_TDX_DIR}/guest-tools/image"
    "${create_cmd[@]}"
  )
}

scaffold_backend() {
  maybe_remove "${STANDALONE_DIR}"
  rm -f "${BACKEND_TARBALL}"

  node "${REPO_ROOT}/scripts/scaffold-trusted-backend-standalone.mjs" \
    --target "${STANDALONE_DIR}" \
    --force >/dev/null
  tar -C "${STANDALONE_DIR}" -czf "${BACKEND_TARBALL}" .
}

create_overlay_image() {
  maybe_remove "${OUTPUT_IMAGE}"
  qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMAGE}" "${OUTPUT_IMAGE}" >/dev/null
}

customize_image() {
  local bootstrap_dir="/opt/openclaw-trusted-backend-bootstrap"
  local guest_attestation_path=""
  local install_script="${REPO_ROOT}/scripts/tdx/install-trusted-backend-guest.sh"
  local tdx_attestation_helper_source="${REPO_ROOT}/scripts/tdx/openclaw-tdx-attest.c"
  local -a install_cmd=(
    /bin/bash
    "${bootstrap_dir}/install-trusted-backend-guest.sh"
    --backend-tar "${bootstrap_dir}/openclaw-trusted-backend.tgz"
    --backend-port "${BACKEND_PORT}"
    --verify-mode ed25519
  )
  local -a virt_customize_args=(
    -a "${OUTPUT_IMAGE}"
    --mkdir "${bootstrap_dir}"
    --copy-in "${BACKEND_TARBALL}:${bootstrap_dir}"
    --copy-in "${install_script}:${bootstrap_dir}"
    --copy-in "${tdx_attestation_helper_source}:${bootstrap_dir}"
    --run-command "chmod 0755 ${bootstrap_dir}/install-trusted-backend-guest.sh"
  )

  if [[ -n "${TDX_GUEST_ID}" ]]; then
    install_cmd+=(--tdx-guest-id "${TDX_GUEST_ID}")
  fi
  if [[ -n "${ATTESTATION_COMMAND}" ]]; then
    install_cmd+=(--attestation-command "${ATTESTATION_COMMAND}")
  fi
  if [[ -n "${ATTESTATION_FILE}" ]]; then
    guest_attestation_path="${bootstrap_dir}/$(basename "${ATTESTATION_FILE}")"
    virt_customize_args+=(--copy-in "${ATTESTATION_FILE}:${bootstrap_dir}")
    install_cmd+=(--attestation-file "${guest_attestation_path}")
  fi

  local install_cmd_str=""
  printf -v install_cmd_str '%q ' "${install_cmd[@]}"
  virt_customize_args+=(--run-command "${install_cmd_str% }")
  virt_customize_args+=(--run-command "rm -rf ${bootstrap_dir}")

  virt-customize "${virt_customize_args[@]}"
}

flatten_output_image() {
  # Remove the backing-file chain so libvirt/qemu only needs to open one qcow2.
  qemu-img rebase -f qcow2 -b "" "${OUTPUT_IMAGE}"
}

export_public_key() {
  virt-cat -a "${OUTPUT_IMAGE}" /etc/openclaw-trusted-backend/ed25519-public.pem > "${PUBLIC_KEY_PATH}"
}

write_host_config() {
  node - <<'NODE' "${HOST_CONFIG_PATH}" "${PUBLIC_KEY_PATH}" "${BACKEND_PORT}"
const fs = require("node:fs");

const [outputPath, publicKeyPath, backendPort] = process.argv.slice(2);
const publicKeyPem = fs.readFileSync(publicKeyPath, "utf8");
const payload = {
  tools: {
    trustedIsolation: {
      enabled: true,
      enforceFailClosed: true,
      backendBaseUrl: `http://<tdx-guest-ip>:${backendPort}`,
      authorizePath: "/v1/trusted/authorize",
      completePath: "/v1/trusted/complete",
      requestTimeoutMs: 5000,
      ttlMs: 5000,
      verify: {
        mode: "ed25519",
        publicKeyPem,
        requireScopeToken: true,
      },
      forceTrustedActions: ["exec"],
    },
  },
};
fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
NODE
}

print_summary() {
  echo "Prepared TDX guest image: ${OUTPUT_IMAGE}"
  echo "Guest base image: ${BASE_IMAGE}"
  echo "Guest public key: ${PUBLIC_KEY_PATH}"
  echo "Host config snippet: ${HOST_CONFIG_PATH}"
  if [[ -n "${CANONICAL_TDX_DIR}" ]]; then
    echo "Boot with Canonical tdvirsh:"
    echo "  sudo ${REPO_ROOT}/scripts/tdx/configure-libvirt-tdx-host.sh --user ${SUDO_USER:-$USER}"
    echo "  ${REPO_ROOT}/scripts/tdx/run-canonical-tdvirsh.sh --canonical-tdx-dir ${CANONICAL_TDX_DIR} new --td-image ${OUTPUT_IMAGE}"
  fi
}

main() {
  parse_args "$@"
  resolve_paths
  preflight
  prepare_base_image
  scaffold_backend
  create_overlay_image
  customize_image
  flatten_output_image
  export_public_key
  write_host_config
  print_summary
}

main "$@"
