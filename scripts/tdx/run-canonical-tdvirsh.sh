#!/usr/bin/env bash

set -euo pipefail

CANONICAL_TDX_DIR=""
TDVIRSH_WORKDIR=""
TMP_SCRIPT=""
TDVIRSH_ARGS=()
QGS_CID=""
QGS_PORT="4050"
TD_MAC=""

usage() {
  cat <<'EOF'
Usage: run-canonical-tdvirsh.sh --canonical-tdx-dir PATH [--workdir PATH] [--qgs-cid CID] [--qgs-port PORT] [--mac AA:BB:CC:DD:EE:FF] <tdvirsh args...>

Wrap Canonical's guest-tools/tdvirsh with a user-specific workdir so OpenClaw's
TDX guest boots do not depend on the shared /var/tmp/tdvirsh directory.

Examples:
  scripts/tdx/run-canonical-tdvirsh.sh \
    --canonical-tdx-dir ~/canonical-tdx \
    new --td-image /var/tmp/openclaw-tdx/openclaw-trusted-backend-tdx-ubuntu-24.04.qcow2

  scripts/tdx/run-canonical-tdvirsh.sh \
    --canonical-tdx-dir ~/canonical-tdx \
    list

By default the wrapper auto-detects which host-local AF_VSOCK CID can actually
reach qgsd on the chosen port and rewrites the generated libvirt XML to use it.
If you pass --mac, the wrapper also pins the guest NIC MAC so libvirt DHCP
reservations can keep the TD on a stable IP across delete/new cycles.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TMP_SCRIPT}" && -f "${TMP_SCRIPT}" ]]; then
    rm -f "${TMP_SCRIPT}"
  fi
}
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --canonical-tdx-dir)
        CANONICAL_TDX_DIR="${2:-}"
        shift 2
        ;;
      --workdir)
        TDVIRSH_WORKDIR="${2:-}"
        shift 2
        ;;
      --qgs-cid)
        QGS_CID="${2:-}"
        shift 2
        ;;
      --qgs-port)
        QGS_PORT="${2:-}"
        shift 2
        ;;
      --mac)
        TD_MAC="${2:-}"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        break
        ;;
      *)
        break
        ;;
    esac
  done

  [[ -n "${CANONICAL_TDX_DIR}" ]] || die "--canonical-tdx-dir is required"
  CANONICAL_TDX_DIR="$(realpath -m "${CANONICAL_TDX_DIR}")"
  [[ -x "${CANONICAL_TDX_DIR}/guest-tools/tdvirsh" ]] || \
    die "canonical tdvirsh not found at ${CANONICAL_TDX_DIR}/guest-tools/tdvirsh"

  if [[ $# -eq 0 ]]; then
    die "missing tdvirsh arguments (for example: new --td-image ...)"
  fi

  if [[ -z "${TDVIRSH_WORKDIR}" ]]; then
    TDVIRSH_WORKDIR="/var/tmp/openclaw-tdvirsh-${USER}"
  fi
  if [[ -n "${TD_MAC}" ]]; then
    [[ "${TD_MAC}" =~ ^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$ ]] || \
      die "--mac must be formatted like AA:BB:CC:DD:EE:FF"
    TD_MAC="${TD_MAC,,}"
  fi

  TDVIRSH_ARGS=("$@")
}

detect_qgs_cid() {
  if [[ -n "${QGS_CID}" ]]; then
    return
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    QGS_CID="1"
    return
  fi

  local detected=""
  detected="$(python3 - "${QGS_PORT}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
for cid in (1, 2):
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((cid, port))
    except OSError:
        continue
    else:
        print(cid)
        sock.close()
        sys.exit(0)
print("")
PY
)"

  if [[ -n "${detected}" ]]; then
    QGS_CID="${detected}"
  else
    QGS_CID="1"
  fi
}

preflight() {
  if [[ "${EUID}" -eq 0 ]]; then
    die "run this wrapper as the non-root libvirt user, not via sudo"
  fi
  if ! virsh -c qemu:///system list --all >/dev/null 2>&1; then
    die "cannot access qemu:///system as ${USER}; run scripts/tdx/configure-libvirt-tdx-host.sh and then open a new shell"
  fi
  install -d -m 0775 "${TDVIRSH_WORKDIR}"
  if [[ ! -w "${TDVIRSH_WORKDIR}" ]]; then
    die "workdir is not writable: ${TDVIRSH_WORKDIR}"
  fi
  detect_qgs_cid
}

patch_tdvirsh() {
  TMP_SCRIPT="$(mktemp)"
  python3 - \
    "${CANONICAL_TDX_DIR}/guest-tools/tdvirsh" \
    "${TMP_SCRIPT}" \
    "${CANONICAL_TDX_DIR}/guest-tools" \
    "${TDVIRSH_WORKDIR%/}/" \
    "${QGS_CID}" \
    "${QGS_PORT}" \
    "${TD_MAC}" <<'PYGEN'
from pathlib import Path
import sys

src_path, dst_path, script_dir, workdir, qgs_cid, qgs_port, td_mac = sys.argv[1:]
lines = Path(src_path).read_text().splitlines()

injected_block = f"""
QGS_CID="{qgs_cid}"
QGS_PORT="{qgs_port}"
TD_MAC="{td_mac}"

patch_domain_xml() {{
    local xml_path="${{WORKDIR_PATH}}/${{DOMAIN_PREFIX}}.xml"
    [[ -f "${{xml_path}}" ]] || return
    python3 - "${{xml_path}}" "${{QGS_CID}}" "${{QGS_PORT}}" "${{TD_MAC}}" <<'PY2'
from pathlib import Path
import re
import sys

xml_path, qgs_cid, qgs_port, td_mac = sys.argv[1:]
xml = Path(xml_path).read_text()
xml, replacements = re.subn(
    r"(<SocketAddress[^>]*type='vsock'[^>]*cid=')[^']+(' port=')[^']+('/?>)",
    lambda match: match.group(1) + qgs_cid + match.group(2) + qgs_port + match.group(3),
    xml,
    count=1,
)
if replacements != 1:
    raise SystemExit(f"failed to rewrite quote-generation socket in {{xml_path}}")
if td_mac:
    xml, mac_replacements = re.subn(
        r"(<interface[^>]*type='network'[^>]*>\s*)(<mac address='[^']+'/>\s*)?",
        lambda match: match.group(1) + f"<mac address='{td_mac}'/>\\n      ",
        xml,
        count=1,
    )
    if mac_replacements != 1:
        raise SystemExit(f"failed to rewrite guest NIC MAC in {{xml_path}}")
Path(xml_path).write_text(xml)
PY2
}}

run_td() {{
    echo "Create and run new virsh domain from ${{base_img_path}} and ${{xml_template_path}} "
    echo "---"
    echo "Using quote-generation socket vsock CID ${{QGS_CID}} port ${{QGS_PORT}}"
    if [[ -n "${{TD_MAC}}" ]]; then
        echo "Using guest NIC MAC ${{TD_MAC}}"
    fi
    attach_gpus ${{gpus}}
    check_input_paths
    create_overlay_image
    create_domain_xml
    patch_domain_xml || exit 1
    boot_vm
    virsh dominfo "${{created_domain}}"
}}
""".strip("\n").splitlines()

out = []
for line in lines:
    if line.startswith("SCRIPT_DIR="):
        out.append(f"SCRIPT_DIR={script_dir}")
        continue
    if line.startswith("WORKDIR_PATH=/var/tmp/tdvirsh/"):
        out.append(f"WORKDIR_PATH={workdir}")
        continue
    if line == 'parse_params "$@"':
        out.extend(injected_block)
        out.append("")
        out.append(line)
        continue
    out.append(line)

Path(dst_path).write_text("\n".join(out) + "\n")
PYGEN
  chmod 0755 "${TMP_SCRIPT}"
}

main() {
  parse_args "$@"
  preflight
  patch_tdvirsh
  exec "${TMP_SCRIPT}" "${TDVIRSH_ARGS[@]}"
}

main "$@"
