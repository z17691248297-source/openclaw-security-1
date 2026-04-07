#!/usr/bin/env bash

set -euo pipefail

HAS_BLOCKER="0"
SHOW_LOGS="0"
REGISTRATION_READY="0"

readonly PCCS_CONFIG="/opt/intel/sgx-dcap-pccs/config/default.json"
readonly MPA_CONFIG="/etc/mpa_registration.conf"
readonly PCCS_PACKAGE_JSON="/opt/intel/sgx-dcap-pccs/package.json"
readonly QCNL_CONFIG="/etc/sgx_default_qcnl.conf"
readonly QGS_CONFIG="/etc/qgs.conf"
readonly LIBVIRT_QEMU_APPARMOR="/etc/apparmor.d/abstractions/libvirt-qemu"
readonly EXPECTED_QGS_PORT="4050"

usage() {
  cat <<'EOF'
Usage: check-attestation-host.sh [options]

Check host-side Intel TDX quote-generation prerequisites for an OpenClaw TDX
guest deployment.

This script does not change host state. It reports the common blockers behind:

- guest `/usr/share/doc/libtdx-attest-dev/examples/test_tdx_attest`
  printing `Failed to get the quote`
- libvirt/qemu logging `Failed to connect to '2:4050': Permission denied`
- `curl http://<tdx-guest-ip>:19090/v1/trusted/guest?attest=1` failing once the
  guest backend is wired to a real attestation command

Options:
  --show-logs   Include recent qgsd/pccs journal snippets when checks fail
  -h, --help    Show this help
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

mark_blocker() {
  HAS_BLOCKER="1"
  printf 'BLOCKER: %s\n' "$*"
}

mark_ok() {
  printf 'OK: %s\n' "$*"
}

mark_note() {
  printf 'NOTE: %s\n' "$*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run this script as root so it can inspect systemd and journal details"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --show-logs)
        SHOW_LOGS="1"
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
}

check_path() {
  local path="$1"
  if [[ -e "${path}" ]]; then
    mark_ok "${path} exists"
  else
    mark_blocker "${path} is missing"
  fi
}

check_reboot_required() {
  if [[ -e /run/reboot-required || -e /var/run/reboot-required ]]; then
    mark_blocker "host reboot is still pending; reboot before retrying quote generation"
    if [[ -f /run/reboot-required.pkgs ]]; then
      mark_note "reboot-required packages:"
      sed 's/^/  - /' /run/reboot-required.pkgs
    fi
  else
    mark_ok "no pending reboot marker is present"
  fi
}

service_is_active() {
  local service="$1"
  systemctl is-active --quiet "${service}"
}

service_is_enabled() {
  local service="$1"
  systemctl is-enabled --quiet "${service}"
}

print_service_summary() {
  local service="$1"
  local active="inactive"
  local enabled="disabled"
  if service_is_active "${service}"; then
    active="active"
  fi
  if service_is_enabled "${service}"; then
    enabled="enabled"
  fi
  printf 'INFO: %s active=%s enabled=%s\n' "${service}" "${active}" "${enabled}"
}

check_service() {
  local service="$1"
  print_service_summary "${service}"
  if service_is_active "${service}"; then
    mark_ok "${service} is active"
  else
    mark_blocker "${service} is not active"
    if [[ "${SHOW_LOGS}" == "1" ]]; then
      mark_note "recent ${service} logs:"
      journalctl -u "${service}" -n 20 --no-pager | sed 's/^/  /'
    fi
  fi
}

check_file_hint() {
  local path="$1"
  local label="$2"
  if [[ -f "${path}" ]]; then
    mark_ok "${label} exists at ${path}"
  else
    mark_blocker "${label} is missing at ${path}"
  fi
}

semver_satisfies_range() {
  local current="$1"
  local range="$2"
  node - "${current}" "${range}" <<'NODE'
const [, , currentRaw, rangeRaw] = process.argv;

function parseSemver(raw) {
  const cleaned = String(raw).trim().replace(/^v/, "");
  const parts = cleaned.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length < 3 || parts.some((part) => !Number.isFinite(part))) {
    throw new Error(`invalid semver: ${raw}`);
  }
  return parts.slice(0, 3);
}

function compare(a, b) {
  for (let index = 0; index < 3; index += 1) {
    if (a[index] < b[index]) {
      return -1;
    }
    if (a[index] > b[index]) {
      return 1;
    }
  }
  return 0;
}

function testComparator(current, comparator, expected) {
  const relation = compare(current, parseSemver(expected));
  switch (comparator) {
    case ">":
      return relation > 0;
    case ">=":
      return relation >= 0;
    case "<":
      return relation < 0;
    case "<=":
      return relation <= 0;
    case "=":
    case "":
      return relation === 0;
    default:
      throw new Error(`unsupported comparator: ${comparator}`);
  }
}

const current = parseSemver(currentRaw);
const clauses = rangeRaw
  .split("||")
  .map((item) => item.trim())
  .filter(Boolean);
const ok = clauses.some((clause) => {
  const comparators = [...clause.matchAll(/(>=|<=|>|<|=)?\s*([0-9]+(?:\.[0-9]+){2})/g)];
  if (comparators.length === 0) {
    return false;
  }
  return comparators.every(([, comparator = "", version]) =>
    testComparator(current, comparator, version),
  );
});
process.exit(ok ? 0 : 1);
NODE
}

check_pccs_node_runtime() {
  if [[ ! -f "${PCCS_PACKAGE_JSON}" ]]; then
    mark_note "PCCS package.json not found at ${PCCS_PACKAGE_JSON}; skipping node runtime check"
    return
  fi

  local node_cmd=""
  local exec_start=""
  exec_start="$(systemctl show -p ExecStart --value pccs.service 2>/dev/null || true)"
  if [[ -n "${exec_start}" ]]; then
    node_cmd="$(printf '%s\n' "${exec_start}" | sed -n 's/.*argv\[\]=\([^ ;][^ ;]*\).*/\1/p' | head -n 1)"
  fi
  if [[ -z "${node_cmd}" ]]; then
    node_cmd="$(command -v node 2>/dev/null || true)"
  fi
  if [[ -z "${node_cmd}" || ! -x "${node_cmd}" ]]; then
    mark_blocker "unable to determine the node runtime used by pccs.service"
    return
  fi

  local current_node
  current_node="$("${node_cmd}" -p 'process.version' 2>/dev/null || true)"
  local supported_range
  supported_range="$(node - "${PCCS_PACKAGE_JSON}" <<'NODE'
const fs = require("node:fs");
const pkg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(pkg?.engines?.node ?? "");
NODE
)"

  printf 'INFO: PCCS node runtime path=%s current=%s supported=%s\n' "${node_cmd}" "${current_node:-unknown}" "${supported_range:-unknown}"

  if [[ -z "${current_node}" || -z "${supported_range}" ]]; then
    mark_note "unable to determine PCCS node runtime compatibility"
    return
  fi

  if semver_satisfies_range "${current_node}" "${supported_range}"; then
    mark_ok "current node runtime is within the PCCS supported range"
  else
    mark_blocker "current node runtime ${current_node} is outside the PCCS supported range ${supported_range}"
  fi
}

check_qgs_port() {
  if [[ ! -f "${QGS_CONFIG}" ]]; then
    mark_blocker "QGS config is missing at ${QGS_CONFIG}"
    return
  fi

  local configured_port
  configured_port="$(sed -n 's/^[[:space:]]*port[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "${QGS_CONFIG}" | tail -n 1)"
  if [[ -z "${configured_port}" ]]; then
    mark_blocker "unable to determine qgsd port from ${QGS_CONFIG}"
    return
  fi

  printf 'INFO: qgsd configured port=%s expected=%s\n' "${configured_port}" "${EXPECTED_QGS_PORT}"

  if [[ "${configured_port}" == "${EXPECTED_QGS_PORT}" ]]; then
    mark_ok "qgsd is configured for the expected AF_VSOCK port"
  else
    mark_blocker "qgsd port ${configured_port} does not match the Canonical tdvirsh/libvirt expectation ${EXPECTED_QGS_PORT}"
  fi

  if command -v ss >/dev/null 2>&1; then
    local listener=""
    listener="$(ss --vsock -lpnH 2>/dev/null | awk -v suffix=":${EXPECTED_QGS_PORT}" '$5 ~ suffix "$" { print $5; exit }')"
    if [[ -n "${listener}" ]]; then
      mark_ok "AF_VSOCK listener is present on ${listener}"
    else
      mark_blocker "no AF_VSOCK listener is present on port ${EXPECTED_QGS_PORT}; restart qgsd after fixing ${QGS_CONFIG}"
    fi
  fi
}

check_qgs_local_cid() {
  if ! command -v python3 >/dev/null 2>&1; then
    mark_note "python3 is unavailable; skipping host-local AF_VSOCK CID probe"
    return
  fi

  local probe_output
  probe_output="$(python3 - "${EXPECTED_QGS_PORT}" <<'PY'
import socket
import sys

port = int(sys.argv[1])
for cid in (1, 2):
    try:
        sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((cid, port))
    except OSError as exc:
        print(f"{cid}:ERR:{exc.errno}:{exc.strerror}")
    else:
        print(f"{cid}:OK")
        sock.close()
PY
)"

  local cid1_status cid2_status
  cid1_status="$(printf '%s\n' "${probe_output}" | sed -n 's/^1:\([^:]*\).*/\1/p')"
  cid2_status="$(printf '%s\n' "${probe_output}" | sed -n 's/^2:\([^:]*\).*/\1/p')"

  if [[ "${cid1_status}" == "OK" ]]; then
    mark_ok "host-local QGS probe reaches AF_VSOCK CID 1 on port ${EXPECTED_QGS_PORT}"
  fi
  if [[ "${cid2_status}" == "OK" ]]; then
    mark_ok "host-local QGS probe reaches AF_VSOCK CID 2 on port ${EXPECTED_QGS_PORT}"
  fi

  if [[ "${cid1_status}" != "OK" && "${cid2_status}" != "OK" ]]; then
    mark_blocker "host-local QGS probe could not connect to AF_VSOCK CID 1 or 2 on port ${EXPECTED_QGS_PORT}"
    printf '%s\n' "${probe_output}" | sed 's/^/NOTE: qgs local probe /'
    return
  fi

  if [[ "${cid1_status}" == "OK" && "${cid2_status}" != "OK" ]]; then
    mark_note "on this host qgsd is reachable through local AF_VSOCK CID 1, not CID 2; recreate TDs with scripts/tdx/run-canonical-tdvirsh.sh so the wrapper rewrites the XML"
  fi
}

check_qcnl_pccs_connectivity() {
  if [[ ! -f "${QCNL_CONFIG}" ]]; then
    mark_note "QCNL config not found at ${QCNL_CONFIG}; skipping PCCS client check"
    return
  fi

  local qcnl_json
  qcnl_json="$(cat "${QCNL_CONFIG}")"
  local pccs_url use_secure_cert
  pccs_url="$(node - "${QCNL_CONFIG}" <<'NODE'
const fs = require("node:fs");
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(String(cfg?.pccs_url ?? ""));
NODE
)"
  use_secure_cert="$(node - "${QCNL_CONFIG}" <<'NODE'
const fs = require("node:fs");
const cfg = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
process.stdout.write(String(cfg?.use_secure_cert ?? ""));
NODE
)"

  if [[ -z "${pccs_url}" ]]; then
    mark_blocker "QCNL config at ${QCNL_CONFIG} does not define pccs_url"
    return
  fi

  printf 'INFO: QCNL pccs_url=%s use_secure_cert=%s\n' "${pccs_url}" "${use_secure_cert:-unknown}"

  local pccs_host pccs_port
  pccs_host="$(node - "${pccs_url}" <<'NODE'
const url = new URL(process.argv[2]);
process.stdout.write(url.hostname);
NODE
)"
  pccs_port="$(node - "${pccs_url}" <<'NODE'
const url = new URL(process.argv[2]);
process.stdout.write(url.port || (url.protocol === "https:" ? "443" : "80"));
NODE
)"

  local listeners=""
  listeners="$(ss -ltnH "( sport = :${pccs_port} )" 2>/dev/null | awk '{print $4}' || true)"
  if [[ -n "${listeners}" ]]; then
    local local_only="0"
    if printf '%s\n' "${listeners}" | rg -qx '127\.0\.0\.1:[0-9]+'; then
      local_only="1"
    fi
    if [[ "${local_only}" == "1" && "${pccs_host}" != "localhost" && "${pccs_host}" != "127.0.0.1" ]]; then
      mark_blocker "QCNL points to ${pccs_host}:${pccs_port}, but PCCS only listens on 127.0.0.1:${pccs_port}"
      return
    fi
  fi

  if ! command -v curl >/dev/null 2>&1; then
    mark_note "curl is unavailable; skipping direct PCCS probe"
    return
  fi

  local curl_code="0"
  local curl_output=""
  local curl_args=( -I --max-time 5 -sS "${pccs_url}" -o /dev/null )
  if [[ "${use_secure_cert}" == "false" ]]; then
    curl_args=( -k "${curl_args[@]}" )
  fi
  curl_output="$(curl "${curl_args[@]}" 2>&1)" || curl_code="$?"
  if [[ "${curl_code}" == "0" ]]; then
    mark_ok "QCNL can reach the configured PCCS URL"
    return
  fi

  if [[ "${curl_code}" == "7" ]]; then
    mark_blocker "QCNL cannot connect to PCCS at ${pccs_url}"
    return
  fi
  if [[ "${curl_code}" == "60" && "${use_secure_cert}" == "true" ]]; then
    mark_blocker "QCNL certificate verification fails for ${pccs_url}; use_secure_cert=true does not match the current PCCS certificate"
    return
  fi

  mark_note "direct PCCS probe for ${pccs_url} returned curl exit ${curl_code}: ${curl_output}"
}

apparmor_enabled() {
  if [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    local enabled
    enabled="$(tr -d '[:space:]' < /sys/module/apparmor/parameters/enabled)"
    [[ "${enabled}" =~ ^[Yy1]$ ]]
    return
  fi

  if command -v aa-enabled >/dev/null 2>&1; then
    aa-enabled >/dev/null 2>&1
    return
  fi

  if command -v aa-status >/dev/null 2>&1; then
    aa-status >/dev/null 2>&1
    return
  fi

  return 1
}

check_libvirt_vsock_policy() {
  if [[ ! -f "${LIBVIRT_QEMU_APPARMOR}" ]]; then
    mark_note "libvirt AppArmor abstraction not found at ${LIBVIRT_QEMU_APPARMOR}; skipping AF_VSOCK policy check"
    return
  fi

  if ! apparmor_enabled; then
    mark_note "AppArmor is not active; skipping libvirt AF_VSOCK policy check"
    return
  fi

  if rg -q -e '^[[:space:]]*network[[:space:]]+vsock([[:space:]]+stream)?[[:space:]]*,' "${LIBVIRT_QEMU_APPARMOR}"; then
    mark_ok "libvirt AppArmor allows AF_VSOCK stream access"
    return
  fi

  mark_blocker "libvirt AppArmor lacks AF_VSOCK access in ${LIBVIRT_QEMU_APPARMOR}; qemu can fail with Failed to connect to '2:4050': Permission denied"
  if [[ "${SHOW_LOGS}" == "1" ]]; then
    mark_note "recent kernel/libvirt denial hints:"
    journalctl -k -n 100 --no-pager | rg 'apparmor|DENIED|vsock|qemu-system|libvirt' | tail -n 20 | sed 's/^/  /' || true
  fi
}

check_platform_registration() {
  if ! command -v mpa_manage >/dev/null 2>&1; then
    mark_blocker "mpa_manage is unavailable; cannot verify platform registration"
    return
  fi

  local status_output
  status_output="$(mpa_manage -get_registration_status 2>&1 || true)"
  printf 'INFO: mpa_manage status: %s\n' "${status_output}"
  if [[ "${status_output}" == *"completed successfully"* ]]; then
    REGISTRATION_READY="1"
    mark_ok "platform registration completed successfully"
  elif [[ -n "${status_output}" ]]; then
    mark_blocker "platform registration is incomplete: ${status_output}"
  else
    mark_blocker "platform registration is incomplete"
  fi
}

print_next_steps() {
  echo
  echo "Suggested next steps:"
  if [[ -e /run/reboot-required || -e /var/run/reboot-required ]]; then
    echo "  1. Reboot the host and re-run this check."
  fi
  if ! service_is_active pccs.service; then
    echo "  2. Run /usr/bin/pccs-configure with your Intel PCS subscription key."
    echo "  3. Restart PCCS: systemctl restart pccs"
    echo "  4. Inspect PCCS logs: journalctl -u pccs -n 100 --no-pager"
  fi
  echo "  5. Ensure /etc/qgs.conf sets port = 4050 and restart QGS: systemctl restart qgsd"
  echo "  6. Run scripts/tdx/configure-libvirt-tdx-host.sh --user <your-user> to patch libvirt AppArmor for AF_VSOCK"
  echo "  7. If qemu still logs Failed to connect to '2:4050': Permission denied, inspect kernel denials:"
  echo "     journalctl -k --since '30 minutes ago' --no-pager | rg 'apparmor|DENIED|vsock|qemu-system|libvirt'"
  if [[ "${REGISTRATION_READY}" != "1" ]]; then
    echo "  8. Enable and run registration: systemctl enable --now mpa_registration_tool"
    echo "  9. Inspect registration: systemctl status mpa_registration_tool --no-pager"
    echo "  10. Inspect /var/log/mpa_registration.log"
  fi
  echo "  11. Shut down and boot the TD again so qemu picks up the new libvirt/AppArmor state."
  echo "  12. After host checks are clean, retry quote generation inside the guest:"
  echo "      /usr/share/doc/libtdx-attest-dev/examples/test_tdx_attest"
}

main() {
  parse_args "$@"
  require_root

  echo "Checking host-side Intel TDX quote-generation prerequisites..."
  check_path /dev/sgx_enclave
  check_path /dev/sgx_provision
  check_path /dev/sgx_vepc
  check_reboot_required
  check_file_hint "${PCCS_CONFIG}" "PCCS config"
  check_file_hint "${MPA_CONFIG}" "MPA registration config"
  check_pccs_node_runtime
  check_service qgsd.service
  check_qgs_port
  check_qgs_local_cid
  check_service pccs.service
  check_qcnl_pccs_connectivity
  check_libvirt_vsock_policy
  print_service_summary mpa_registration_tool.service
  check_platform_registration

  if [[ "${HAS_BLOCKER}" == "1" ]]; then
    echo
    echo "Result: BLOCKED"
    print_next_steps
    exit 1
  fi

  echo
  echo "Result: READY"
  echo "Host-side prerequisites look good for guest quote generation."
}

main "$@"
