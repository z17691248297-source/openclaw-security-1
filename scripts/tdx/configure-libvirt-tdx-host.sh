#!/usr/bin/env bash

set -euo pipefail

QEMU_CONF="/etc/libvirt/qemu.conf"
CANONICAL_WORKDIR="/var/tmp/tdvirsh"
USER_WORKDIR_BASE="/var/tmp"
LIBVIRT_QEMU_APPARMOR="/etc/apparmor.d/abstractions/libvirt-qemu"
TARGET_USER=""
TARGET_GROUP=""
USER_WORKDIR=""
CLEAN_WORKDIRS="0"

usage() {
  cat <<'EOF'
Usage: configure-libvirt-tdx-host.sh [options]

Configure libvirt/qemu for Canonical TDX guest workflows that should run as a
non-root user.

This script:
- sets qemu.conf user/group/dynamic_ownership to the chosen user
- adds the user to libvirt and kvm groups when those groups exist
- prepares both the Canonical tdvirsh workdir and a user-specific OpenClaw workdir
- patches libvirt AppArmor to allow AF_VSOCK stream access when AppArmor is enabled
- restarts libvirt daemons so new VMs pick up the new qemu.conf settings

Options:
  --user USER          Non-root user that should own QEMU processes
  --group GROUP        Group that should own QEMU processes
  --workdir PATH       User-specific tdvirsh workdir
                       (default: /var/tmp/openclaw-tdvirsh-<user>)
  --clean-workdirs     Remove stale overlay/xml artifacts from prepared workdirs
  -h, --help           Show this help
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "run this script as root"
  fi
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --user)
        TARGET_USER="${2:-}"
        shift 2
        ;;
      --group)
        TARGET_GROUP="${2:-}"
        shift 2
        ;;
      --workdir)
        USER_WORKDIR="${2:-}"
        shift 2
        ;;
      --clean-workdirs)
        CLEAN_WORKDIRS="1"
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

resolve_identity() {
  if [[ -z "${TARGET_USER}" ]]; then
    TARGET_USER="${SUDO_USER:-}"
  fi
  if [[ -z "${TARGET_USER}" ]]; then
    die "--user is required when SUDO_USER is unavailable"
  fi
  if ! id -u "${TARGET_USER}" >/dev/null 2>&1; then
    die "user not found: ${TARGET_USER}"
  fi

  if [[ -z "${TARGET_GROUP}" ]]; then
    TARGET_GROUP="$(id -gn "${TARGET_USER}")"
  fi
  if ! getent group "${TARGET_GROUP}" >/dev/null 2>&1; then
    die "group not found: ${TARGET_GROUP}"
  fi

  if [[ -z "${USER_WORKDIR}" ]]; then
    USER_WORKDIR="${USER_WORKDIR_BASE}/openclaw-tdvirsh-${TARGET_USER}"
  fi
}

backup_file() {
  local path="$1"
  local backup_path="${path}.openclaw-tdx.bak"
  if [[ -f "${path}" && ! -f "${backup_path}" ]]; then
    cp "${path}" "${backup_path}"
  fi
}

write_qemu_conf() {
  backup_file "${QEMU_CONF}"
  local tmp
  tmp="$(mktemp)"
  awk '
    !/^[[:space:]]*(#.*)?$/ && /^[[:space:]]*(#[[:space:]]*)?(user|group|dynamic_ownership)[[:space:]]*=/ {
      next
    }
    { print }
  ' "${QEMU_CONF}" > "${tmp}"

  cat >> "${tmp}" <<EOF

# OpenClaw TDX host configuration
user = "${TARGET_USER}"
group = "${TARGET_GROUP}"
dynamic_ownership = 0
EOF

  install -m 0600 "${tmp}" "${QEMU_CONF}"
  rm -f "${tmp}"
}

patch_libvirt_apparmor() {
  if [[ ! -f "${LIBVIRT_QEMU_APPARMOR}" ]]; then
    return
  fi

  local vsock_count
  vsock_count="$(rg -c -e '^[[:space:]]*network[[:space:]]+vsock([[:space:]]+stream)?[[:space:]]*,' "${LIBVIRT_QEMU_APPARMOR}" 2>/dev/null || true)"
  if [[ "${vsock_count:-0}" == "1" ]]; then
    return
  fi

  backup_file "${LIBVIRT_QEMU_APPARMOR}"
  local tmp
  tmp="$(mktemp)"
  awk '
    /^[[:space:]]*network[[:space:]]+vsock([[:space:]]+stream)?[[:space:]]*,[[:space:]]*$/ {
      next
    }
    inserted == 0 && /^[[:space:]]*network[[:space:]]+inet6[[:space:]]+stream[[:space:]]*,[[:space:]]*$/ {
      print
      print "  network vsock stream,"
      inserted = 1
      next
    }
    { print }
    END {
      if (inserted == 0) {
        print ""
        print "  # OpenClaw TDX host configuration"
        print "  network vsock stream,"
      }
    }
  ' "${LIBVIRT_QEMU_APPARMOR}" > "${tmp}"

  install -m 0644 "${tmp}" "${LIBVIRT_QEMU_APPARMOR}"
  rm -f "${tmp}"
}

ensure_group_membership() {
  local group_name="$1"
  if ! getent group "${group_name}" >/dev/null 2>&1; then
    return
  fi
  if id -nG "${TARGET_USER}" | tr ' ' '\n' | rg -qx "${group_name}"; then
    return
  fi
  usermod -aG "${group_name}" "${TARGET_USER}"
}

prepare_workdir() {
  local workdir="$1"
  install -d -m 0775 -o "${TARGET_USER}" -g "${TARGET_GROUP}" "${workdir}"
  if [[ "${CLEAN_WORKDIRS}" == "1" ]]; then
    find "${workdir}" -maxdepth 1 -type f \
      \( -name 'overlay.*.qcow2' -o -name 'tdvirsh*.xml' \) -delete
  fi
}

restart_libvirt_daemons() {
  local restarted="0"
  local services=(
    "virtqemud.service"
    "virtlogd.service"
    "virtlockd.service"
    "libvirtd.service"
  )
  for service in "${services[@]}"; do
    if systemctl list-unit-files --no-legend "${service}" 2>/dev/null | rg -q "^${service}[[:space:]]"; then
      systemctl restart "${service}" || true
      restarted="1"
    fi
  done
  if [[ "${restarted}" != "1" ]]; then
    echo "warning: no libvirt service was restarted automatically" >&2
  fi
}

reload_apparmor_profiles() {
  if [[ ! -f "${LIBVIRT_QEMU_APPARMOR}" ]]; then
    return
  fi

  if systemctl list-unit-files --no-legend "apparmor.service" 2>/dev/null | rg -q '^apparmor\.service[[:space:]]'; then
    systemctl reload apparmor.service || true
  fi
}

print_summary() {
  cat <<EOF
Configured libvirt/qemu for user ${TARGET_USER}:${TARGET_GROUP}
- qemu.conf: ${QEMU_CONF}
- canonical tdvirsh workdir: ${CANONICAL_WORKDIR}
- user tdvirsh workdir: ${USER_WORKDIR}
- libvirt AppArmor abstraction: ${LIBVIRT_QEMU_APPARMOR}

If group membership changed, open a new shell before running virsh/tdvirsh.

Recommended next command:
  scripts/tdx/run-canonical-tdvirsh.sh --canonical-tdx-dir /path/to/canonical-tdx new --td-image /path/to/guest.qcow2
EOF
}

main() {
  parse_args "$@"
  require_root
  resolve_identity
  write_qemu_conf
  patch_libvirt_apparmor
  reload_apparmor_profiles
  ensure_group_membership "libvirt"
  ensure_group_membership "kvm"
  prepare_workdir "${CANONICAL_WORKDIR}"
  prepare_workdir "${USER_WORKDIR}"
  restart_libvirt_daemons
  print_summary
}

main "$@"
