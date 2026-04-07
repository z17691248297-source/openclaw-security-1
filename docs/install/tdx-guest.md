---
summary: "Run the standalone OpenClaw trusted backend inside a real Ubuntu TDX guest"
read_when:
  - You want the current Node-based trusted backend running inside a real Intel TDX guest
  - You want OpenClaw host REE to point trusted isolation at a guest backendBaseUrl
  - You want the guest image to be prepared from Canonical's Ubuntu TDX tooling
title: "TDX Guest"
---

# OpenClaw Trusted Backend in a TDX Guest

This guide takes the existing standalone trusted backend and places it inside a real Ubuntu TDX guest. It is the first deployment phase:

- the backend runs inside a TD
- the host points `tools.trustedIsolation.backendBaseUrl` at the guest
- request verification uses `ed25519`

This guide does not yet add host/guest mTLS, vsock transport, attestation-enforced host verification, or a real guest-side isolated executor. Those are later phases.

## What you need

- A TDX-capable Ubuntu host prepared with Canonical's [`tdx`](https://github.com/canonical/tdx) project
- A checkout of this OpenClaw repository on the host
- `node`, `tar`, `qemu-img`, `virt-customize`, and `virt-cat` on the host
- Enough disk space for a TD image and overlay

If you want Canonical's guest attestation packages available inside the TD, set `TDX_SETUP_ATTESTATION=1` in Canonical's `setup-tdx-config` before building the base guest image.

## What the script does

`scripts/tdx/prepare-trusted-backend-tdx-guest.sh`:

- scaffolds the standalone backend from `external/openclaw-trusted-backend`
- creates or reuses a Canonical Ubuntu TD image
- builds an overlay qcow2 for the OpenClaw-specific guest
- installs the backend into the guest image with `virt-customize`
- generates a guest-local `ed25519` keypair
- exports the guest public key and a host `openclaw.json` snippet

The guest-side installer lives at `scripts/tdx/install-trusted-backend-guest.sh`. It can also be run manually inside a live guest if you prefer to install after boot.
If you do that and want `/usr/local/bin/openclaw-tdx-attest`, copy `scripts/tdx/openclaw-tdx-attest.c` alongside the installer before running it.

## Prepare a new TD image

First clone Canonical's TDX tooling on the host if you do not already have it:

```bash
git clone https://github.com/canonical/tdx ~/tdx
```

If you want the script to call Canonical's image builder for you:

```bash
sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
  --canonical-tdx-dir ~/tdx \
  --ubuntu-version 24.04 \
  --artifact-dir /var/tmp/openclaw-tdx
```

This calls Canonical's `guest-tools/image/create-td-image.sh` under the hood and then layers the OpenClaw backend on top.

## Reuse an existing TD image

If you already have a TDX-enabled qcow2 image:

```bash
sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
  --base-image /path/to/tdx-guest-ubuntu-24.04-generic.qcow2 \
  --artifact-dir /var/tmp/openclaw-tdx
```

If you start from a regular Ubuntu guest instead of a TD image, first convert that guest with Canonical's `setup-tdx-guest.sh`, then shut it down and use the converted qcow2 as `--base-image`.

## Optional attestation inputs

The guest backend already supports TDX identity and attestation-source inputs:

```bash
sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
  --base-image /path/to/tdx-guest-ubuntu-24.04-generic.qcow2 \
  --artifact-dir /var/tmp/openclaw-tdx \
  --tdx-guest-id tdx-guest:trusted-backend-prod-01 \
  --attestation-command "/usr/local/bin/openclaw-tdx-attest"
```

When you use `/usr/local/bin/openclaw-tdx-attest`, the guest installer compiles
the bundled helper from `scripts/tdx/openclaw-tdx-attest.c` inside the TD and
links it against `libtdx_attest`. The helper emits backend-compatible JSON and
binds `TRUSTED_TDX_NONCE_HEX` into the TDX `report_data`. The installer also
installs a udev rule so the `openclaw-trusted` service account can access TDX
guest device nodes such as `/dev/tdx_guest`, and writes `/etc/tdx-attest.conf`
with `port=4050` so the library uses the host QGS vsock path by default.

Or copy a static attestation JSON payload into the guest:

```bash
sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
  --base-image /path/to/tdx-guest-ubuntu-24.04-generic.qcow2 \
  --artifact-dir /var/tmp/openclaw-tdx \
  --attestation-file /path/to/tdx-attestation.json
```

The backend runs without those optional inputs, but the resulting proof only includes the guest identity summary instead of a quote-backed attestation sample.

## Boot the guest

Canonical recommends `tdvirsh` for running multiple TDs, but on a stock host you should first align libvirt and `tdvirsh` with the non-root user that will launch the TD:

```bash
sudo scripts/tdx/configure-libvirt-tdx-host.sh --user "$USER"
```

Open a new shell after that if the script added you to the `libvirt` group.

Then boot the guest through the OpenClaw wrapper around Canonical `tdvirsh`:

```bash
scripts/tdx/run-canonical-tdvirsh.sh \
  --canonical-tdx-dir /path/to/tdx \
  new --td-image /var/tmp/openclaw-tdx/openclaw-trusted-backend-tdx-ubuntu-24.04.qcow2
```

The OpenClaw wrapper uses a per-user workdir under `/var/tmp/openclaw-tdvirsh-<user>` so you do not inherit stale permissions from the shared `/var/tmp/tdvirsh` directory.
It also auto-detects whether the host-local `qgsd` listener is reachable through
AF_VSOCK CID `1` or `2` and rewrites the generated TD XML accordingly.

If you want the TD to keep the same libvirt DHCP reservation across
delete/new cycles, pass a fixed NIC MAC:

```bash
scripts/tdx/run-canonical-tdvirsh.sh \
  --canonical-tdx-dir /path/to/tdx \
  --mac 52:54:00:9b:5e:1a \
  new --td-image /var/tmp/openclaw-tdx/openclaw-trusted-backend-tdx-ubuntu-24.04.qcow2
```

That lets you bind the MAC once in the libvirt `default` network, for example
`52:54:00:9b:5e:1a -> 192.168.122.76`, and then keep the same guest IP even
after recreating the TD.

Find the guest IP from libvirt:

```bash
virsh list --all
virsh domifaddr <td-domain-name>
```

Then verify the backend is healthy from the host:

```bash
curl http://<tdx-guest-ip>:19090/healthz
curl http://<tdx-guest-ip>:19090/v1/trusted/guest
```

## Host attestation prerequisites

The guest backend can already run inside the TD without quote-backed attestation.
If you want real guest quote generation later, finish Canonical's host-side
attestation setup first:

```bash
cd ~/canonical-tdx/attestation
sudo ./check-production.sh
sudo ./setup-attestation-host.sh
sudo /usr/bin/pccs-configure
sudo systemctl restart pccs
sudo systemctl enable --now mpa_registration_tool
sudo scripts/tdx/check-attestation-host.sh --show-logs
```

The important detail is that `setup-attestation-host.sh` installs packages, but
it does not finish PCCS configuration for you. You still need:

- an Intel PCS subscription key for `pccs-configure`
- a clean `pccs.service` startup
- successful platform registration through `mpa_registration_tool`
- `qgsd` listening on AF_VSOCK port `4050`, which is what Canonical's
  `tdvirsh` templates hardcode for `<quoteGenerationService>`
- libvirt/qemu AppArmor allowing `network vsock stream` on Ubuntu hosts with
  AppArmor enabled
- a host reboot if the machine still reports `System restart required` or a
  pending microcode upgrade

Only after those are clean should you retry guest quote generation.

## Guest quote-generation check

After the host prerequisites are ready, install Canonical's guest-side
attestation packages inside the TD if you have not already:

```bash
sudo ~/canonical-tdx/attestation/setup-attestation-guest.sh
```

Then validate quote generation inside the guest:

```bash
/usr/share/doc/libtdx-attest-dev/examples/test_tdx_attest
```

Expected result:

- the command no longer ends with `Failed to get the quote`
- you see a successful quote-generation message instead
- `Failed to extend rtmr[2]` or `Failed to extend rtmr[3]` at the end of the
  sample output does not invalidate a quote that was already generated

If the guest backend was prepared with `--attestation-command /usr/local/bin/openclaw-tdx-attest`,
verify the backend-level attestation path from the host:

```bash
curl "http://<tdx-guest-ip>:19090/v1/trusted/guest?attest=1"
```

Expected result:

- `guest.attestationMode` is `command`
- `guest.attestationReady` is `true`
- `attestation.quoteSha256` and `attestation.quoteBytes` are present

If it still fails, rerun the host diagnostic script and inspect the failing
service logs:

```bash
sudo scripts/tdx/check-attestation-host.sh --show-logs
sudo journalctl -u pccs -n 100 --no-pager
sudo journalctl -u qgsd -n 100 --no-pager
```

Common blockers:

- `pccs.service` is in `activating (auto-restart)` or `failed`
- `pccs.service` crashes with a Node runtime mismatch such as `Utils.isRegExp is not a function`; check `/opt/intel/sgx-dcap-pccs/package.json` and make sure the service is using a supported Node version
- `/etc/qgs.conf` uses a port other than `4050`, so the guest points at the
  wrong host quote-generation socket
- the guest's qemu log shows `Failed to connect to '2:4050': Permission denied`;
  on Ubuntu this usually means libvirt's AppArmor profile still lacks
  `network vsock stream`
- the guest's qemu log shows `Failed to connect to '2:4050': No such device`;
  on some hosts the local `qgsd` listener is only reachable through AF_VSOCK
  CID `1`, so recreate the TD with `scripts/tdx/run-canonical-tdvirsh.sh`
  instead of reusing a domain definition generated from Canonical's stock
  template
- `qgsd` receives the quote request but logs `[QCNL] Encountered CURL error: (7) Couldn't connect to server`;
  in that case `/etc/sgx_default_qcnl.conf` usually points to a PCCS URL that
  does not match the actual listener, for example `https://<host-ip>:8081/...`
  while PCCS only listens on `https://localhost:8081`
- `qgsd` reaches PCCS but TLS verification fails after you generated an
  insecure self-signed PCCS cert; set `use_secure_cert` to `false` in
  `/etc/sgx_default_qcnl.conf` or regenerate a certificate whose hostname
  matches the configured PCCS URL
- `mpa_manage -get_registration_status` does not report `completed successfully`
- the host still needs a reboot after TDX microcode or attestation package
  changes

## Fix common libvirt, tdvirsh, and qemu-vsock permission failures

If you saw errors like these before the host fix:

- `Failed to connect socket to '/var/run/libvirt/libvirt-sock': Permission denied`
- `Could not create '/var/tmp/tdvirsh/.../overlay....qcow2': Permission denied`
- `Could not open '/var/tmp/tdvirsh/.../overlay....qcow2': Permission denied`
- `qemu-system-x86_64: Failed to connect to '2:4050': Permission denied`

run the host configuration script and then use the wrapper instead of calling Canonical `tdvirsh` directly:

```bash
sudo scripts/tdx/configure-libvirt-tdx-host.sh --user "$USER"
scripts/tdx/run-canonical-tdvirsh.sh \
  --canonical-tdx-dir /path/to/tdx \
  list
```

What the host fix changes:

- sets `/etc/libvirt/qemu.conf` `user`, `group`, and `dynamic_ownership = 0`
- adds your user to `libvirt` and `kvm` when those groups exist
- prepares both `/var/tmp/tdvirsh` and `/var/tmp/openclaw-tdvirsh-<user>`
- patches `/etc/apparmor.d/abstractions/libvirt-qemu` with
  `network vsock stream,` when needed and reloads AppArmor
- restarts libvirt daemons so new guests pick up the new qemu settings

If quote generation is still failing after the host prerequisite check says the
host is ready, inspect the guest qemu log on the host:

```bash
sudo tail -n 40 /var/log/libvirt/qemu/<td-domain-name>.log
sudo journalctl -k --since '30 minutes ago' --no-pager | rg 'apparmor|DENIED|vsock|qemu-system|libvirt'
```

If you see `Failed to connect to '2:4050': Permission denied`, shut down the
TD, rerun the host configuration script, and boot the TD again so qemu picks up
the reloaded libvirt/AppArmor profile.

## Point OpenClaw at the guest

The preparation script exports:

- `/var/tmp/openclaw-tdx/ed25519-public.pem`
- `/var/tmp/openclaw-tdx/openclaw-trusted-isolation.host.json`

Use the JSON file as the starting point for your host-side `tools.trustedIsolation` config. The only value you need to replace is `backendBaseUrl`, for example:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "enforceFailClosed": true,
      "backendBaseUrl": "http://192.168.122.50:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "requestTimeoutMs": 5000,
      "ttlMs": 5000,
      "verify": {
        "mode": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n<guest-public-key>\n-----END PUBLIC KEY-----\n",
        "requireScopeToken": true
      },
      "forceTrustedActions": ["exec"]
    }
  }
}
```

After that, OpenClaw host REE talks to the TD guest over the current HTTP transport, while the private signing key stays inside the guest.

## Current limitations

- The transport is still HTTP over the current host/guest network path. mTLS or vsock-plus-attestation is a later step.
- Trusted isolation can call the guest backend today, but true guest-side isolated execution is still a later phase.
- Canonical's README currently notes that attestation support is still under development, with partial support planned for Ubuntu 26.04 LTS.
- The backend is still the Node implementation. Rewriting the backend in Rust should wait until the guest protocol and executor model are stable.

## Related docs

- [Trusted isolation testing](/trusted-isolation-testing)
- [Cross-platform trusted backends](/cross-platform-trusted-backends)
- [Gateway configuration reference](/gateway/configuration-reference)
