# pve-prov

A single-file, interactive provisioner for **Debian and Ubuntu** LXC containers and VMs on Proxmox VE.

- No external script sourcing, no telemetry. Read it once, run it forever.
- **Run-once tool:** when it finishes the guest is self-contained and the script is no longer involved.
- Interactive quick-provisioning is the main use case; every question can also be answered with a flag, so it works from automation too.

## Requirements

- Proxmox VE 8.x / 9.x, amd64, run as `root` on the PVE host.
- For VMs, an internet connection to fetch the cloud image (cached and checksum-verified after the first run).

## Install / update

Download, read, then run. Updating is the same command.

```bash
curl -fsSLo prov.sh https://raw.githubusercontent.com/ait88/pve-prov/main/prov.sh
less prov.sh          # audit it
bash prov.sh
```

To pin a version, replace `main` with a release tag (e.g. `v1.3`). `bash prov.sh --version` prints the version you have.

## What you get

| | LXC | VM |
|---|---|---|
| OS | Debian stable / oldstable, two newest Ubuntu LTS (resolved live, see below) | same, from the official cloud images |
| Users | `sysadmin` (sudo) + random `root` password in the Proxmox notes (console login only) | same |
| SSH | password auth + optional GitHub keys, **root login disabled** via an `sshd_config.d` drop-in | same |
| CPU | cores | cores + CPU type (default `x86-64-v3`) |
| Extras | btop, git, GitHub CLI, optional apt cache | same + `qemu-guest-agent` |

Guests are tagged `pve-prov`. The failure-cleanup logic will only ever destroy a guest carrying that tag.

### OS list is live

The menu is built when you run the script, not hard-coded:

- **Debian** – `stable` (default) and `oldstable` from the Debian `Release` files.
- **Ubuntu** – the two newest supported LTS releases from Canonical's release metadata.

If the metadata can't be reached, it falls back to built-in releases and says so. Choose by menu number, by id (`debian-13`, `ubuntu-26.04`), by codename, or by alias (`debian`, `debian-oldstable`, `ubuntu`).

LXC templates come from `pveam`; Proxmox sometimes lags a new Ubuntu release by a few weeks. A VM works regardless.

### CPU type (VMs)

Proxmox's default (`kvm64`) is a very old baseline: no SSE4/AVX. Many prebuilt binaries then hang or crash at startup. The script defaults to `x86-64-v3`. Alternatives: `x86-64-v2-AES` (safest on mixed/older clusters), `x86-64-v4`, `host` (fastest, no live migration across CPU generations). It warns if the host CPU lacks flags the chosen level needs.

### Guest ID safety

The ID is refused if it is used anywhere in the cluster, **or** if any active storage still holds disks or backups for it (including Proxmox Backup Server), so a new guest can't collide with an old one's volumes or a future restore.

### Apt cache (optional)

Offers to point the guest at an apt-cacher-ng instance (default `apt-cacher-ng.lan:3142`; the prompt defaults to *yes* only when that name resolves from the PVE host). It uses `Proxy-Auto-Detect` with a 1 s probe and falls back to direct, so an unreachable cache never breaks `apt`. HTTPS repositories bypass it (apt-cacher-ng refuses `CONNECT`).

### VM first boot and cloud-init

Cloud-init configures the VM once. When it reports finished, the script removes its user-data snippet **and** the `cicustom` setting together, so the VM never depends on a file on the host. By default cloud-init is then disabled inside the guest (`/etc/cloud/cloud-init.disabled`), so a later restart can't re-run it (which would regenerate SSH host keys). Use `--keep-cloud-init` to leave it enabled. If the script can't confirm cloud-init finished, it leaves both in place and tells you the command to remove them.

## Non-interactive use

Any option given as a flag (or as the matching `PROV_*` environment variable) is not asked for. `--yes` never prompts: unsupplied values take defaults and the confirmation is skipped.

```bash
bash prov.sh --yes --type vm --os debian --id 930 --hostname build.lan \
  --cores 4 --cpu-type x86-64-v3 --ram 8 --disk 60 --bridge vmbr0 \
  --storage local-zfs --sysadmin-password-file ./pw --github-user octocat
```

Run `bash prov.sh --help` for all flags. With `--yes` and no password supplied, random `sysadmin` and `root` passwords are generated and stored in the Proxmox notes.

## Development

```bash
tests/smoke.sh      # stub-based tests; needs bash, python3-yaml and `script` (util-linux)
shellcheck prov.sh tests/smoke.sh
```

The tests replace `qm`, `pct`, `pvesm`, `pvesh`, `pveam` and `curl` with recording stubs, so they verify the commands the script *issues*, not that Proxmox accepts them. Before tagging a release, run a real VM and a real container on a PVE host.
