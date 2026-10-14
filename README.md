# pve-prov

Single-file provisioner for **Debian and Ubuntu** LXC containers and VMs on Proxmox VE. Interactive by default; every question also has a flag. Run once per guest: when it finishes, the guest is self-contained.

Needs Proxmox VE 8/9 (amd64), run as root on the host.

## ⚠️ It runs as root on your hypervisor

Read `prov.sh` before running it (it is one file) and **pin to a tag or commit you have reviewed**, not `main`. Try it on a test node first. Never run a copy someone sent you.

- **Contacts:** `deb.debian.org`, `changelogs.ubuntu.com`, `cloud.debian.org`, `cloud-images.ubuntu.com`, Proxmox via `pveam`; `github.com/<user>.keys` only if you import keys. In guests: distro mirrors, `cli.github.com` only with the GitHub CLI, your apt cache only if chosen.
- **Writes:** the image cache (`/var/lib/vz/template/cloud`), a temporary cloud-init snippet, the guest and its notes.
- **Destroys:** only a half-built guest from the current run, and only if it has the `pve-prov` tag.
- No telemetry, no `eval`.

## Install / update

This downloads and shows the script; it does not run it. The same command updates.

```bash
curl -fsSLo prov.sh https://raw.githubusercontent.com/ait88/pve-prov/main/prov.sh && less prov.sh
bash prov.sh        # once you are happy with it
```

Pin by replacing `main` with a reviewed tag or commit. `bash prov.sh --version` shows what you have.

## What you get

- **OS:** Debian stable/oldstable and the two newest Ubuntu LTS, resolved live (`debian`, `ubuntu`, `debian-13`, a codename or a menu number). VMs use the official cloud images, checksum-verified. LXC templates come from `pveam`, which can lag a new Ubuntu release.
- **Access:** `sysadmin` with sudo, password login plus optional GitHub keys, **root SSH disabled**. A random root password goes in the Proxmox notes (console only).
- **VM CPU type:** `x86-64-v3` by default. Proxmox's own default, `kvm64`, lacks SSE4/AVX and hangs many prebuilt binaries. Also `x86-64-v2-AES`, `x86-64-v4`, `host`.
- **ID safety:** an ID is refused if it is used in the cluster or if any storage, PBS included, still holds disks or backups for it. If a storage cannot be listed, the ID is refused (`--ignore-storage NAME` skips one). The default ID steps past IDs that have backups.
- **Apt cache (optional):** apt-cacher-ng, default `apt-cacher-ng.lan:3142`, offered as *yes* only if it resolves. It falls back to direct if unreachable, and distro mirrors are switched to http so the cache is really used.
- Notes are written in a UTF-8 locale, whatever your shell's locale.

## VM first boot and cloud-init

The first-boot steps run from one script inside the guest, which records any failure. The host checks that result, then removes its cloud-init snippet and `cicustom` together. If it cannot confirm, it leaves both and prints the command to detach them.

**Cloud-init is then disabled in the guest.** Otherwise a restart makes Proxmox rebuild default cloud-init data, cloud-init treats it as a new machine, and you get a **new SSH host key and DHCP address**; we measured both. The cost: later changes in Proxmox's Cloud-Init tab won't apply. Use `--keep-cloud-init` to opt out.

## Non-interactive use

A flag, or the matching `PROV_*` variable, answers its question. `--yes` never prompts and takes defaults. With no password given it generates one and stores it in the notes.

```bash
bash prov.sh --yes --type vm --os debian --id 930 --hostname build.lan --cores 4 \
  --ram 8 --disk 60 --storage local-zfs --sysadmin-password-file ./pw --github-user octocat
```

`bash prov.sh --help` lists every flag.

**Exit codes:** `0` done and verified · `1` error or refusal, any half-built guest removed · `2` bad usage · `3` VM built but cloud-init completion unconfirmed (snippet kept, detach command printed) · `4` VM built but a first-boot step failed (named).

On failure or interruption, even a dropped SSH session, a guest is destroyed only if it carries the `pve-prov` tag, and its snippet is deleted only once the guest is really gone.

## Development

```bash
tests/smoke.sh                      # stubbed Proxmox; needs python3-yaml and `script`
shellcheck prov.sh tests/smoke.sh
```

The tests check the commands the script issues, not that Proxmox accepts them. Before a release, run a real VM and container on a PVE host.
