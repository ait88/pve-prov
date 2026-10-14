# pve-prov

A single-file, interactive provisioner for **Debian and Ubuntu** LXC containers and VMs on Proxmox VE.

- No external script sourcing, no telemetry. Read it once, run it forever.
- **Run-once tool:** when it finishes the guest is self-contained and the script is no longer involved.
- Interactive quick-provisioning is the main use case; every question can also be answered with a flag, so it works from automation too.

## Requirements

- Proxmox VE 8.x / 9.x, amd64, run as `root` on the PVE host.
- For VMs, an internet connection to fetch the cloud image (cached and checksum-verified after the first run).

## ⚠️ Read this before you run it

**This script runs as `root` on your hypervisor.** It creates and destroys guests, writes to your storage, and downloads images from the internet. A script like that can do anything to your Proxmox host and everything on it.

- **Do not run code you haven't read, including this.** That is why the install command below only *downloads* the file. It deliberately does not pipe into `bash`.
- Read `prov.sh` (it is a single file) or have someone you trust review it, and **pin to a release tag or commit** you have reviewed rather than `main`. A tag or commit can't change under you; `main` can.
- Try it on a test node first, or fork it and run your own copy.
- If someone sends you a link to a copy of this script, don't run it: get it from this repository and check it.

What it does, so you know what you are agreeing to:

- **Contacts (from the host):** `deb.debian.org` (release data), `changelogs.ubuntu.com` (Ubuntu LTS list), `cloud.debian.org` and `cloud-images.ubuntu.com` (VM images and their checksums), Proxmox's own template servers via `pveam`, and `github.com/<user>.keys` **only if** you ask it to import SSH keys. Inside new guests: the distro mirrors, `cli.github.com` **only if** you choose the GitHub CLI, and your apt cache **only if** you choose one.
- **Writes:** the image cache (`/var/lib/vz/template/cloud`), a temporary cloud-init snippet in `/var/lib/vz/snippets` (removed again once the guest has finished first boot), the guest itself, and its notes.
- **Destroys:** only a half-created guest from the current run, and only if it carries the `pve-prov` tag. It never touches any other guest.
- **No telemetry**, no other network calls, no `eval`. `bash prov.sh --help` and `--version` do nothing else.

## Install / update

One line. It downloads the script and shows it to you; it does not run it. Installing and updating are the same command.

```bash
curl -fsSLo prov.sh https://raw.githubusercontent.com/ait88/pve-prov/main/prov.sh && less prov.sh
```

Then, once you are happy with what you read:

```bash
bash prov.sh
```

To pin a version, replace `main` in the URL with a release tag or commit hash you have reviewed (e.g. `v1.3`). `bash prov.sh --version` prints the version you have. To see what an update changes before you run it, download to a new filename and `diff prov.sh prov.new.sh`.

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

- **It fails closed.** If a storage can't be listed (for example a PBS datastore that times out), the ID is refused and the storage is named, because that storage might hold backups for it. `--ignore-storage NAME` (repeatable) skips a storage you know is irrelevant. Storages that aren't active are listed in a warning up front.
- Only guest-owned content counts (disks, container volumes, backups). Snippet and import files on a storage are not treated as belonging to an ID.
- The default ID is the lowest free one, **stepping up past IDs that still have backups**, so `--yes` without `--id` keeps working on clusters with a long backup history.

### Apt cache (optional)

Offers to point the guest at an apt-cacher-ng instance (default `apt-cacher-ng.lan:3142`; the prompt defaults to *yes* only when that name resolves from the PVE host). It uses `Proxy-Auto-Detect` with a 1 s probe and falls back to direct, so an unreachable cache never breaks `apt`. HTTPS repositories bypass it (apt-cacher-ng refuses `CONNECT`).

### VM first boot and cloud-init

Cloud-init configures the VM once. When it reports finished, the script removes its user-data snippet **and** the `cicustom` setting together, so the VM never depends on a file on the host. If the script can't confirm cloud-init finished, it leaves both in place and tells you the command to remove them.

Before it reports success, the script also checks that the first-boot steps it asked for really worked. They run from one small script inside the guest (starting the guest agent, `sshd` configuration and verification, the apt mirror rewrite, the GitHub CLI), which records any failure and only writes a success marker if every step passed. "Cloud-init finished" alone proves nothing, because a failed line in a plain cloud-init `runcmd` is invisible.

**Cloud-init is then disabled inside the guest by default** (`/etc/cloud/cloud-init.disabled`).

Why: once the snippet is gone, Proxmox gives the VM fresh default cloud-init data on its next start, and cloud-init treats that as a *new machine* and sets it up again. We measured what that does on a real host: **a new SSH host key and a new DHCP address**, from a plain restart. Anything you saved from the provisioning output (the IP, the host key in `known_hosts`, an agent's cached connection details) would then be wrong. The first restart after provisioning is usually when this bites: the first-boot package upgrade can install a new kernel, and people tend to reboot a new guest soon after their first login. Disabling cloud-init keeps the IP and host key identical across every restart.

What it does *not* matter for: anything that changes *during* provisioning, before the script prints the summary, is invisible to you.

The trade-off: with cloud-init disabled, later `ipconfig`, user or key changes made in the Proxmox UI's *Cloud-Init* tab are not applied inside the guest. This is a run-once tool, so that is usually fine, but if you want to manage the guest through Proxmox's cloud-init afterwards:

- provision with `--keep-cloud-init`, accepting the restart behaviour above; or
- on an existing guest, `rm /etc/cloud/cloud-init.disabled` inside it. Expect it to be set up again as a new machine on its next boot (new host key, possibly a new IP), the same as `--keep-cloud-init`. We have not tested this on an already-provisioned guest.

## Non-interactive use

Any option given as a flag (or as the matching `PROV_*` environment variable) is not asked for. `--yes` never prompts: unsupplied values take defaults and the confirmation is skipped.

```bash
bash prov.sh --yes --type vm --os debian --id 930 --hostname build.lan \
  --cores 4 --cpu-type x86-64-v3 --ram 8 --disk 60 --bridge vmbr0 \
  --storage local-zfs --sysadmin-password-file ./pw --github-user octocat
```

Run `bash prov.sh --help` for all flags.

**Exit codes** (so automation can tell "done" from "done, but look"):

| Code | Meaning |
|---|---|
| 0 | guest provisioned and verified |
| 1 | error or refusal; a half-built guest from this run is removed |
| 2 | bad usage |
| 3 | VM built, but cloud-init completion could not be confirmed; the snippet and `cicustom` were left in place and the command to detach them is printed (and saved in the Proxmox notes) |
| 4 | VM built and cloud-init finished, but a first-boot step failed; the failed steps are named |

If provisioning fails or is interrupted after the guest was created, the guest is destroyed only if it carries the `pve-prov` tag, and its cloud-init snippet is deleted only if the guest is really gone. This also holds when the terminal or SSH session disappears mid-run. With `--yes` and no password supplied, random `sysadmin` and `root` passwords are generated and stored in the Proxmox notes.

## Development

```bash
tests/smoke.sh      # stub-based tests; needs bash, python3-yaml and `script` (util-linux)
shellcheck prov.sh tests/smoke.sh
```

The tests replace `qm`, `pct`, `pvesm`, `pvesh`, `pveam` and `curl` with recording stubs, so they verify the commands the script *issues*, not that Proxmox accepts them. Before tagging a release, run a real VM and a real container on a PVE host.
