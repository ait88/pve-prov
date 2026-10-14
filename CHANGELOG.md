# Changelog

## v1.3

Fixes and features from [#4](https://github.com/ait88/pve-prov/issues/4). Debian and Ubuntu only.

### Fixed
- **VM failed to start a second time** (`volume 'local:snippets/…' does not exist`): the cloud-init snippet was deleted but `cicustom` still pointed at it. The snippet and `cicustom` are now removed together once cloud-init has finished; if that can't be confirmed, both are left in place. The broken `qm guest cmd … exec` wait loop and the background cleanup job are gone.
- VMs no longer default to the `kvm64` CPU model (see *Added*).
- The failure log is no longer deleted before you can read it.
- The cleanup trap could `destroy --purge` a guest that already existed if creation failed on a colliding ID. Cleanup is now armed only after a successful create, and refuses to destroy a guest without the `pve-prov` tag.
- An interrupted image download was cached as if valid. Downloads go to `.part`, are verified against the upstream checksum, then moved into place. Cached images are re-verified each run (this also refreshes stale `latest` images).
- sshd hardening is written as `/etc/ssh/sshd_config.d/00-pve-prov.conf` instead of `sed` on `sshd_config`, which cloud-init drop-ins could override.
- cloud-init sets the short hostname plus the FQDN instead of using the FQDN as the hostname.
- Input validation for IDs, hostnames, cores/RAM/disk, bridge, storage choice and apt cache; LXC networking failure is now fatal; empty VM IP no longer reaches the notes.
- Removed Ubuntu 25.04 (EOL).
- Found by real-host testing: with an apt cache, Debian 13 cloud images fetch from `https://` mirrors, which bypass the cache (apt-cacher-ng refuses `CONNECT`), so the cache silently did nothing. Distro mirrors are now switched to `http://` (apt still verifies signatures): via cloud-init's `apt:` mirror settings for Debian (editing the files early is overwritten by cloud-init's `generate_mirrorlists`), plus a final `runcmd` rewrite; in LXC directly.
- Leftover-volume/backup refusal now shows a count and the first three entries instead of every backup.
- RAM (max 4096 GB) and disk (max 65536 GB) are bounded; a thin-provisioned pool otherwise happily accepts a petabyte disk.

### Added
- **CPU type selection** for VMs, default `x86-64-v3`, with a host capability warning.
- **Existing guest IDs are refused**: cluster-wide check, plus leftover disks/backups on any active storage (including PBS).
- **Optional apt-cacher-ng** support (Y/N, default host `apt-cacher-ng.lan:3142`) for LXC and VM.
- **Live OS list**: Debian stable/oldstable and the two newest Ubuntu LTS, resolved at run time, with an offline fallback.
- **Non-interactive mode**: all options as flags / `PROV_*` env vars, `--yes`, `--help`, `--version`.
- Guests are tagged `pve-prov`; VM disks use `discard`, `iothread` and `ssd`.
- Cloud-init is disabled after first boot by default (`--keep-cloud-init` to opt out).
- README and `tests/smoke.sh` (stub-based tests; `shellcheck`-clean).

## v1.2
- VM: fixed cloud-image import failure. `download_cloud_image`'s status messages leaked onto stdout, which is captured via `$(...)`, corrupting the `--scsi0 <storage>:0,import-from=<path>` argument. Status now goes to stderr; only the image path is written to stdout.
- Applied the same stdout-hygiene fix to `find_lxc_template` and `wait_for_network`.
- Storage picker: fixed free-space units (`pvesm status` reports KiB, not bytes) and auto-scale the unit.

## v1.1
- Replaced `eval` with `printf -v` in prompt functions.
- Fixed storage detection empty-string false positive and `pvesm status` column parsing.
- Expanded valid guest ID range to 100–999999999.
- VM storage no longer selects "iso" storage for cloud images.
- Cloud-init preserves the default user with a `- default` entry.
- Cloud-init snippet gets `chmod 600` and auto-cleanup after boot.
- apt-get: logs to file, shows tail on error, uses force-conf flags, `set -euo pipefail` inside `pct exec` subshells.
- curl: added `--connect-timeout` and `--max-time` for cloud images.
- Password passed via `pct push` tempfile instead of shell expansion.
- Package display: "gh" not "gh-cli".
