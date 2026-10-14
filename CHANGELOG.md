# Changelog

## v1.3.1

- **Proxmox notes showed garbage (`������`) instead of the emoji** when the script was run from a shell without a UTF-8 locale: under `C`/`POSIX` (or no locale, common in non-login shells and automation) `qm set --description` stores the bytes mangled. The notes are now always written in `LC_ALL=C.UTF-8`, and the command's output (the whole notes HTML plus a harmless Proxmox "Wide character" warning) is no longer echoed to the terminal. Verified on a real node from a shell with no locale.
- README cut by more than half (10.0 KB to 4.3 KB): same warning, install line, behaviours and exit codes, less prose.

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

### Fixed after review of #5 (verified on a real PVE 9.2 node)
- **Cleanup could delete the snippet while the VM survived** (e.g. the destroy failed, or the config could not be read), recreating the original unstartable-VM bug. The snippet is now removed only when the guest is confirmed gone, "Cleaned up" is printed only when true, and the tag is matched exactly (`not-pve-prov` no longer counts).
- **Cleanup could be skipped entirely.** A bash killed by SIGPIPE (terminal or SSH session gone) dies without running its EXIT trap, leaving a half-built guest. SIGPIPE now becomes a normal exit, and output errors inside the trap no longer abort it.
- **The leftover-ID check could refuse every ID** on hosts with `snippets` enabled (`pvesm list --vmid` returns snippet files whatever the ID); only disks, container volumes and backups count now.
- **The leftover-ID check failed open**: a storage that timed out or errored was treated as empty. It now refuses and names the storage (`--ignore-storage` skips one on purpose).
- **VM provisioning reported success when first-boot steps had failed** ("cloud-init finished" does not mean the steps worked). The first-boot steps are now one tracked script; failures are named, the banner and notes say so, and the exit code is 4. A VM whose completion can't be confirmed exits 3, with the detach command printed and saved in the notes, instead of a success banner and `ssh sysadmin@pending`.
- A finished guest is never destroyed because a late step (writing the notes) failed.
- **LXC sshd is verified**: `sshd -t`, service running, and `permitrootlogin no` / `passwordauthentication yes` actually in effect; every failure was previously swallowed.
- A requested GitHub key import that fails now aborts (it used to continue silently with password-only access); usernames are validated and only well-formed key lines are used. Keys and hostnames are quoted in the cloud-init YAML (a key comment containing `: ` or ` #`, or a hostname like `no.lan`/`null`, broke or changed the user-data).
- The default ID steps past IDs that still have backups.
- Passwords starting with `-` work (`openssl passwd` read them as an option; now via stdin, so they are also not visible in `ps`); a typed password is no longer trimmed.
- A failed lookup in a nested `$(...)` aborts instead of continuing with an empty value (`shopt -s inherit_errexit`); e.g. no active storage used to proceed with an empty storage name.
- `PROV_KEEP_CLOUD_INIT=yes/1/true` is honoured; internal state (`PROV_SSH_KEYS`, ...) can no longer be injected from the environment.
- The script can again be run via `bash -c "$(curl ...)"` or a pipe.

### Added
- **CPU type selection** for VMs, default `x86-64-v3`, with a host capability warning.
- **Existing guest IDs are refused**: cluster-wide check, plus leftover disks/backups on any active storage (including PBS).
- **Optional apt-cacher-ng** support (Y/N, default host `apt-cacher-ng.lan:3142`) for LXC and VM.
- **Live OS list**: Debian stable/oldstable and the two newest Ubuntu LTS, resolved at run time, with an offline fallback.
- **Non-interactive mode**: all options as flags / `PROV_*` env vars, `--yes`, `--help`, `--version`.
- Distinct exit codes (3 = unconfirmed, 4 = first-boot step failed) and `--ignore-storage`.
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
