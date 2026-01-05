# pam_gocryptfs

PAM module that mounts a per-user gocryptfs FUSE filesystem at session open and unmounts it at session close.
This was inspired by pam_ecryptfs, with a first version drafted by GPT5.

- Default cipher directory: `~/.gocryptfs`
- Default mount point: `~/Private`
- Opt-in toggles: `~/.gocryptfs/auto-mount` and `~/.gocryptfs/auto-umount`
- Password is read from PAM’s `PAM_AUTHTOK` or prompted if missing, and passed to `gocryptfs` via a pipe using `-passfile /proc/self/fd/N`
- Runs `gocryptfs`/`fusermount3` as the target user (drops privileges)

Tested on Debian/Ubuntu-like systems. Adjust paths as needed for your distribution.

## Prerequisites

- Debian/Ubuntu system with PAM
- Packages:
    - `build-essential`
    - `cargo` (or `rustup` + toolchain)
    - `libpam0g-dev`
    - `gocryptfs`
    - `fuse3` (or `fuse` on older systems)

```bash
sudo apt update
sudo apt install -y build-essential cargo libpam0g-dev gocryptfs fuse3
```

## Build

```bash
# From the project root (where Cargo.toml is)
cargo build --release
# Result: target/release/libpam_gocryptfs.so
```

## Install the PAM module

On Debian/Ubuntu, PAM modules live under a multiarch-specific security directory (e.g., `/lib/x86_64-linux-gnu/security`). The following commands detect that directory and install the module:

```bash
# Discover the PAM module directory
PAM_SEC_DIR="$(dpkg -L libpam-modules | awk '/\/security$/ {print; exit}')"
echo "PAM module dir: $PAM_SEC_DIR"

# Install (rename to pam_gocryptfs.so)
sudo install -m 0644 target/release/libpam_gocryptfs.so "$PAM_SEC_DIR/pam_gocryptfs.so"
```

If detection fails, typical locations include:
- `/lib/x86_64-linux-gnu/security`
- `/lib/aarch64-linux-gnu/security`
- `/lib/security` (older/non-multiarch)

## Configure PAM

You can enable the module system-wide for all sessions or per-service.

- Recommended: add to both `common-session` and `common-session-noninteractive` so it applies to graphical and non-graphical sessions.

```bash
sudoedit /etc/pam.d/common-session
# Add near the end:
# session optional pam_gocryptfs.so

sudoedit /etc/pam.d/common-session-noninteractive
# Add near the end:
# session optional pam_gocryptfs.so
```

Notes:

- Leave the module without arguments to use the per-user defaults:
    - Cipher dir: `~/.gocryptfs`
    - Mount point: `~/Private`
- If you insist on custom paths, pass absolute paths:
    - Example: `session optional pam_gocryptfs.so cipherdir=/home/%(USER)/.gocryptfs mountpoint=~/Private`
    - The module does expand `~/`, `%(USER)`, `%(USERUID)`, and `%(USERGID)`.

## Initialize per-user data

For each user that should mount on login:

```bash
# As the user
mkdir -m 700 -p ~/.gocryptfs
# Initialize cipher directory (creates ~/.gocryptfs/gocryptfs.conf)
gocryptfs -init ~/.gocryptfs

# Create mount point
mkdir -m 700 -p ~/Private

# Opt-in to auto mount/umount
touch ~/.gocryptfs/auto-mount
touch ~/.gocryptfs/auto-umount
```

Now log out and log back in. On session open, the module will:

- If not already mounted and `~/.gocryptfs/auto-mount` exists, run `gocryptfs` to mount `~/.gocryptfs` at `~/Private`.
- On session close, if `~/.gocryptfs/auto-umount` exists, unmount `~/Private` using `fusermount3 -u`.

## Binary locations and permissions

- `gocryptfs` is expected at `/usr/bin/gocryptfs`.
- Unmount uses `fusermount3` (preferred), falling back to `fusermount`, then `umount`. Paths used: `/bin/fusermount3`, `/bin/fusermount`, `/bin/umount`.
- Ensure `fusermount3` is installed and setuid-root (default on Debian/Ubuntu) so regular users can mount FUSE filesystems.

## Logging

Messages are sent via `syslog`. On systemd-based systems, view logs with:

```bash
# Show PAM logs containing pam_gocryptfs
sudo journalctl -b | grep pam_gocryptfs
```

You may also see messages attached to the calling service (e.g., `login`, `sshd`, display manager).

## Uninstall

```bash
# Remove PAM configuration lines you added
sudoedit /etc/pam.d/common-session
sudoedit /etc/pam.d/common-session-noninteractive

# Remove the module
PAM_SEC_DIR="$(dpkg -L libpam-modules | awk '/\/security$/ {print; exit}')"
sudo rm -f "$PAM_SEC_DIR/pam_gocryptfs.so"
```

## Security and behavior notes

- The passphrase is obtained from PAM’s `PAM_AUTHTOK` if available (e.g., after `pam_unix.so`), otherwise the module prompts. If your stack clears `PAM_AUTHTOK` before `open_session`, expect a prompt.
- The passphrase is not written to disk; it is passed to `gocryptfs` through a pipe (`-passfile /proc/self/fd/N`) with close-on-exec handled to only expose the needed FD to the child.
- The module drops privileges to the target user before invoking `gocryptfs` and `fusermount3`.
- Mounting is skipped if:
    - `~/.gocryptfs/auto-mount` is absent, or
    - The mount point is already mounted, or
    - `gocryptfs.conf` is not present in the cipher directory.
- Unmounting is skipped if:
    - `~/.gocryptfs/auto-umount` is absent, or
    - The mount point is not mounted.

## Troubleshooting

- “auto-mount not enabled, skipping”
    - Create `~/.gocryptfs/auto-mount`.

- “No gocryptfs.conf found in cipherdir; skipping mount”
    - Run `gocryptfs -init ~/.gocryptfs` as the user.

- “no passphrase available; skipping mount”
    - Ensure your PAM stack sets `PAM_AUTHTOK` before `open_session` (place this module after `pam_unix.so`), or allow prompting in your login method.

- “failed to drop privileges”
    - Check that the user exists in `/etc/passwd` and that PAM is being called in a normal session context.

- Mount not appearing in graphical login but works on TTY
    - Ensure the module is present in both `common-session` and `common-session-noninteractive`.
    - Some display managers handle sessions differently; check their specific PAM configs under `/etc/pam.d/`.

- Verify mounts
    - `mount | grep gocryptfs` or `grep -E 'gocryptfs|fuse.gocryptfs' /proc/self/mounts`

## License

This module is provided under the MIT OR Apache-2.0 license (choose either).
