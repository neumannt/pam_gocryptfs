# pam_gocryptfs

PAM module that mounts a per-user gocryptfs FUSE filesystem at session open and unmounts it at session close.
This was inspired by pam_ecryptfs.

- Default cipher directory: `~/.gocryptfs` (with the gocryptfs data in `~/.gocryptfs/gocryptfs`)
- Default mount point: `~/Private`
- Opt-in toggles: `~/.gocryptfs/auto-mount` and `~/.gocryptfs/auto-umount`

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

The easiest way is to just build a Debian package and install that, it will setup PAM, too:

```bash
dpkg-buildpackage -us -uc -i -I
dpkg -i ../pam-gocryptfs_0.1_amd64.deb
```

## Manual installation

Manual installation requires placing the shared library in the correct folder and setting up PAM.
On Debian/Ubuntu, PAM modules live under a multiarch-specific security directory (e.g., `/lib/x86_64-linux-gnu/security`). The following commands detect that directory and install the module:

```bash
# Discover the PAM module directory
PAM_SEC_DIR="$(dpkg -L libpam-modules | awk '/\/security\/.*\.so$/ {print; exit}' | xargs dirname)"
echo "PAM module dir: $PAM_SEC_DIR"

# Install (rename to pam_gocryptfs.so)
sudo install -m 0644 target/release/libpam_gocryptfs.so "$PAM_SEC_DIR/pam_gocryptfs.so"
```

If detection fails, typical locations include:

- `/lib/x86_64-linux-gnu/security`
- `/lib/aarch64-linux-gnu/security`
- `/lib/security` (older/non-multiarch)

You can enable the module system-wide for all sessions or per-service.

- Recommended: add to both `common-session` and `common-session-noninteractive` so it applies to graphical and non-graphical sessions.

```bash
sudoedit /etc/pam.d/common-session
# Add near the end:
session optional pam_gocryptfs.so

sudoedit /etc/pam.d/common-session-noninteractive
# Add near the end:
session optional pam_gocryptfs.so

sudoedit /etc/pam.d/common-password
# Add near the end:
password optional pam_gocryptfs.so

sudoedit /etc/pam.d/common-auth
# Add near the end:
auth optional pam_gocryptfs.so
```

Notes:

- Leave the module without arguments to use the per-user defaults:
    - Cipher dir: `~/.gocryptfs`
    - Mount point: `~/Private`
- If you insist on custom paths, pass absolute paths:
    - Example: `session optional pam_gocryptfs.so cipherdir=/home/%(USER)/.gocryptfs mountpoint=~/Private`
    - The module expands `~/`, `%(USER)`, `%(HOME)`, `%(USERUID)`, and `%(USERGID)`.

### Per-user config file

Each user may override the paths and pass extra gocryptfs flags via an optional
file at `~/.gocryptfs/config`. It takes precedence over the PAM arguments, which
in turn take precedence over the built-in defaults. Format:

```
# key=value lines set paths (with ~/ and %(…) expansion)
cipherdir=/home/.gocryptfs/%(USER)
mountpoint=%(HOME)

# lines starting with '-' are extra gocryptfs flags, one per line
-allow_other
-nonempty
```

`cipherdir` names the directory whose `gocryptfs` subdirectory holds the cipher
data (and the toggle files); `mountpoint` is where it is mounted. This file is
what makes per-user, whole-home encryption possible without changing the
system-wide PAM configuration (see below).

## Initialize per-user data

For each user that should mount on login:

```bash
# As the user
mkdir -m 700 -p ~/.gocryptfs/gocryptfs
# Initialize cipher directory (creates ~/.gocryptfs/gocryptfs.conf)
gocryptfs -init ~/.gocryptfs/gocryptfs

# Create mount point
mkdir -m 700 -p ~/Private

# Opt-in to auto mount/umount
touch ~/.gocryptfs/auto-mount
touch ~/.gocryptfs/auto-umount
```

Now log out and log back in. On session open, the module will:

- If not already mounted and `~/.gocryptfs/auto-mount` exists, run `gocryptfs` to mount `~/.gocryptfs` at `~/Private`.
- On session close, if `~/.gocryptfs/auto-umount` exists, unmount `~/Private` using `fusermount3 -u`.

## Encrypting the whole home directory

Instead of a `~/Private` subdirectory you can encrypt the entire home, the way
`ecryptfs-migrate-home` did for eCryptfs. No change to the PAM module is needed —
it is driven entirely by the per-user `config` file described above. The
`gocryptfs-migrate-home` script automates the conversion:

```bash
# As root, with the user logged out:
sudo gocryptfs-migrate-home alice
# add --allow-other if a service outside alice's session must read into the home
```

It initializes a cipher store **outside** the home at
`/home/.gocryptfs/<user>/gocryptfs` (the cipher must live outside the
mountpoint), copies the home into it, swaps the plaintext home for an empty
mountpoint, and writes the `config` and opt-in toggles. Then it prints the steps
to verify and, only afterwards, delete the plaintext backup. Use
`gocryptfs-migrate-home --rollback <user>` to undo.

Important caveats for whole-home encryption:

- **The gocryptfs passphrase is the login password.** The script initializes the
  filesystem with it, and keeping `pam_gocryptfs` in the `password` stack keeps
  the two in sync on password change. If they ever diverge (e.g. the password is
  reset with `passwd`/`chpasswd`, which carry no usable old token), the home
  stops mounting at login — but this is recoverable: change the login password
  back to the old one, or re-key the cipher with the still-working old password
  (`gocryptfs -passwd <cipherdir>`). It is only unrecoverable if no working
  passphrase is known at all.
- **Save the gocryptfs master key.** It is the one recovery path that works
  regardless of the password (`gocryptfs --masterkey ...` to mount). Dump it once
  and store it offline (password manager, printout) — never on the encrypted
  volume:
  `gocryptfs-xray -dumpmasterkey /home/.gocryptfs/<user>/gocryptfs/gocryptfs.conf`
- **Password-less logins cannot decrypt the home.** SSH public-key logins,
  autologin, and similar carry no `PAM_AUTHTOK`, so the session opens onto an
  empty mount. This is inherent to the approach (eCryptfs had the same limit).
- **`-allow_other`** (and `user_allow_other` in `/etc/fuse.conf`) may be needed
  if a greeter or agent must read into the home from outside the user's session.

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


## Troubleshooting

- “auto-mount not enabled, skipping”
    - Create `~/.gocryptfs/auto-mount`.

- “No gocryptfs.conf found in cipherdir; skipping mount”
    - Run `gocryptfs -init ~/.gocryptfs/gocryptfs` as the user.

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
