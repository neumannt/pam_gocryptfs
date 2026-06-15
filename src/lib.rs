// SPDX-License-Identifier: MIT OR Apache-2.0
//
// pam_gocryptfs.rs - PAM module that mounts a user gocryptfs FUSE filesystem
// at session open and unmounts it at session close.
//
// Summary
// - pam_sm_authenticate: no-op (we do not use kernel keyrings)
// - pam_sm_open_session: mount gocryptfs
// - pam_sm_close_session: unmount gocryptfs
//
// Defaults
// - Cipher directory: ~/.gocryptfs/gocryptfs
// - Mount point:      ~/Private
// - Auto toggles:     ~/.gocryptfs/auto-mount and ~/.gocryptfs/auto-umount
//
// PAM args (optional):
// - cipherdir=/path/to/cipher
// - mountpoint=/path/to/mount
//
// Per-user config file (optional): $HOME/.gocryptfs/config
// - cipherdir=... / mountpoint=... override the args (with ~/ and %(...) expansion)
// - lines starting with '-' are extra gocryptfs flags (one per line)
// - precedence: config file > PAM args > built-in defaults
// - this is what enables whole-home encryption without a system-wide PAM change
//
// Build: link against pam and libc
// Notes:
// - This is a minimal/portable implementation. You may want to harden
//   logging, error handling, option handling, and environment isolation.
// - Assumes gocryptfs binary at /usr/bin/gocryptfs (adjust as needed).
// - Requires FUSE userspace tools (fusermount3 or fusermount) for unmount.

#![allow(non_camel_case_types)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::missing_safety_doc)]

use libc::{c_char, c_int, c_long, c_uint, c_void, gid_t, mode_t, pid_t, size_t, uid_t, O_CLOEXEC, O_NOFOLLOW, S_IFDIR};
use std::ffi::{CStr, CString};
use std::fs;
use std::mem::zeroed;
use std::os::fd::RawFd;
use std::ptr::{null, null_mut};

// PAM constants
const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_AUTHTOK_RECOVERY_ERR: c_int = 21;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_BUF_ERR: c_int = 5;
const PAM_PRELIM_CHECK: c_int = 0x4000;

// Defaults
const DEFAULT_CIPHER_DIR_NAME: &str = ".gocryptfs";
const DEFAULT_MOUNT_DIR_NAME: &str = "Private";
const DEFAULT_GCRYPTFS_BIN: &str = "/usr/bin/gocryptfs";
const AUTO_MOUNT_FILE: &str = "auto-mount";
const AUTO_UMOUNT_FILE: &str = "auto-umount";
const CONFIG_FILE: &str = "config";
const GOCRYPTFS_DIR: &str = "gocryptfs";
const GOCONF_FILE: &str = "gocryptfs.conf";

// Upper bound on how long we wait for a helper (mount/unmount/passwd) to finish
// before killing it. We use that to prevent blocking the login process.
const HELPER_TIMEOUT_SECS: u64 = 30;

#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct passwd {
    pub pw_name: *mut c_char,
    pub pw_passwd: *mut c_char,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_gecos: *mut c_char,
    pub pw_dir: *mut c_char,
    pub pw_shell: *mut c_char,
}

extern "C" {
    // PAM
    fn pam_get_user(pamh: *mut pam_handle_t, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_item(pamh: *const pam_handle_t, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_prompt(pamh: *const pam_handle_t, style: c_int, response: *mut *mut c_char, fmt: *const c_char, ...) -> c_int;
    fn pam_set_data(pamh: *mut pam_handle_t, module_data_name: *const c_char, data: *mut c_void, cleanup: Option<unsafe extern "C" fn(*mut pam_handle_t, *mut c_void, c_int)>) -> c_int;
    fn pam_get_data(pamh: *mut pam_handle_t, module_data_name: *const c_char, data: *mut *const c_void) -> c_int;

    // libc/sys
    fn syslog(prio: c_int, fmt: *const c_char, ...);
    fn getpwnam_r(name: *const c_char, pwd: *mut passwd, buf: *mut c_char, buflen: size_t, result: *mut *mut passwd) -> c_int;
    fn sysconf(name: c_int) -> c_long;

    fn geteuid() -> uid_t;
    fn getegid() -> gid_t;
    fn getgroups(size: c_int, list: *mut gid_t) -> c_int;
    fn setgroups(size: c_int, list: *const gid_t) -> c_int;

    fn setegid(gid: gid_t) -> c_int;
    fn seteuid(uid: uid_t) -> c_int;
    fn setgid(gid: gid_t) -> c_int;
    fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> c_int;

    fn fork() -> pid_t;
    fn waitpid(pid: pid_t, status: *mut c_int, options: c_int) -> pid_t;
    fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int;
    fn mkdir(path: *const c_char, mode: mode_t) -> c_int;

    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: size_t) -> isize;
    fn close(fd: c_int) -> c_int;
}

// A CString wrapper that zeroes its memory before freeing.
struct PwdString(CString);

impl PwdString {
    fn new(s: CString) -> Self {
        Self(s)
    }
}

impl std::ops::Deref for PwdString {
    type Target = CStr;
    fn deref(&self) -> &CStr {
        &self.0
    }
}

impl Drop for PwdString {
    fn drop(&mut self) {
        let bytes = self.0.as_bytes_with_nul();
        // write_volatile prevents the compiler from eliding the zeroing
        for i in 0..bytes.len() {
            unsafe { std::ptr::write_volatile((bytes.as_ptr() as *mut u8).add(i), 0) };
        }
    }
}

const UNIQUE_DATA_KEY: &CStr = c"pam_gocryptfs.authtok";

unsafe extern "C" fn cleanup_password(_pamh: *mut pam_handle_t, data: *mut c_void, _err: c_int) {
    if data.is_null() {
        return;
    }
    let p = data as *mut c_char;
    let len = libc::strlen(p);
    libc::memset(p as *mut c_void, 0, len);
    libc::free(p as *mut c_void);
}

// Helper to store password into PAM handle using pam_set_data.
fn store_password(pamh: *mut pam_handle_t, pass: &CStr) -> c_int {
    unsafe {
        let pw_owned = libc::strdup(pass.as_ptr());
        if pw_owned.is_null() {
            syslog_err("pam_gocryptfs: strdup failed (out of memory)");
            return PAM_BUF_ERR;
        }
        let rc = pam_set_data(pamh, UNIQUE_DATA_KEY.as_ptr(), pw_owned as *mut c_void, Some(cleanup_password));
        if rc != PAM_SUCCESS {
            // If set_data failed, wipe+free immediately to avoid leaks
            cleanup_password(pamh, pw_owned as *mut c_void, rc);
        }
        rc
    }
}

fn cstr(s: &str) -> CString {
    let bytes = match s.find('\0') {
        Some(pos) => &s.as_bytes()[..pos],
        None => s.as_bytes(),
    };
    CString::new(bytes).unwrap()
}

fn syslog_err(msg: &str) {
    let fmt = cstr("%s");
    let m = cstr(msg);
    unsafe {
        syslog(libc::LOG_ERR, fmt.as_ptr(), m.as_ptr());
    }
}

fn syslog_warn(msg: &str) {
    let fmt = cstr("%s");
    let m = cstr(msg);
    unsafe {
        syslog(libc::LOG_WARNING, fmt.as_ptr(), m.as_ptr());
    }
}

fn syslog_debug(msg: &str) {
    let fmt = cstr("%s");
    let m = cstr(msg);
    unsafe {
        syslog(libc::LOG_DEBUG, fmt.as_ptr(), m.as_ptr());
    }
}

// A wrapper around pam_handle_t to control the lifetime of the handle.
struct PamHandle {
    handle: *mut pam_handle_t,
}

impl PamHandle {
    fn new(pamh: *mut pam_handle_t) -> Self {
        Self { handle: pamh }
    }
}

// Password info retrieved from passwd database.
struct PasswordInfo {
    name: CString,
    dir: CString,
    uid: uid_t,
    gid: gid_t,
}

fn fetch_pwd(pam: &PamHandle) -> Option<PasswordInfo> {
    unsafe {
        let mut username_ptr: *const c_char = null();
        let rc = pam_get_user(pam.handle, &mut username_ptr, null());
        if rc != PAM_SUCCESS || username_ptr.is_null() {
            syslog(libc::LOG_ERR, cstr("pam_gocryptfs: Error getting user; rc = [%d]\n").as_ptr(), rc);
            return None;
        }
        // Handle indeterminate _SC_GETPW_R_SIZE_MAX
        let mut buflen = match sysconf(libc::_SC_GETPW_R_SIZE_MAX) {
            n if n > 0 => n as usize,
            _ => 16384,
        };
        const MAX_BUFLEN: usize = 1 << 20; // 1 MiB ceiling for the passwd buffer
        loop {
            let mut buf = vec![0 as c_char; buflen];
            let mut pwd: passwd = zeroed();
            let mut pwd_ptr: *mut passwd = zeroed();
            let r = getpwnam_r(username_ptr, &mut pwd as *mut passwd, buf.as_mut_ptr(), buf.len(), &mut pwd_ptr);
            // Buffer too small: grow and retry instead of giving up.
            if r == libc::ERANGE && buflen < MAX_BUFLEN {
                buflen = (buflen * 2).min(MAX_BUFLEN);
                continue;
            }
            if r != 0 || !std::ptr::eq(pwd_ptr, &pwd) {
                syslog(libc::LOG_ERR, cstr("pam_gocryptfs: getpwnam() failed\n").as_ptr());
                return None;
            }
            return Some(PasswordInfo {
                name: CStr::from_ptr(pwd.pw_name).to_owned(),
                dir: CStr::from_ptr(pwd.pw_dir).to_owned(),
                uid: pwd.pw_uid,
                gid: pwd.pw_gid,
            });
        }
    }
}

// A helper to drop privileges
struct Privileges {
    oeuid: uid_t,
    oegid: gid_t,
    groups: Vec<gid_t>,
}

impl Privileges {
    // Collect provileges to drop then restore them later.
    fn new() -> Privileges {
        unsafe {
            let oeuid = geteuid();
            let oegid = getegid();
            let ngroups_max = sysconf(libc::_SC_NGROUPS_MAX);
            let max_groups = if ngroups_max > 0 { (ngroups_max as usize) + 1 } else { 64 };
            let mut groups: Vec<gid_t> = vec![0; max_groups];
            let mut ngids = getgroups(groups.len() as c_int, groups.as_mut_ptr());
            if ngids < 0 {
                ngids = 0;
            }
            groups.truncate(ngids as usize);

            Privileges { oeuid, oegid, groups }
        }
    }
    // Drop privileges
    fn drop_privileges(&self, uid: uid_t, gid: gid_t) -> bool {
        unsafe { setegid(gid) >= 0 && setgroups(1, &gid as *const gid_t) >= 0 && seteuid(uid) >= 0 }
    }
    // Restore privileges to the state before drop_privileges() was called.
    fn restore_privileges(&self) {
        unsafe {
            let _ = seteuid(self.oeuid);
            let _ = setegid(self.oegid);
            if !self.groups.is_empty() {
                let _ = setgroups(self.groups.len() as c_int, self.groups.as_ptr());
            }
        }
    }
}

fn file_exists(path: &CStr) -> bool {
    unsafe {
        let mut s: libc::stat = zeroed();
        stat(path.as_ptr(), &mut s) == 0
    }
}

fn toggle_exists(path: &CStr, file: &str) -> bool {
    let toggle_path = cstr(&format!("{}/{}", path.to_string_lossy(), file));
    file_exists(&toggle_path)
}

fn ensure_dir(path: &CStr, mode: mode_t) -> bool {
    unsafe {
        let mut s: libc::stat = zeroed();
        if stat(path.as_ptr(), &mut s) == 0 {
            // Exists, ensure directory
            return (s.st_mode & libc::S_IFMT) == S_IFDIR;
        }
        mkdir(path.as_ptr(), mode) == 0
    }
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => match parts.last() {
                Some(&"..") | None if !absolute => parts.push(".."),
                None => {}
                _ => {
                    parts.pop();
                }
            },
            c => parts.push(c),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{}", joined)
    } else {
        joined
    }
}

fn mounts_contains(mountpoint: &str) -> bool {
    let needle = normalize_path(mountpoint);
    // Check if mountpoint is a gocryptfs mount (type "fuse.gocryptfs" or "gocryptfs")
    if let Ok(contents) = fs::read_to_string("/proc/self/mounts") {
        for line in contents.lines() {
            // Each line: <src> <target> <fstype> <opts> ...
            let mut it = line.split_whitespace();
            let _src = it.next();
            let tgt = it.next();
            let fstype = it.next();
            if let (Some(t), Some(ft)) = (tgt, fstype) {
                if normalize_path(t) == needle && (ft == "fuse.gocryptfs" || ft == "gocryptfs") {
                    return true;
                }
            }
        }
    }
    false
}

// expand a variable that occurred in a path specifier
fn map_var(pwd: &PasswordInfo, name: &str) -> String {
    match name {
        "USER" => pwd.name.to_string_lossy().to_string(),
        "HOME" => pwd.dir.to_string_lossy().to_string(),
        "USERUID" => pwd.uid.to_string(),
        "USERGID" => pwd.gid.to_string(),
        _ => format!("%({})", name),
    }
}

// expand all variables (and leading ~/) that occur in a path specifier
fn expand_vars(pwd: &PasswordInfo, s: String) -> String {
    // Expand home directory
    let s = if let Some(p) = s.strip_prefix("~/") { format!("{}/{}", pwd.dir.to_string_lossy(), p) } else { s };

    // Expand variables
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    #[allow(clippy::while_let_on_iterator)]
    while let Some(c) = chars.next() {
        if c == '%' {
            if let Some('(') = chars.peek() {
                // Consume the '('
                chars.next();
                let mut var_name = String::new();
                // Collect characters until ')'
                while let Some(c) = chars.next() {
                    if c == ')' {
                        break;
                    }
                    var_name.push(c);
                }
                // Replace with the mapped value
                result.push_str(&map_var(pwd, &var_name));
            } else {
                // Just push the '%' if not followed by '('
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

// Per-user overrides parsed from $HOME/.gocryptfs/config.
struct UserConfig {
    cipherdir: Option<String>,
    mountpoint: Option<String>,
    options: Vec<CString>,
}

impl UserConfig {
    fn empty() -> Self {
        UserConfig { cipherdir: None, mountpoint: None, options: Vec::new() }
    }
}

// Fully resolved paths for a user, after folding in the per-user config file,
// the PAM arguments, and the built-in defaults (in that order of precedence).
struct ResolvedPaths {
    cipher_dir: CString,
    mountpoint: CString,
    config_dir: CString,
    options: Vec<CString>,
}

// True for a gocryptfs flag line that is safe to forward to the mount command.
// Rejects foreground flags (which would hang the login) and embedded NULs.
fn is_allowed_option(line: &str) -> bool {
    line.starts_with('-') && !line.contains('\0') && line != "-f" && line != "-fg"
}

// Parse the per-user config file. Recognized line kinds:
//   cipherdir=<path>    cipher data location (gocryptfs.conf lives in here)
//   mountpoint=<path>   where the filesystem is mounted
//   -<flag>             a gocryptfs flag, one per line (e.g. -allow_other)
// Blank lines, '#' comments, and unrecognized keys are ignored.
fn parse_user_config(contents: &str) -> UserConfig {
    let mut cfg = UserConfig::empty();
    for raw in contents.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            if is_allowed_option(line) {
                cfg.options.push(cstr(line));
            }
        } else if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "cipherdir" => cfg.cipherdir = Some(value.trim().to_string()),
                "mountpoint" => cfg.mountpoint = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    cfg
}

// Read a small regular file securely. Path resolution can run while we are still
// root (before privileges are dropped), so we refuse to follow a final symlink
// and require the file to be a regular file owned by the target user. That keeps
// a user from pointing the config at a file they do not own.
fn read_owned_regular_file(path: &str, uid: uid_t) -> Option<String> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let f = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW | O_CLOEXEC).open(path).ok()?;
    let md = f.metadata().ok()?;
    if !md.is_file() || md.uid() != uid {
        return None;
    }
    let mut buf = String::new();
    // Cap the read so a pathological file can never exhaust memory.
    f.take(64 * 1024).read_to_string(&mut buf).ok()?;
    Some(buf)
}

fn read_user_config(pwd: &PasswordInfo) -> UserConfig {
    let path = format!("{}/{}/{}", pwd.dir.to_string_lossy(), DEFAULT_CIPHER_DIR_NAME, CONFIG_FILE);
    match read_owned_regular_file(&path, pwd.uid) {
        Some(contents) => parse_user_config(&contents),
        None => UserConfig::empty(),
    }
}

// Resolve cipher dir, mount point, config (toggle) dir, and mount options.
// Precedence for each path: per-user config file > PAM argument > built-in default.
// The "config_dir" is the parent of the cipher data; toggles live there. The
// cipher data itself is always its `gocryptfs` subdirectory.
fn resolve_paths(pwd: &PasswordInfo, cipher_arg: Option<&str>, mount_arg: Option<&str>) -> ResolvedPaths {
    let user_cfg = read_user_config(pwd);
    let home_str = pwd.dir.to_string_lossy();

    let config_dir_spec = user_cfg.cipherdir.or_else(|| cipher_arg.map(|s| s.to_string())).unwrap_or_else(|| format!("{}/{}", home_str, DEFAULT_CIPHER_DIR_NAME));
    let config_dir = expand_vars(pwd, config_dir_spec);
    let cipher_dir = format!("{}/{}", config_dir, GOCRYPTFS_DIR);

    let mountpoint_spec = user_cfg.mountpoint.or_else(|| mount_arg.map(|s| s.to_string())).unwrap_or_else(|| format!("{}/{}", home_str, DEFAULT_MOUNT_DIR_NAME));
    let mountpoint = expand_vars(pwd, mountpoint_spec);

    ResolvedPaths {
        cipher_dir: cstr(&cipher_dir),
        mountpoint: cstr(&mountpoint),
        config_dir: cstr(&config_dir),
        options: user_cfg.options,
    }
}

fn parse_pam_args(argc: c_int, argv: *const *const c_char) -> (Option<String>, Option<String>) {
    let mut cipherdir: Option<String> = None;
    let mut mountpoint: Option<String> = None;
    if argc > 0 && !argv.is_null() {
        for i in 0..argc {
            let s = unsafe {
                let p = *argv.add(i as usize);
                if p.is_null() {
                    continue;
                }
                CStr::from_ptr(p).to_string_lossy()
            };
            if let Some(rest) = s.strip_prefix("cipherdir=") {
                cipherdir = Some(rest.to_string());
            } else if let Some(rest) = s.strip_prefix("mountpoint=") {
                mountpoint = Some(rest.to_string());
            }
        }
    }
    (cipherdir, mountpoint)
}

fn prompt_or_get_password(pamh: *mut pam_handle_t) -> Option<PwdString> {
    unsafe {
        // First try to get PAM_AUTHTOK
        let mut item: *const c_void = null();
        let rc = pam_get_item(pamh as *const pam_handle_t, PAM_AUTHTOK, &mut item);
        if rc == PAM_SUCCESS && !item.is_null() {
            let pass = CStr::from_ptr(item as *const c_char).to_bytes();
            if !pass.is_empty() {
                return CString::new(pass).ok().map(PwdString::new);
            }
        }
        // Fall back to prompting
        let mut resp: *mut c_char = null_mut();
        let prompt = cstr("gocryptfs passphrase: ");
        let prc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &mut resp, prompt.as_ptr());
        if prc == PAM_SUCCESS && !resp.is_null() {
            let out = CStr::from_ptr(resp).to_bytes();
            let s = CString::new(out).ok().map(PwdString::new);
            // Zero and free the PAM-allocated response
            let len = libc::strlen(resp);
            libc::memset(resp as *mut c_void, 0, len);
            libc::free(resp as *mut c_void);
            return s;
        }
        None
    }
}

fn create_pass_pipe_with_data(pass: &[u8]) -> Option<(RawFd, RawFd)> {
    unsafe {
        let mut fds = [0i32; 2];
        // Prefer pipe2 for atomic CLOEXEC setup
        let use_pipe2 = {
            // _GNU_SOURCE pipe2 is common; try and fallback
            pipe2(fds.as_mut_ptr(), O_CLOEXEC) == 0
        };
        if !use_pipe2 {
            if pipe(fds.as_mut_ptr()) != 0 {
                return None;
            }
            // Set CLOEXEC on write end; we will clear it on read end
            let flags = libc::fcntl(fds[0], libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fds[0], libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
            let flags_r = libc::fcntl(fds[1], libc::F_GETFD);
            if flags_r >= 0 {
                libc::fcntl(fds[1], libc::F_SETFD, flags_r | libc::FD_CLOEXEC);
            }
        }
        let read_fd = fds[0];
        let write_fd = fds[1];

        // Write pass + newline
        let mut buf = Vec::with_capacity(pass.len() + 1);
        buf.extend_from_slice(pass);
        buf.push(b'\n');
        let wrote = write(write_fd, buf.as_ptr() as *const c_void, buf.len());
        // Zero password buffer before dropping
        for b in buf.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
        drop(buf);
        if wrote < 0 || wrote as usize != (pass.len() + 1) {
            close(read_fd);
            close(write_fd);
            return None;
        }
        // Keep write_fd open in parent until the child execs to avoid premature EOF
        Some((read_fd, write_fd))
    }
}

// Become the mounting user in a child process
fn impersonate_user_after_fork(pwd: &PasswordInfo, oeuid: uid_t) {
    unsafe {
        if seteuid(oeuid) < 0 {
            libc::_exit(1);
        }
        if setgroups(1, &pwd.gid as *const gid_t) < 0 || setgid(pwd.gid) < 0 {
            libc::_exit(1);
        }
        if setresuid(pwd.uid, pwd.uid, pwd.uid) < 0 {
            libc::_exit(1);
        }
    }
}

// True iff the child terminated normally with exit status 0. `status` is the
// encoded value from waitpid, not a plain exit code.
fn exited_ok(status: c_int) -> bool {
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

// Wait for the process, but give up after the timeout and SIGKILL the child, so a
// hung helper can never block login forever.
fn wait_with_timeout(pid: pid_t, timeout_secs: u64) -> Option<c_int> {
    unsafe {
        let poll_interval_us: c_uint = 50_000; // 50ms
        let max_polls = (timeout_secs * 1_000_000) / poll_interval_us as u64;
        let mut st: c_int = 0;
        let mut polls = 0u64;
        loop {
            let r = waitpid(pid, &mut st, libc::WNOHANG);
            if r == pid {
                return Some(st);
            }
            if r < 0 {
                return None; // error, e.g. ECHILD
            }
            // r == 0: child is still running
            if polls >= max_polls {
                // Timed out: kill and reap so we don't leave a zombie behind.
                libc::kill(pid, libc::SIGKILL);
                let _ = waitpid(pid, &mut st, 0);
                return None;
            }
            libc::usleep(poll_interval_us);
            polls += 1;
        }
    }
}

fn mount_gocryptfs_as_user(pwd: &PasswordInfo, oeuid: uid_t, cipher_dir: &CStr, mountpoint: &CStr, pass: &CStr, options: &[CString]) {
    // Ensure cipherdir has a config file
    let conf_path = cstr(&format!("{}/{}", cipher_dir.to_string_lossy(), GOCONF_FILE));
    if !file_exists(&conf_path) {
        syslog_warn("pam_gocryptfs: No gocryptfs.conf found in cipherdir; skipping mount");
        return;
    }

    // Ensure mountpoint exists
    if !ensure_dir(mountpoint, 0o700) {
        syslog_err("pam_gocryptfs: Failed to create mountpoint directory");
        return;
    }

    // Prepare password pipe
    let pass_bytes = pass.to_bytes();
    let (read_fd, write_fd) = match create_pass_pipe_with_data(pass_bytes) {
        Some(fds) => fds,
        None => {
            syslog_err("pam_gocryptfs: Failed to create pass pipe");
            return;
        }
    };

    // Assemble everything that allocates before fork(). After fork the child must
    // touch only async-signal-safe calls, because the host PAM process may be
    // multi-threaded and malloc/file I/O between fork and exec can deadlock.
    let bin = cstr(DEFAULT_GCRYPTFS_BIN);
    let passfile_arg = cstr(&format!("/proc/self/fd/{}", read_fd));
    let mut args: Vec<CString> = vec![cstr("gocryptfs"), cstr("-q"), cstr("-passfile"), passfile_arg];
    args.extend(options.iter().cloned());
    let mut argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
    argv.push(cipher_dir.as_ptr());
    argv.push(mountpoint.as_ptr());
    argv.push(null());

    unsafe {
        let pid1 = fork();
        if pid1 < 0 {
            syslog_err("pam_gocryptfs: fork() failed");
            close(read_fd);
            close(write_fd);
            return;
        }
        if pid1 == 0 {
            // Child: run as the user
            impersonate_user_after_fork(pwd, oeuid);

            // Close write end in grandchild right before exec (reader remains open)
            close(write_fd);

            // Clear CLOEXEC on read_fd here so the exec'ed
            // gocryptfs can access /proc/self/fd/<read_fd>.
            let cur = libc::fcntl(read_fd, libc::F_GETFD);
            if cur >= 0 {
                libc::fcntl(read_fd, libc::F_SETFD, cur & !libc::FD_CLOEXEC);
            }

            // Exec gocryptfs with an empty environment.
            let envp = [null::<c_char>()];
            libc::execve(bin.as_ptr(), argv.as_ptr(), envp.as_ptr());
            // If execve returns, it failed.
            libc::_exit(1);
        }
        // Parent: wait for first child
        match wait_with_timeout(pid1, HELPER_TIMEOUT_SECS) {
            Some(st) if exited_ok(st) => {}
            Some(_) => syslog_warn("pam_gocryptfs: gocryptfs mount failed"),
            None => syslog_warn("pam_gocryptfs: gocryptfs mount timed out or failed"),
        }

        // Parent can close fds now
        close(read_fd);
        close(write_fd);
    }
}

fn unmount_gocryptfs_as_user(pwd: &PasswordInfo, oeuid: uid_t, mountpoint: &CStr) {
    // Build all argv vectors before fork
    // then fusermount, then umount.
    let fusermount3 = cstr("/bin/fusermount3");
    let fusermount = cstr("/bin/fusermount");
    let umount_bin = cstr("/bin/umount");
    let arg0_fm3 = cstr("fusermount3");
    let arg0_fm = cstr("fusermount");
    let arg0_um = cstr("umount");
    let arg_u = cstr("-u");
    let argv_fm3 = [arg0_fm3.as_ptr(), arg_u.as_ptr(), mountpoint.as_ptr(), null()];
    let argv_fm = [arg0_fm.as_ptr(), arg_u.as_ptr(), mountpoint.as_ptr(), null()];
    let argv_um = [arg0_um.as_ptr(), mountpoint.as_ptr(), null()];

    unsafe {
        // fork and exec fusermount3 -u mountpoint (fallback to fusermount, then umount)
        let pid1 = fork();
        if pid1 < 0 {
            syslog_err("pam_gocryptfs: fork() failed (unmount)");
            return;
        }
        if pid1 == 0 {
            impersonate_user_after_fork(pwd, oeuid);

            let envp = [null::<c_char>()];
            // Try fusermount3
            libc::execve(fusermount3.as_ptr(), argv_fm3.as_ptr(), envp.as_ptr());
            // Try fusermount
            libc::execve(fusermount.as_ptr(), argv_fm.as_ptr(), envp.as_ptr());
            // Try umount
            libc::execve(umount_bin.as_ptr(), argv_um.as_ptr(), envp.as_ptr());
            libc::_exit(1);
        }
        match wait_with_timeout(pid1, HELPER_TIMEOUT_SECS) {
            Some(st) if exited_ok(st) => {}
            _ => syslog_warn("pam_gocryptfs: unmount failed"),
        }
    }
}

// ----- PAM entry points -----

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pam = PamHandle::new(pamh);
    let pwd = fetch_pwd(&pam);
    let pwd = if let Some(pwd) = pwd {
        pwd
    } else {
        return PAM_IGNORE;
    };

    // Parse args and compute paths
    let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
    let paths = resolve_paths(&pwd, cipher_arg.as_deref(), mount_arg.as_deref());

    // Honor per-user auto-mount toggle
    if !toggle_exists(&paths.config_dir, AUTO_MOUNT_FILE) {
        syslog_debug("pam_gocryptfs: auto-mount not enabled, skipping");
        return PAM_IGNORE;
    }

    // Already mounted?
    if mounts_contains(&paths.mountpoint.to_string_lossy()) {
        syslog_debug("pam_gocryptfs: mountpoint already mounted, skipping");
        return PAM_IGNORE;
    }

    // Store the pass phrase to make it available in the session
    let pass = match prompt_or_get_password(pamh) {
        Some(p) => p,
        None => {
            syslog_warn("pam_gocryptfs: no passphrase available; skipping mount");
            return PAM_IGNORE;
        }
    };
    // We ignore failures when storing the password, as we will simply skip mounting in that case
    let _ = store_password(pamh, &pass);
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(_pamh: *mut pam_handle_t, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_open_session(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pam = PamHandle::new(pamh);
    let pwd = fetch_pwd(&pam);
    let pwd = if let Some(pwd) = pwd {
        pwd
    } else {
        return PAM_SUCCESS;
    };

    // Parse args and compute paths
    let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
    let paths = resolve_paths(&pwd, cipher_arg.as_deref(), mount_arg.as_deref());

    // Honor per-user auto-mount toggle
    if !toggle_exists(&paths.config_dir, AUTO_MOUNT_FILE) {
        return PAM_SUCCESS;
    }

    // Already mounted?
    if mounts_contains(&paths.mountpoint.to_string_lossy()) {
        return PAM_SUCCESS;
    }

    unsafe {
        // Temporarily drop to user for mounting
        let privs = Privileges::new();

        if !privs.drop_privileges(pwd.uid, pwd.gid) {
            syslog_err("pam_gocryptfs: failed to drop privileges");
            // Attempt to restore anyway
            privs.restore_privileges();
            return PAM_SUCCESS;
        }

        // Obtain passphrase
        let mut pass_ptr: *const c_void = zeroed();
        let rc = pam_get_data(pamh, UNIQUE_DATA_KEY.as_ptr(), &mut pass_ptr);
        if rc != PAM_SUCCESS {
            syslog_warn("pam_gocryptfs: unable to retrieve passphrase; skipping mount");
            privs.restore_privileges();
            return PAM_SUCCESS;
        }
        let pass = CStr::from_ptr(pass_ptr as *const c_char);

        // Mount
        mount_gocryptfs_as_user(&pwd, privs.oeuid, &paths.cipher_dir, &paths.mountpoint, pass, &paths.options);

        // Restore privileges
        privs.restore_privileges()
    }

    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_close_session(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pam = PamHandle::new(pamh);
    let pwd = fetch_pwd(&pam);
    let pwd = if let Some(pwd) = pwd {
        pwd
    } else {
        return PAM_SUCCESS;
    };
    let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
    let paths = resolve_paths(&pwd, cipher_arg.as_deref(), mount_arg.as_deref());

    // Honor per-user auto-umount toggle
    if !toggle_exists(&paths.config_dir, AUTO_UMOUNT_FILE) {
        syslog_debug("pam_gocryptfs: auto-umount not enabled, skipping");
        return PAM_SUCCESS;
    }

    if !mounts_contains(&paths.mountpoint.to_string_lossy()) {
        syslog_debug("pam_gocryptfs: not mounted, skipping umount");
        return PAM_SUCCESS;
    }

    // Drop to user and unmount
    let privs = Privileges::new();

    if !privs.drop_privileges(pwd.uid, pwd.gid) {
        syslog_err("pam_gocryptfs: failed to drop privileges (umount)");
        // Attempt to restore anyway
        privs.restore_privileges();
        return PAM_SUCCESS;
    }

    unmount_gocryptfs_as_user(&pwd, privs.oeuid, &paths.mountpoint);

    // Restore
    privs.restore_privileges();

    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_chauthtok(pamh: *mut pam_handle_t, flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    // Fetch user
    let pam = PamHandle::new(pamh);
    let pwd = fetch_pwd(&pam);
    let pwd = if let Some(pwd) = pwd {
        pwd
    } else {
        return PAM_SUCCESS;
    };

    unsafe {
        // Get old password
        let mut item: *const c_void = null();
        let rc_old = pam_get_item(pamh as *const pam_handle_t, PAM_OLDAUTHTOK, &mut item);
        if rc_old != PAM_SUCCESS {
            syslog(libc::LOG_ERR, cstr("pam_gocryptfs: Error retrieving old passphrase; rc = [%d]\n").as_ptr(), rc_old);
            return PAM_SUCCESS;
        }
        let old_pass_ptr = item as *const c_char;

        // On PRELIM_CHECK, only verify we have the old password
        if (flags & PAM_PRELIM_CHECK) != 0 {
            if old_pass_ptr.is_null() || CStr::from_ptr(old_pass_ptr).to_bytes().is_empty() {
                syslog_warn("pam_gocryptfs: PRELIM_CHECK: old password is missing");
                return PAM_AUTHTOK_RECOVERY_ERR;
            }
            return PAM_SUCCESS;
        }

        // Get new password
        item = null();
        let rc_new = pam_get_item(pamh as *const pam_handle_t, PAM_AUTHTOK, &mut item);
        if rc_new != PAM_SUCCESS {
            syslog(libc::LOG_ERR, cstr("pam_gocryptfs: Error retrieving new passphrase; rc = [%d]\n").as_ptr(), rc_new);
            return PAM_SUCCESS;
        }
        let new_pass_ptr = item as *const c_char;

        if old_pass_ptr.is_null() || new_pass_ptr.is_null() || CStr::from_ptr(new_pass_ptr).to_bytes().is_empty() {
            syslog_warn("pam_gocryptfs: at least one passphrase is NULL/empty; skipping password change");
            return PAM_AUTHTOK_RECOVERY_ERR;
        }

        // Determine cipherdir (ignore mountpoint here)
        let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
        let paths = resolve_paths(&pwd, cipher_arg.as_deref(), mount_arg.as_deref());
        let cipher_dir = paths.cipher_dir;

        // Ensure cipherdir has gocryptfs.conf
        let conf_path = cstr(&format!("{}/{}", cipher_dir.to_string_lossy(), GOCONF_FILE));
        if !file_exists(&conf_path) {
            syslog_warn("pam_gocryptfs: No gocryptfs.conf found in cipherdir; skipping password change");
            return PAM_SUCCESS;
        }

        // Prepare stdin pipe for old and new password (we will write it twice with newlines)
        let mut stdin_fds = [0i32; 2];
        let have_pipe2 = pipe2(stdin_fds.as_mut_ptr(), libc::O_CLOEXEC) == 0;
        if !have_pipe2 && pipe(stdin_fds.as_mut_ptr()) != 0 {
            syslog_err("pam_gocryptfs: Failed to create stdin pipe");
            return PAM_SUCCESS;
        }
        let stdin_rd = stdin_fds[0];
        let stdin_wr = stdin_fds[1];

        // Drop privileges to the user for the exec
        let privs = Privileges::new();

        if !privs.drop_privileges(pwd.uid, pwd.gid) {
            syslog_err("pam_gocryptfs: failed to drop privileges for password change");
            close(stdin_rd);
            close(stdin_wr);
            privs.restore_privileges();
            return PAM_SUCCESS;
        }

        // Assemble argv before fork
        // gocryptfs -q -nosyslog -passwd <cipherdir>: it reads passwords from
        // stdin when stdin is not a TTY, so we feed the child the old password
        // followed by the new password twice, each newline-terminated (this
        // relies on gocryptfs's -passwd stdin behavior; there is no -passfile).
        let bin = cstr(DEFAULT_GCRYPTFS_BIN);
        let arg0 = cstr("gocryptfs");
        let a_q = cstr("-q");
        let a_nosyslog = cstr("-nosyslog");
        let a_passwd = cstr("-passwd");
        let argv_pw = [arg0.as_ptr(), a_q.as_ptr(), a_nosyslog.as_ptr(), a_passwd.as_ptr(), cipher_dir.as_ptr(), null()];

        let pid = fork();
        if pid < 0 {
            syslog_err("pam_gocryptfs: fork() failed for password change");
            close(stdin_rd);
            close(stdin_wr);
            privs.restore_privileges();
            return PAM_SUCCESS;
        }

        if pid == 0 {
            // Child
            impersonate_user_after_fork(&pwd, privs.oeuid);

            // Close write ends in child; we will only read
            close(stdin_wr);

            // Connect stdin pipe read end to STDIN
            if libc::dup2(stdin_rd, 0) < 0 {
                libc::_exit(1);
            }
            close(stdin_rd);

            let envp = [null::<c_char>()];
            libc::execve(bin.as_ptr(), argv_pw.as_ptr(), envp.as_ptr());
            // If we get here, exec failed
            libc::_exit(1);
        }

        // Parent: we no longer need read ends
        close(stdin_rd);

        // Parent: write old password + new password twice + newline to child's stdin, then close
        let old_c = CStr::from_ptr(old_pass_ptr);
        let new_c = CStr::from_ptr(new_pass_ptr);
        let mut buf = Vec::with_capacity(old_c.to_bytes().len() + new_c.to_bytes().len() * 2 + 3);
        buf.extend_from_slice(old_c.to_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(new_c.to_bytes());
        buf.push(b'\n');
        buf.extend_from_slice(new_c.to_bytes());
        buf.push(b'\n');

        let buf_len = buf.len();
        let wrote = write(stdin_wr, buf.as_ptr() as *const c_void, buf_len);
        // Zero password buffer before dropping
        for b in buf.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
        drop(buf);
        if wrote < 0 || wrote as usize != buf_len {
            syslog_err("pam_gocryptfs: Failed to write new password to stdin");
        }
        close(stdin_wr);

        // Wait for child to finish
        let _ = wait_with_timeout(pid, HELPER_TIMEOUT_SECS);

        // Restore privileges
        privs.restore_privileges();
    }

    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_option_rejects_foreground_and_non_flags() {
        assert!(is_allowed_option("-allow_other"));
        assert!(is_allowed_option("-nonempty"));
        assert!(!is_allowed_option("-f"));
        assert!(!is_allowed_option("-fg"));
        assert!(!is_allowed_option("notaflag"));
        assert!(!is_allowed_option("-bad\0flag"));
    }

    #[test]
    fn parse_config_extracts_paths_and_options() {
        let cfg = parse_user_config(
            "# comment\n\
             cipherdir=/home/.gocryptfs/%(USER)\n\
             mountpoint=%(HOME)\n\
             -nonempty\n\
             -allow_other\n",
        );
        assert_eq!(cfg.cipherdir.as_deref(), Some("/home/.gocryptfs/%(USER)"));
        assert_eq!(cfg.mountpoint.as_deref(), Some("%(HOME)"));
        assert_eq!(cfg.options, vec![cstr("-nonempty"), cstr("-allow_other")]);
    }

    #[test]
    fn parse_config_trims_and_ignores_unknown_keys() {
        let cfg = parse_user_config("  cipherdir = /tmp/c  \n bogus=1 \n  \n# x\n");
        assert_eq!(cfg.cipherdir.as_deref(), Some("/tmp/c"));
        assert_eq!(cfg.mountpoint, None);
        assert!(cfg.options.is_empty());
    }

    #[test]
    fn parse_config_empty_is_empty() {
        let cfg = parse_user_config("");
        assert!(cfg.cipherdir.is_none() && cfg.mountpoint.is_none() && cfg.options.is_empty());
    }

    #[test]
    fn expand_handles_home_and_user() {
        let pwd = PasswordInfo { name: cstr("alice"), dir: cstr("/home/alice"), uid: 1000, gid: 1000 };
        assert_eq!(expand_vars(&pwd, "%(HOME)".to_string()), "/home/alice");
        assert_eq!(expand_vars(&pwd, "/home/.gocryptfs/%(USER)".to_string()), "/home/.gocryptfs/alice");
        assert_eq!(expand_vars(&pwd, "~/Private".to_string()), "/home/alice/Private");
    }
}
