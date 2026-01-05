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
// - Cipher directory: ~/.gocryptfs
// - Mount point:      ~/Private
// - Auto toggles:     ~/.gocryptfs/auto-mount and ~/.gocryptfs/auto-umount
//
// PAM args (optional):
// - cipherdir=/path/to/cipher
// - mountpoint=/path/to/mount
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

use libc::{c_char, c_int, c_long, c_void, gid_t, mode_t, pid_t, size_t, uid_t, O_CLOEXEC, S_IFDIR};
use std::ffi::{CStr, CString};
use std::fs;
use std::mem::zeroed;
use std::os::fd::RawFd;
use std::ptr::{null, null_mut};

// PAM constants
const PAM_SUCCESS: c_int = 0;
const PAM_AUTHTOK_RECOVERY_ERR: c_int = 21;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PRELIM_CHECK: c_int = 0x4000;

// Defaults
const DEFAULT_CIPHER_DIR_NAME: &str = ".gocryptfs";
const DEFAULT_MOUNT_DIR_NAME: &str = "Private";
const DEFAULT_GCRYPTFS_BIN: &str = "/usr/bin/gocryptfs";
const AUTO_MOUNT_FILE: &str = "auto-mount";
const AUTO_UMOUNT_FILE: &str = "auto-umount";
const GOCONF_FILE: &str = "gocryptfs.conf";

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
    fn syslog(prio: c_int, fmt: *const c_char, ...) -> c_int;
    fn getpwnam(name: *const c_char) -> *mut passwd;
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
    fn execl(path: *const c_char, arg0: *const c_char, ...) -> c_int;
    fn clearenv() -> c_int;
    fn stat(path: *const c_char, buf: *mut libc::stat) -> c_int;
    fn mkdir(path: *const c_char, mode: mode_t) -> c_int;

    fn pipe2(fds: *mut c_int, flags: c_int) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: size_t) -> isize;
    fn close(fd: c_int) -> c_int;
}

fn unique_data_key() -> &'static CStr {
    c"pam_gocryptfs.authtok"
}

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
// Expects a NUL-terminated pointer (char *) that we own (malloc/strdup allocated).
unsafe fn store_password(pamh: *mut pam_handle_t, pw_owned: *mut c_char) -> c_int {
    if pw_owned.is_null() {
        return PAM_SUCCESS;
    }
    let rc = pam_set_data(pamh, unique_data_key().as_ptr(), pw_owned as *mut c_void, Some(cleanup_password));
    if rc != PAM_SUCCESS {
        // If set_data failed, wipe+free immediately to avoid leaks
        cleanup_password(pamh, pw_owned as *mut c_void, rc);
    }
    rc
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
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

unsafe fn fetch_pwd(pamh: *mut pam_handle_t) -> *mut passwd {
    let mut username_ptr: *const c_char = null();
    let rc = pam_get_user(pamh, &mut username_ptr, null());
    if rc != PAM_SUCCESS || username_ptr.is_null() {
        syslog(libc::LOG_ERR, cstr("pam_gocryptfs: Error getting user; rc = [%d]\n").as_ptr(), rc);
        return null_mut();
    }
    let pwd = getpwnam(username_ptr);
    if pwd.is_null() {
        syslog(libc::LOG_ERR, cstr("pam_gocryptfs: getpwnam() failed\n").as_ptr());
    }
    pwd
}

fn file_exists(path: &CStr) -> bool {
    unsafe {
        let mut s: libc::stat = zeroed();
        stat(path.as_ptr(), &mut s) == 0
    }
}

unsafe fn ensure_dir(path: &CStr, mode: mode_t) -> bool {
    let mut s: libc::stat = zeroed();
    if stat(path.as_ptr(), &mut s) == 0 {
        // Exists, ensure directory
        return (s.st_mode & libc::S_IFMT) == S_IFDIR;
    }
    mkdir(path.as_ptr(), mode) == 0
}

fn mounts_contains(mountpoint: &str) -> bool {
    // Check if mountpoint is a gocryptfs mount (type "fuse.gocryptfs" or "gocryptfs")
    if let Ok(contents) = fs::read_to_string("/proc/self/mounts") {
        for line in contents.lines() {
            // Each line: <src> <target> <fstype> <opts> ...
            let mut it = line.split_whitespace();
            let _src = it.next();
            let tgt = it.next();
            let fstype = it.next();
            if let (Some(t), Some(ft)) = (tgt, fstype) {
                if t == mountpoint && (ft == "fuse.gocryptfs" || ft == "gocryptfs") {
                    return true;
                }
            }
        }
    }
    false
}

// expand a variable that occured in a path specifier
fn map_var(pwd: *mut passwd, name: &str) -> String {
    match name {
        "USER" => unsafe { CStr::from_ptr((*pwd).pw_name) }.to_string_lossy().to_string(),
        "USERUID" => unsafe { (*pwd).pw_uid }.to_string(),
        "USERGID" => unsafe { (*pwd).pw_gid }.to_string(),
        _ => format!("%({})", name),
    }
}

// expand all variables (and leading ~/) that occur in a path specifier
fn expand_vars(pwd: *mut passwd, s: String) -> String {
    // Expand home directory
    let s = if let Some(p) = s.strip_prefix("~/") { format!("{}/{}", unsafe { CStr::from_ptr((*pwd).pw_dir) }.to_string_lossy(), p) } else { s };

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

fn build_default_paths(pwd: *mut passwd, cipher_arg: Option<&str>, mount_arg: Option<&str>) -> (CString, CString, CString, CString) {
    let home = unsafe { CStr::from_ptr((*pwd).pw_dir) };
    let home_str = home.to_string_lossy();
    let cipherdir = cipher_arg.map(|s| expand_vars(pwd, s.to_string())).unwrap_or_else(|| format!("{}/{}", home_str, DEFAULT_CIPHER_DIR_NAME));
    let mountpoint = mount_arg.map(|s| expand_vars(pwd, s.to_string())).unwrap_or_else(|| format!("{}/{}", home_str, DEFAULT_MOUNT_DIR_NAME));
    let auto_mount = format!("{}/{}", cipherdir, AUTO_MOUNT_FILE);
    let auto_umount = format!("{}/{}", cipherdir, AUTO_UMOUNT_FILE);
    (CString::new(cipherdir).unwrap(), CString::new(mountpoint).unwrap(), CString::new(auto_mount).unwrap(), CString::new(auto_umount).unwrap())
}

unsafe fn parse_pam_args(argc: c_int, argv: *const *const c_char) -> (Option<String>, Option<String>) {
    let mut cipherdir: Option<String> = None;
    let mut mountpoint: Option<String> = None;
    if argc > 0 && !argv.is_null() {
        for i in 0..argc {
            let p = *argv.add(i as usize);
            if p.is_null() {
                continue;
            }
            let s = CStr::from_ptr(p).to_string_lossy();
            if let Some(rest) = s.strip_prefix("cipherdir=") {
                cipherdir = Some(rest.to_string());
            } else if let Some(rest) = s.strip_prefix("mountpoint=") {
                mountpoint = Some(rest.to_string());
            }
        }
    }
    (cipherdir, mountpoint)
}

unsafe fn prompt_or_get_password(pamh: *mut pam_handle_t) -> Option<CString> {
    // First try to get PAM_AUTHTOK
    let mut item: *const c_void = null();
    let rc = pam_get_item(pamh as *const pam_handle_t, PAM_AUTHTOK, &mut item);
    if rc == PAM_SUCCESS && !item.is_null() {
        let pass = CStr::from_ptr(item as *const c_char).to_bytes();
        if !pass.is_empty() {
            return CString::new(pass).ok();
        }
    }
    // Fall back to prompting
    let mut resp: *mut c_char = null_mut();
    let prompt = cstr("gocryptfs passphrase: ");
    let prc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &mut resp, prompt.as_ptr());
    if prc == PAM_SUCCESS && !resp.is_null() {
        let out = CStr::from_ptr(resp).to_bytes();
        let s = CString::new(out).ok();
        // pam alloc for resp is managed by PAM; do not free here.
        return s;
    }
    None
}

unsafe fn create_pass_pipe_with_data(pass: &[u8]) -> Option<(RawFd, RawFd)> {
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

    // We must clear CLOEXEC on read_fd so the exec'ed gocryptfs can access /proc/self/fd/<read_fd>
    let cur = libc::fcntl(read_fd, libc::F_GETFD);
    if cur >= 0 {
        libc::fcntl(read_fd, libc::F_SETFD, cur & !libc::FD_CLOEXEC);
    }

    // Write pass + newline
    let mut buf = Vec::with_capacity(pass.len() + 1);
    buf.extend_from_slice(pass);
    buf.push(b'\n');
    let wrote = write(write_fd, buf.as_ptr() as *const c_void, buf.len());
    if wrote < 0 || wrote as usize != buf.len() {
        close(read_fd);
        close(write_fd);
        return None;
    }
    // Keep write_fd open in parent until the child execs to avoid premature EOF
    Some((read_fd, write_fd))
}

unsafe fn mount_gocryptfs_as_user(pwd: *mut passwd, oeuid: uid_t, cipherdir: &CStr, mountpoint: &CStr, pass: &CStr) {
    // Ensure cipherdir has a config file
    let conf_path = CString::new(format!("{}/{}", cipherdir.to_string_lossy(), GOCONF_FILE)).unwrap();
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

    // Double-fork: parent waits for first child; first child spawns grandchild and exits;
    // grandchild execs gocryptfs in foreground, fully detached from PAM.
    let pid1 = fork();
    if pid1 < 0 {
        syslog_err("pam_gocryptfs: fork() failed");
        close(read_fd);
        close(write_fd);
        return;
    }
    if pid1 == 0 {
        // Grandchild: run as the user
        seteuid(oeuid);
        clearenv();
        if setgroups(1, &(*pwd).pw_gid as *const gid_t) < 0 || setgid((*pwd).pw_gid) < 0 {
            libc::_exit(1);
        }
        if setresuid((*pwd).pw_uid, (*pwd).pw_uid, (*pwd).pw_uid) < 0 {
            libc::_exit(1);
        }

        // Close write end in grandchild right before exec (reader remains open)
        close(write_fd);

        // Build -passfile /proc/self/fd/<read_fd>
        let passfile_arg = CString::new(format!("/proc/self/fd/{}", read_fd)).unwrap();

        // Exec gocryptfs
        let bin = cstr(DEFAULT_GCRYPTFS_BIN);
        let arg0 = cstr("gocryptfs");
        let a1 = cstr("-q");
        let a2 = cstr("-nosyslog");
        let a3 = cstr("-passfile");

        execl(bin.as_ptr(), arg0.as_ptr(), a1.as_ptr(), a2.as_ptr(), a3.as_ptr(), passfile_arg.as_ptr(), cipherdir.as_ptr(), mountpoint.as_ptr(), null::<c_char>());
        // If execl returns, it failed
        libc::_exit(1);
    }
    // Parent: wait for first child
    let mut st: c_int = 0;
    let r = waitpid(pid1, &mut st, 0);
    if r < 0 || st != 0 {
        syslog_warn("pam_gocryptfs: gocrypts mount failed");
    }

    // Parent can close fds now
    close(read_fd);
    close(write_fd);
}

unsafe fn unmount_gocryptfs_as_user(pwd: *mut passwd, oeuid: uid_t, mountpoint: &CStr) {
    // Double-fork and exec fusermount3 -u mountpoint (fallback to fusermount, then umount)
    let pid1 = fork();
    if pid1 < 0 {
        syslog_err("pam_gocryptfs: fork() failed (unmount)");
        return;
    }
    if pid1 == 0 {
        seteuid(oeuid);
        clearenv();
        if setgroups(1, &(*pwd).pw_gid as *const gid_t) < 0 || setgid((*pwd).pw_gid) < 0 {
            libc::_exit(1);
        }
        if setresuid((*pwd).pw_uid, (*pwd).pw_uid, (*pwd).pw_uid) < 0 {
            libc::_exit(1);
        }

        let fusermount3 = cstr("/bin/fusermount3");
        let fusermount = cstr("/bin/fusermount");
        let umount_bin = cstr("/bin/umount");
        let arg0_fm3 = cstr("fusermount3");
        let arg0_fm = cstr("fusermount");
        let arg0_um = cstr("umount");
        let arg_u = cstr("-u");

        // Try fusermount3
        execl(fusermount3.as_ptr(), arg0_fm3.as_ptr(), arg_u.as_ptr(), mountpoint.as_ptr(), null::<c_char>());
        // Try fusermount
        execl(fusermount.as_ptr(), arg0_fm.as_ptr(), arg_u.as_ptr(), mountpoint.as_ptr(), null::<c_char>());
        // Try umount
        execl(umount_bin.as_ptr(), arg0_um.as_ptr(), mountpoint.as_ptr(), null::<c_char>());
        libc::_exit(1);
    }
    let mut st: c_int = 0;
    let r = waitpid(pid1, &mut st, 0);
    if r < 0 || st != 0 {
        syslog_warn("pam_gocryptfs: unmount failed");
    }
}

// ----- PAM entry points -----

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pwd = fetch_pwd(pamh);
    if pwd.is_null() {
        return PAM_SUCCESS;
    }

    // Parse args and compute paths
    let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
    let (_cipherdir, mountpoint, auto_mount, _auto_umount) = build_default_paths(pwd, cipher_arg.as_deref(), mount_arg.as_deref());

    // Honor per-user ~/.gocryptfs/auto-mount toggle
    if !file_exists(&auto_mount) {
        syslog_debug("pam_gocryptfs: auto-mount not enabled, skipping");
        return PAM_SUCCESS;
    }

    // Already mounted?
    if mounts_contains(&mountpoint.to_string_lossy()) {
        syslog_debug("pam_gocryptfs: mountpoint already mounted, skipping");
        return PAM_SUCCESS;
    }

    // Store the pass phrase to make it available in the session
    let pass = match prompt_or_get_password(pamh) {
        Some(p) => p,
        None => {
            syslog_warn("pam_gocryptfs: no passphrase available; skipping mount");
            return PAM_SUCCESS;
        }
    };
    store_password(pamh, libc::strdup(pass.as_ptr()))
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(_pamh: *mut pam_handle_t, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pwd = fetch_pwd(pamh);
    if pwd.is_null() {
        return PAM_SUCCESS;
    }

    // Parse args and compute paths
    let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
    let (cipherdir, mountpoint, auto_mount, _auto_umount) = build_default_paths(pwd, cipher_arg.as_deref(), mount_arg.as_deref());

    // Honor per-user ~/.gocryptfs/auto-mount toggle
    if !file_exists(&auto_mount) {
        return PAM_SUCCESS;
    }

    // Already mounted?
    if mounts_contains(&mountpoint.to_string_lossy()) {
        return PAM_SUCCESS;
    }

    // Temporarily drop to user for mounting
    let oeuid = geteuid();
    let oegid = getegid();

    let ngroups_max = sysconf(libc::_SC_NGROUPS_MAX);
    let max_groups = if ngroups_max > 0 { (ngroups_max as usize) + 1 } else { 64 };
    let mut groups: Vec<gid_t> = vec![0; max_groups];
    let ngids = getgroups(groups.len() as c_int, groups.as_mut_ptr());
    let restore_privs = || {
        seteuid(oeuid);
        setegid(oegid);
        if ngids > 0 {
            let _ = setgroups(ngids, groups.as_ptr());
        }
    };

    if setegid((*pwd).pw_gid) < 0 || setgroups(1, &(*pwd).pw_gid as *const gid_t) < 0 || seteuid((*pwd).pw_uid) < 0 {
        syslog_err("pam_gocryptfs: failed to drop privileges");
        // Attempt to restore anyway
        restore_privs();
        return PAM_SUCCESS;
    }

    // Obtain passphrase
    let mut pass_ptr: *const c_void = zeroed();
    let rc = pam_get_data(pamh, unique_data_key().as_ptr(), &mut pass_ptr);
    if rc != PAM_SUCCESS {
        syslog_warn("pam_gocryptfs: unable to retrieve passphrase; skipping mount");
        restore_privs();
        return PAM_SUCCESS;
    }
    let pass = CStr::from_ptr(pass_ptr as *const c_char);

    // Mount
    mount_gocryptfs_as_user(pwd, oeuid, &cipherdir, &mountpoint, pass);

    // Restore privileges
    restore_privs();

    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    let pwd = fetch_pwd(pamh);
    if pwd.is_null() {
        return PAM_SUCCESS;
    }
    let (cipher_arg, mount_arg) = parse_pam_args(argc, argv);
    let (_cipherdir, mountpoint, _auto_mount, auto_umount) = build_default_paths(pwd, cipher_arg.as_deref(), mount_arg.as_deref());

    // Honor per-user ~/.gocryptfs/auto-umount toggle
    if !file_exists(&auto_umount) {
        syslog_debug("pam_gocryptfs: auto-umount not enabled, skipping");
        return PAM_SUCCESS;
    }

    if !mounts_contains(&mountpoint.to_string_lossy()) {
        syslog_debug("pam_gocryptfs: not mounted, skipping umount");
        return PAM_SUCCESS;
    }

    // Drop to user and unmount
    let oeuid = geteuid();
    let oegid = getegid();

    let ngroups_max = sysconf(libc::_SC_NGROUPS_MAX);
    let max_groups = if ngroups_max > 0 { (ngroups_max as usize) + 1 } else { 64 };
    let mut groups: Vec<gid_t> = vec![0; max_groups];
    let ngids = getgroups(groups.len() as c_int, groups.as_mut_ptr());
    let restore_privs = || {
        seteuid(oeuid);
        setegid(oegid);
        if ngids > 0 {
            let _ = setgroups(ngids, groups.as_ptr());
        }
    };

    if setegid((*pwd).pw_gid) < 0 || setgroups(1, &(*pwd).pw_gid as *const gid_t) < 0 || seteuid((*pwd).pw_uid) < 0 {
        syslog_err("pam_gocryptfs: failed to drop privileges (umount)");
        // Attempt to restore anyway
        restore_privs();
        return PAM_SUCCESS;
    }

    unmount_gocryptfs_as_user(pwd, oeuid, &mountpoint);

    // Restore
    restore_privs();

    PAM_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(pamh: *mut pam_handle_t, flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    // Fetch user
    let pwd = fetch_pwd(pamh);
    if pwd.is_null() {
        return PAM_SUCCESS;
    }

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
    let (cipher_arg, _mount_arg) = parse_pam_args(argc, argv);
    let (cipherdir, _mountpoint, _auto_mount, _auto_umount) = build_default_paths(pwd, cipher_arg.as_deref(), None);

    // Ensure cipherdir has gocryptfs.conf
    let conf_path = CString::new(format!("{}/{}", cipherdir.to_string_lossy(), GOCONF_FILE)).unwrap();
    if !file_exists(&conf_path) {
        syslog_warn("pam_gocryptfs: No gocryptfs.conf found in cipherdir; skipping password change");
        return PAM_SUCCESS;
    }

    // Prepare pipe for old password via -passfile (write done by helper)
    let old_c = CStr::from_ptr(old_pass_ptr);
    let (old_rd, old_wr) = match create_pass_pipe_with_data(old_c.to_bytes()) {
        Some(fds) => fds,
        None => {
            syslog_err("pam_gocryptfs: Failed to create old-pass pipe");
            return PAM_SUCCESS;
        }
    };

    // Prepare stdin pipe for new password (we will write it twice with newlines)
    let mut stdin_fds = [0i32; 2];
    let have_pipe2 = pipe2(stdin_fds.as_mut_ptr(), libc::O_CLOEXEC) == 0;
    if !have_pipe2 && pipe(stdin_fds.as_mut_ptr()) != 0 {
        close(old_rd);
        close(old_wr);
        syslog_err("pam_gocryptfs: Failed to create stdin pipe");
        return PAM_SUCCESS;
    }
    let stdin_rd = stdin_fds[0];
    let stdin_wr = stdin_fds[1];

    // Drop privileges to the user for the exec
    let oeuid = geteuid();
    let oegid = getegid();
    let ngroups_max = sysconf(libc::_SC_NGROUPS_MAX);
    let max_groups = if ngroups_max > 0 { (ngroups_max as usize) + 1 } else { 64 };
    let mut groups: Vec<gid_t> = vec![0; max_groups];
    let ngids = getgroups(groups.len() as c_int, groups.as_mut_ptr());

    let restore_privs = || {
        let _ = seteuid(oeuid);
        let _ = setegid(oegid);
        if ngids > 0 {
            let _ = setgroups(ngids, groups.as_ptr());
        }
    };

    if setegid((*pwd).pw_gid) < 0 || setgroups(1, &(*pwd).pw_gid as *const gid_t) < 0 || seteuid((*pwd).pw_uid) < 0 {
        syslog_err("pam_gocryptfs: failed to drop privileges for password change");
        close(old_rd);
        close(old_wr);
        close(stdin_rd);
        close(stdin_wr);
        restore_privs();
        return PAM_SUCCESS;
    }

    // Fork and exec: gocryptfs -passwd -passfile /proc/self/fd/<old_rd> <cipherdir>
    // The new password is provided twice via child's stdin.
    let pid = fork();
    if pid < 0 {
        syslog_err("pam_gocryptfs: fork() failed for password change");
        close(old_rd);
        close(old_wr);
        close(stdin_rd);
        close(stdin_wr);
        restore_privs();
        return PAM_SUCCESS;
    }

    if pid == 0 {
        // Child
        clearenv();

        // Ensure we fully run as the user (ruid/euid/suid)
        if setresuid((*pwd).pw_uid, (*pwd).pw_uid, (*pwd).pw_uid) < 0 {
            libc::_exit(1);
        }

        // Close write ends in child; we will only read
        close(old_wr);
        close(stdin_wr);

        // Connect stdin pipe read end to STDIN
        if libc::dup2(stdin_rd, 0) < 0 {
            libc::_exit(1);
        }
        close(stdin_rd);

        // Build -passfile /proc/self/fd/<old_rd>
        let passfile_arg = CString::new(format!("/proc/self/fd/{}", old_rd)).unwrap();

        let bin = cstr(DEFAULT_GCRYPTFS_BIN);
        let arg0 = cstr("gocryptfs");
        let a_q = cstr("-q");
        let a_nosyslog = cstr("-nosyslog");
        let a_passwd = cstr("-passwd");
        let a_passfile = cstr("-passfile");

        execl(bin.as_ptr(), arg0.as_ptr(), a_q.as_ptr(), a_nosyslog.as_ptr(), a_passwd.as_ptr(), a_passfile.as_ptr(), passfile_arg.as_ptr(), cipherdir.as_ptr(), null::<c_char>());
        // If we get here, exec failed
        libc::_exit(1);
    }

    // Parent: we no longer need read ends
    close(old_rd);
    close(stdin_rd);

    // Parent: write new password twice + newline to child's stdin, then close
    let new_c = CStr::from_ptr(new_pass_ptr);
    let mut buf = Vec::with_capacity(new_c.to_bytes().len() * 2 + 2);
    buf.extend_from_slice(new_c.to_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(new_c.to_bytes());
    buf.push(b'\n');

    let wrote = write(stdin_wr, buf.as_ptr() as *const c_void, buf.len());
    if wrote < 0 || wrote as usize != buf.len() {
        syslog_err("pam_gocryptfs: Failed to write new password to stdin");
    }
    close(stdin_wr);

    // Close the old password writer (it was pre-filled by helper)
    close(old_wr);

    // Wait for child to finish
    let mut _st: c_int = 0;
    let _ = waitpid(pid, &mut _st, 0);

    // Restore privileges
    restore_privs();

    PAM_SUCCESS
}
