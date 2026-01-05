// build.rs
fn main() {
    // Ensure libpam symbols (pam_get_user, pam_get_item, etc.) are linked
    println!("cargo:rustc-link-lib=pam");
}
