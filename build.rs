use std::fs;

fn main() {
    let current_version = match std::env::var("CARGO_PKG_VERSION") {
        Ok(v) => v,
        Err(_) => return,
    };
    let last_version = match fs::read_to_string("version") {
        Ok(v) => v.trim().to_string(),
        Err(_) => return,
    };
    if current_version.eq(&last_version) {
        return;
    }

    println!("cargo:warning= current version: {current_version} last version: {last_version}");

    // lib.rs
    if replace_lib(&current_version, &last_version).is_err() {
        return;
    }
    // constant.rs
    if replace_constant(&current_version, &last_version).is_err() {
        return;
    }
    // Cargo.toml
    let _ = replace_cargo(&current_version, &last_version);
}

fn replace_constant(current_version: &str, last_version: &str) -> Result<(), ()> {
    let current_str = format!("SSH-2.0-SSH_RS-{current_version}");
    let last_str = format!("SSH-2.0-SSH_RS-{last_version}");
    replace_file("src/constant.rs", current_str, last_str)
}

fn replace_lib(current_version: &str, last_version: &str) -> Result<(), ()> {
    let current_str = format!("ssh-rs = \"{current_version}\"");
    let last_str = format!("ssh-rs = \"{last_version}\"");
    replace_file("src/lib.rs", current_str, last_str)
}

fn replace_cargo(current_version: &str, last_version: &str) -> Result<(), ()> {
    let current_str = format!("version = \"{current_version}\"");
    let last_str = format!("version = \"{last_version}\"");
    replace_file("Cargo.toml", current_str, last_str)
}

fn replace_file(file_path: &str, current_str: String, last_str: String) -> Result<(), ()> {
    let buf_str = match fs::read_to_string(file_path) {
        Ok(v) => v,
        Err(_) => return Err(()),
    };
    let new_buf_str = buf_str.replace(&current_str, &last_str);
    if fs::write(file_path, new_buf_str).is_err() {
        return Err(());
    }
    Ok(())
}
