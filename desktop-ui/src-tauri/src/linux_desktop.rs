//! Persistent per-user desktop identity for portable Linux AppImage launches.

use std::ffi::c_char;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MANAGED: &str = "X-EvidenceForge-Managed=true";
const ICON: &[u8] = include_bytes!("../icons/icon.png");

#[link(name = "glib-2.0")]
extern "C" {
    fn g_set_application_name(application_name: *const c_char);
}

/// Register the AppImage outside its temporary mount so the desktop can identify its windows.
pub fn initialize() -> io::Result<()> {
    // GLib copies this static UTF-8 label. Set it before GTK creates any windows.
    unsafe {
        g_set_application_name(b"EvidenceForge Studio\0".as_ptr().cast());
    }
    // Source launches and isolated acceptance workspaces do not install user launchers.
    if std::env::var_os("EFORGE_STUDIO_HOME").is_some() {
        return Ok(());
    }
    let Some(image) = std::env::var_os("APPIMAGE").map(PathBuf::from) else {
        return Ok(());
    };
    if !image.is_absolute() || !image.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "APPIMAGE must identify the installed AppImage file",
        ));
    }
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is unavailable"))?;
    let entry = data.join("applications/evidenceforge-studio.desktop");
    match fs::read_to_string(&entry) {
        Ok(existing) if !existing.lines().any(|line| line == MANAGED) => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let image = image.canonicalize()?;
    let executable = image.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "AppImage path must be UTF-8")
    })?;
    if executable.contains(['\n', '\r', '=']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AppImage launcher paths cannot contain newlines or an equals sign",
        ));
    }
    let icon = data.join("evidenceforge/desktop/evidenceforge-studio.png");
    let icon_value = icon.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Desktop icon path must be UTF-8",
        )
    })?;
    let exec = executable
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%");
    let desktop = format!(
        "[Desktop Entry]\nType=Application\nName=EvidenceForge Studio\n\
         Comment=Author scenarios and generate synthetic security logs\n\
         Exec={}\nIcon={}\nStartupWMClass=evidenceforge-studio\n\
         Terminal=false\nCategories=Development;Education;\n{MANAGED}\n",
        desktop_value(&format!("\"{exec}\"")),
        desktop_value(icon_value),
    );
    persist_if_changed(&icon, ICON)?;
    persist_if_changed(&entry, desktop.as_bytes())
}

fn desktop_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn persist_if_changed(path: &Path, content: &[u8]) -> io::Result<()> {
    match fs::read(path) {
        Ok(existing) if existing == content => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing desktop directory"))?;
    fs::create_dir_all(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let temporary = parent.join(format!(".eforge-desktop-{}-{stamp}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
