//! Windows installation uses the bundled interpreter and native Python ACL adapter.
use std::fs::{File, OpenOptions};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use tauri::Manager;

pub struct Runtime {
    pub python: PathBuf,
    pub root: PathBuf,
    _lease: File,
}

pub fn selected(app: &tauri::AppHandle) -> Result<Option<Runtime>, String> {
    let resources = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join("runtime");
    if !resources.exists() {
        return Ok(None); // Source-run builds have no packaged resources.
    }
    if std::env::consts::ARCH != "x86_64" {
        return Err("This Studio preview requires Windows x86_64".into());
    }
    let data = if let Some(home) = std::env::var_os("EFORGE_STUDIO_HOME") {
        PathBuf::from(home).join("data")
    } else {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is unavailable")?)
            .join("EvidenceForge")
    };
    let output = std::process::Command::new(resources.join("bootstrap/python.exe"))
        .args([
            "-I",
            "-B",
            "-X",
            "utf8",
            "-m",
            "evidenceforge.studio.windows_runtime",
            "--resources",
        ])
        .arg(&resources)
        .arg("--data")
        .arg(&data)
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("Could not start the bundled Windows runtime: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().into());
    }
    let root: PathBuf = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    if root.parent() != Some(data.join("runtimes").as_path()) {
        return Err("The private runtime is outside its selected cache".into());
    }
    let leases = data.join("runtimes/leases");
    // The installer creates this private directory through the native ACL adapter.
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(0x00200000) // FILE_FLAG_OPEN_REPARSE_POINT
        .open(leases.join(format!(
            "{}.lock",
            root.file_name().unwrap().to_string_lossy()
        )))
        .map_err(|e| e.to_string())?;
    if !lease.metadata().map_err(|e| e.to_string())?.is_file()
        || lease
            .metadata()
            .map_err(|e| e.to_string())?
            .file_attributes()
            & 0x400
            != 0
    {
        return Err("The Windows runtime lease is not a regular file".into());
    }
    lease.lock_shared().map_err(|e| e.to_string())?;
    Ok(Some(Runtime {
        python: root.join("python.exe"),
        root,
        _lease: lease,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_launch_lease_interoperates_with_python_windows_locks() {
        let directory =
            std::env::temp_dir().join(format!("eforge-windows-lease-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("runtime.lock");
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        lease.lock_shared().unwrap();
        let python = std::env::var_os("EFORGE_STUDIO_TEST_PYTHON").unwrap_or("python".into());
        let script = "import msvcrt,sys\nf=open(sys.argv[1],'r+b')\ntry:\n msvcrt.locking(f.fileno(),msvcrt.LK_NBLCK,1)\n locked=False\nexcept OSError:\n locked=True\nassert locked == (sys.argv[2]=='locked')";
        let check = |state: &str| {
            assert!(std::process::Command::new(&python)
                .args(["-c", script])
                .arg(&path)
                .arg(state)
                .status()
                .unwrap()
                .success());
        };
        check("locked");
        drop(lease);
        check("unlocked");
        std::fs::remove_dir_all(directory).unwrap();
    }
}
