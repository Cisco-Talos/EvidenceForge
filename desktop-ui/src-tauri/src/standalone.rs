use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use tauri::Manager;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Archive {
    archive: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    evidenceforge_version: String,
    python_version: String,
    minimum_macos: String,
    runtimes: HashMap<String, Archive>,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Release {
    schema_version: u32,
    runtime_id: String,
    evidenceforge_version: String,
    python_version: String,
    architecture: String,
}

pub struct Runtime {
    pub python: PathBuf,
    pub root: PathBuf,
    // Covers installation -> bootstrap -> launchd readiness. The helper and its
    // detached workers take over the same shared kernel lease before this drops.
    _lease: File,
}

fn leased_runtime(python: PathBuf, root: PathBuf) -> Result<Runtime, String> {
    let leases = root.parent().unwrap().join("leases");
    safe_ancestry(&leases)?;
    fs::create_dir_all(&leases).map_err(|e| e.to_string())?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(leases.join(format!(
            "{}.lock",
            root.file_name().unwrap().to_string_lossy()
        )))
        .map_err(|e| e.to_string())?;
    let metadata = lease.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("Runtime launch lease must be a regular single-link file".into());
    }
    lease.lock_shared().map_err(|e| e.to_string())?;
    Ok(Runtime {
        python,
        root,
        _lease: lease,
    })
}

fn safe_ancestry(path: &Path) -> Result<(), String> {
    for entry in path.ancestors() {
        match fs::symlink_metadata(entry) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "Runtime cache path is a symbolic link: {}",
                    entry.display()
                ));
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn canonical_system_alias(path: &Path) -> PathBuf {
    // macOS itself publishes these aliases; user-controlled links remain rejected.
    for alias in ["/var", "/tmp", "/etc"] {
        if path.starts_with(alias) {
            return Path::new("/private").join(path.strip_prefix("/").unwrap());
        }
    }
    path.to_path_buf()
}

fn sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn install(resources: &Path, data: &Path, architecture: &str) -> Result<Runtime, String> {
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(resources.join("manifest.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("Invalid standalone runtime manifest: {e}"))?;
    if manifest.schema_version != 1 || manifest.minimum_macos.is_empty() {
        return Err("Unsupported standalone runtime manifest".into());
    }
    let archive = manifest
        .runtimes
        .get(architecture)
        .ok_or_else(|| format!("This app has no native runtime for {architecture}"))?;
    if archive.sha256.len() != 64
        || !archive
            .sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || archive.archive != format!("runtime-{architecture}.tar.gz")
    {
        return Err("Invalid standalone runtime archive identity".into());
    }
    let release = Release {
        schema_version: 1,
        runtime_id: archive.sha256.clone(),
        evidenceforge_version: manifest.evidenceforge_version,
        python_version: manifest.python_version,
        architecture: architecture.into(),
    };
    let runtimes = canonical_system_alias(data).join("runtimes");
    safe_ancestry(&runtimes)?;
    fs::create_dir_all(&runtimes).map_err(|e| e.to_string())?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .open(runtimes.join("install.lock"))
        .map_err(|e| e.to_string())?;
    lock.lock().map_err(|e| e.to_string())?;
    let root = runtimes.join(format!("{}-{architecture}", archive.sha256));
    safe_ancestry(&root)?;
    let python = root.join("bin/python3.12");
    if root.exists() {
        let installed: Release = serde_json::from_slice(
            &fs::read(root.join("release.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("The installed private runtime is incomplete: {e}"))?;
        if installed != release || !python.is_file() || !root.join("bin/eforge").is_file() {
            return Err("The installed private runtime does not match this app".into());
        }
        return leased_runtime(python, root);
    }
    let source = resources.join(&archive.archive);
    if sha256(&source)? != archive.sha256 {
        return Err("Standalone runtime checksum mismatch; copy the app again".into());
    }
    let temporary = runtimes.join(format!(".{}-{}", archive.sha256, std::process::id()));
    // An interrupted extraction never publishes a final runtime directory.
    if temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|e| e.to_string())?;
    }
    fs::create_dir(&temporary).map_err(|e| e.to_string())?;
    let result = (|| {
        let output = std::process::Command::new("/usr/bin/tar")
            .args(["-xzf"])
            .arg(&source)
            .arg("-C")
            .arg(&temporary)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("Could not install the bundled runtime; check available disk space".into());
        }
        if !temporary.join("bin/python3.12").is_file() || !temporary.join("bin/eforge").is_file() {
            return Err("The bundled runtime is incomplete".into());
        }
        let mut receipt =
            File::create(temporary.join("release.json")).map_err(|e| e.to_string())?;
        receipt
            .write_all(&serde_json::to_vec_pretty(&release).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        receipt.sync_all().map_err(|e| e.to_string())?;
        let mut contract =
            File::create(temporary.join(".cleanup-lease-v1")).map_err(|e| e.to_string())?;
        contract.write_all(b"1\n").map_err(|e| e.to_string())?;
        contract.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temporary, &root).map_err(|e| e.to_string())?;
        leased_runtime(python, root)
    })();
    if temporary.exists() {
        let _ = fs::remove_dir_all(&temporary);
    }
    result
}

pub fn selected(app: &tauri::AppHandle) -> Result<Option<Runtime>, String> {
    let resources = app
        .path()
        .resource_dir()
        .map_err(|e| e.to_string())?
        .join("runtime");
    if !resources.join("manifest.json").is_file() {
        return Ok(None);
    }
    let data = if let Some(home) = std::env::var_os("EFORGE_STUDIO_HOME") {
        PathBuf::from(home).join("data")
    } else {
        app.path()
            .home_dir()
            .map_err(|e| e.to_string())?
            .join("Library/Application Support/EvidenceForge")
    };
    install(&resources, &data, std::env::consts::ARCH).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_launch_lease_blocks_python_cleanup_until_bootstrap_finishes() {
        let directory = canonical_system_alias(&std::env::temp_dir())
            .join(format!("eforge-runtime-lease-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let root = directory.join(format!("{}-aarch64", "a".repeat(64)));
        fs::create_dir_all(&root).unwrap();
        let runtime = leased_runtime(root.join("bin/python3.12"), root.clone()).unwrap();
        let lock = directory.join("leases").join(format!(
            "{}.lock",
            root.file_name().unwrap().to_string_lossy()
        ));
        let python = std::env::var("EFORGE_STUDIO_TEST_PYTHON").unwrap_or("python3".into());
        let script = "import fcntl,sys\nf=open(sys.argv[1],'r+')\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\n locked=False\nexcept BlockingIOError:\n locked=True\nassert locked == (sys.argv[2]=='locked')";
        let check = |expected: &str| {
            assert!(std::process::Command::new(&python)
                .args(["-c", script])
                .arg(&lock)
                .arg(expected)
                .status()
                .unwrap()
                .success());
        };
        check("locked");
        drop(runtime);
        check("unlocked");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_invalid_archive_identity_before_writing_runtime() {
        let directory =
            std::env::temp_dir().join(format!("eforge-runtime-test-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("manifest.json"),
            br#"{
            "schema_version":1,"evidenceforge_version":"2.1.2","python_version":"3.12.12",
            "minimum_macos":"13.0","runtimes":{"aarch64":{"archive":"../bad","sha256":"bad"}}
        }"#,
        )
        .unwrap();
        let error = install(&directory, &directory.join("data"), "aarch64")
            .err()
            .unwrap();
        assert!(error.contains("Invalid standalone runtime archive identity"));
        assert!(!directory.join("data").exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
