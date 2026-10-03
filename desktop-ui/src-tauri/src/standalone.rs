use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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
    let runtimes = data.join("runtimes");
    fs::create_dir_all(&runtimes).map_err(|e| e.to_string())?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(runtimes.join("install.lock"))
        .map_err(|e| e.to_string())?;
    lock.lock().map_err(|e| e.to_string())?;
    let root = runtimes.join(format!("{}-{architecture}", archive.sha256));
    let python = root.join("bin/python3.12");
    if root.exists() {
        let installed: Release = serde_json::from_slice(
            &fs::read(root.join("release.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("The installed private runtime is incomplete: {e}"))?;
        if installed != release || !python.is_file() || !root.join("bin/eforge").is_file() {
            return Err("The installed private runtime does not match this app".into());
        }
        return Ok(Runtime { python, root });
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
        fs::rename(&temporary, &root).map_err(|e| e.to_string())?;
        Ok(Runtime { python, root })
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
