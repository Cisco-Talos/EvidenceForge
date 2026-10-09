use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_dialog::DialogExt;
use tokio::{fs::OpenOptions, io::AsyncWriteExt, sync::Notify};

#[derive(Default)]
pub struct ExportState(Mutex<HashMap<String, Arc<ExportCancellation>>>);

#[derive(Default)]
struct ExportCancellation {
    cancelled: AtomicBool,
    wake: Notify,
}

impl ExportCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.wake.notify_one();
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Serialize)]
struct ExportProgress {
    id: String,
    bytes: u64,
    total: Option<u64>,
}

fn export_url(base_url: &str, path: &str) -> Result<reqwest::Url, String> {
    let base = reqwest::Url::parse(base_url).map_err(|_| "Invalid Studio service URL")?;
    if base.scheme() != "http"
        || base.host_str() != Some("127.0.0.1")
        || base.port().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err("Exports require the authenticated local Studio service".into());
    }
    if !path.starts_with("/v1/") || path.contains('?') || path.contains('#') {
        return Err("Invalid Studio export path".into());
    }
    let url = base.join(path).map_err(|_| "Invalid Studio export path")?;
    let allowed = (url.path().starts_with("/v1/jobs/")
        && (url.path().contains("/files/")
            || url.path().ends_with("/bundle.zip")
            || url.path().ends_with("/report")))
        || (url.path().starts_with("/v1/bundles/")
            && (url.path().contains("/files/") || url.path().ends_with("/bundle.zip")))
        || (url.path().starts_with("/v1/items/")
            && ((url.path().contains("/bundles/") && url.path().ends_with(".zip"))
                || url.path().contains("/files/")
                || url.path().strip_prefix("/v1/items/").is_some_and(|tail| {
                    tail.strip_suffix("/release")
                        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
                })))
        || (url.path().starts_with("/v1/packs/") && url.path().ends_with("/export"))
        || (url.path().starts_with("/v1/environment/") && url.path().contains("/files/"));
    if !allowed || url.host_str() != Some("127.0.0.1") || url.port() != base.port() {
        return Err("Invalid Studio export path".into());
    }
    Ok(url)
}

fn suggested_file_name(value: &str) -> String {
    let name = Path::new(value)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("export");
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_control() || matches!(character, '/' | '\\' | ':') {
                '_'
            } else {
                character
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "export".into()
    } else {
        cleaned
    }
}

fn temporary_path(destination: &Path) -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "System clock is invalid")?
        .as_nanos();
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("Invalid export destination")?;
    Ok(destination.with_file_name(format!(
        ".{name}.eforge-{}-{nonce}.part",
        std::process::id()
    )))
}

async fn write_export<F: Fn(ExportProgress)>(
    id: &str,
    url: reqwest::Url,
    token: &str,
    destination: &Path,
    cancellation: &ExportCancellation,
    on_progress: F,
) -> Result<bool, String> {
    let temporary = temporary_path(destination)?;
    let result = async {
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        let client = reqwest::Client::new();
        let send = client.get(url).header("X-EForge-Token", token).send();
        let mut response = tokio::select! {
            result = send => result.map_err(|error| format!("Could not reach Studio: {error}"))?,
            _ = cancellation.wake.notified() => return Ok(false),
        };
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| value.get("detail").and_then(|detail| detail.as_str()).map(str::to_owned))
                .unwrap_or_else(|| status.to_string());
            return Err(format!("Studio export failed: {detail}"));
        }
        if let Ok(metadata) = std::fs::symlink_metadata(destination) {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("The selected destination is not a regular file".into());
            }
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(|error| format!("Could not create export file: {error}"))?;
        let total = response.content_length();
        let mut bytes = 0_u64;
        on_progress(ExportProgress { id: id.into(), bytes, total });
        loop {
            if cancellation.is_cancelled() {
                return Ok(false);
            }
            let next = tokio::select! {
                result = response.chunk() => result.map_err(|error| format!("Export interrupted: {error}"))?,
                _ = cancellation.wake.notified() => return Ok(false),
            };
            let Some(chunk) = next else { break };
            output
                .write_all(&chunk)
                .await
                .map_err(|error| format!("Could not write export: {error}"))?;
            bytes += chunk.len() as u64;
            on_progress(ExportProgress { id: id.into(), bytes, total });
        }
        if total.is_some_and(|expected| expected != bytes) {
            return Err("Export was incomplete; the partial copy was removed".into());
        }
        output.sync_all().await.map_err(|error| format!("Could not finish export: {error}"))?;
        drop(output);
        if cancellation.is_cancelled() {
            return Ok(false);
        }
        tokio::fs::rename(&temporary, destination)
            .await
            .map_err(|error| format!("Could not save export: {error}"))?;
        Ok(true)
    }
    .await;
    if !matches!(result, Ok(true)) {
        let _ = tokio::fs::remove_file(&temporary).await;
    }
    result
}

#[tauri::command]
pub async fn save_studio_export(
    app: AppHandle,
    state: State<'_, ExportState>,
    id: String,
    base_url: String,
    token: String,
    path: String,
    filename: String,
    initial_directory: Option<String>,
) -> Result<Option<String>, String> {
    let url = export_url(&base_url, &path)?;
    if id.is_empty() || id.len() > 100 {
        return Err("Invalid export ID".into());
    }
    let mut dialog = app
        .dialog()
        .file()
        .set_file_name(suggested_file_name(&filename));
    if let Some(directory) = initial_directory {
        let directory = PathBuf::from(directory);
        if directory.is_dir() {
            dialog = dialog.set_directory(directory);
        }
    }
    let Some(destination) = crate::native_dialog::select_local_path(|complete| {
        dialog.save_file(complete);
    })
    .await?
    else {
        return Ok(None);
    };
    let cancellation = Arc::new(ExportCancellation::default());
    {
        let mut active = state.0.lock().map_err(|_| "Export state is unavailable")?;
        if active.contains_key(&id) {
            return Err("An export with this ID is already active".into());
        }
        active.insert(id.clone(), cancellation.clone());
    }
    let _ = app.emit(
        "studio-export-progress",
        ExportProgress {
            id: id.clone(),
            bytes: 0,
            total: None,
        },
    );
    let result = write_export(&id, url, &token, &destination, &cancellation, |progress| {
        let _ = app.emit("studio-export-progress", progress);
    })
    .await;
    state
        .0
        .lock()
        .map_err(|_| "Export state is unavailable")?
        .remove(&id);
    match result? {
        true => Ok(Some(destination.to_string_lossy().into_owned())),
        false => Ok(None),
    }
}

#[tauri::command]
pub fn cancel_studio_export(state: State<'_, ExportState>, id: String) -> Result<(), String> {
    if let Some(cancellation) = state
        .0
        .lock()
        .map_err(|_| "Export state is unavailable")?
        .get(&id)
    {
        cancellation.cancel();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        net::TcpListener,
        sync::Mutex,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{export_url, suggested_file_name, write_export, ExportCancellation};

    #[test]
    fn exports_only_use_local_studio_file_routes() {
        assert!(export_url("http://127.0.0.1:4400", "/v1/jobs/abc/files/log.json").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/jobs/abc/bundle.zip").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/jobs/abc/report").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/items/a/bundles/b.zip").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/items/a/files/scenario.yaml").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/packs/a/export").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/items/a/release").is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/items/a/lifecycle").is_err());
        assert!(export_url("http://127.0.0.1:4400", "/v1/items/a/other/release").is_err());
        assert!(export_url(
            "http://127.0.0.1:4400",
            "/v1/environment/a/files/personas/test.yaml"
        )
        .is_ok());
        assert!(export_url("http://127.0.0.1:4400", "/v1/environment/a/refresh").is_err());
        assert!(export_url("http://127.0.0.1:4400", "/v1/packs/a/clone").is_err());
        assert!(export_url("http://127.0.0.1:4400", "/v1/items/a/rename").is_err());
        assert!(export_url("https://example.com", "/v1/jobs/a/bundle.zip").is_err());
        assert!(export_url(
            "http://127.0.0.1:4400",
            "//example.com/v1/jobs/a/bundle.zip"
        )
        .is_err());
        assert!(export_url("http://127.0.0.1:4400", "/v1/settings").is_err());
    }

    #[test]
    fn suggested_names_cannot_escape_the_save_folder() {
        assert_eq!(suggested_file_name("../folder/report.json"), "report.json");
        assert_eq!(suggested_file_name(""), "export");
    }

    #[test]
    fn streamed_save_is_atomic_and_keeps_existing_file_on_incomplete_response() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let folder = std::env::temp_dir().join(format!("eforge-native-save-{nonce}"));
        std::fs::create_dir(&folder).unwrap();
        let destination = folder.join("artifact.json");
        std::fs::write(&destination, b"old").unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let progress = Mutex::new(Vec::new());

        for (declared, body, expected_success) in [
            (7, b"hello".as_slice(), false),
            (5, b"hello".as_slice(), true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                let mut request = [0_u8; 1024];
                let _ = std::io::Read::read(&mut socket, &mut request);
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                socket.write_all(body).unwrap();
            });
            let url = reqwest::Url::parse(&format!(
                "http://127.0.0.1:{port}/v1/jobs/x/files/artifact.json"
            ))
            .unwrap();
            let result = runtime.block_on(write_export(
                "one",
                url,
                "secret",
                &destination,
                &ExportCancellation::default(),
                |event| progress.lock().unwrap().push(event.bytes),
            ));
            server.join().unwrap();
            if expected_success {
                assert_eq!(result.unwrap(), true);
                assert_eq!(std::fs::read(&destination).unwrap(), b"hello");
            } else {
                assert!(result.is_err());
                assert_eq!(std::fs::read(&destination).unwrap(), b"old");
                assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 1);
            }
        }
        assert!(progress.lock().unwrap().contains(&5));
        std::fs::remove_dir_all(folder).unwrap();
    }
}
