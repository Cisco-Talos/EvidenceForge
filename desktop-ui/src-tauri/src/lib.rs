mod native_export;

use tauri_plugin_dialog::DialogExt;

fn studio_python() -> std::ffi::OsString {
    if let Some(explicit) = std::env::var_os("EFORGE_STUDIO_PYTHON") {
        return explicit;
    }
    if let Ok(executable) = std::env::current_exe() {
        for ancestor in executable.ancestors() {
            if !ancestor.join("pyproject.toml").is_file() {
                continue;
            }
            let candidate = if cfg!(windows) {
                ancestor.join(".venv/Scripts/python.exe")
            } else {
                ancestor.join(".venv/bin/python")
            };
            if candidate.is_file() {
                return candidate.into_os_string();
            }
        }
    }
    "python3".into()
}

#[tauri::command]
fn studio_connection() -> Result<serde_json::Value, String> {
    let output = std::process::Command::new(studio_python())
        .args(["-m", "evidenceforge.studio.bootstrap"])
        .output()
        .map_err(|error| format!("Could not start the Studio service: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Studio service returned invalid connection data: {error}"))
}

#[tauri::command]
fn studio_exit(app: tauri::AppHandle) {
    // A prevented close event can outlive AppHandle::exit on macOS. The controller
    // handoff is already durable before this command is called, so bound shutdown.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(1));
        std::process::exit(0);
    });
    app.exit(0);
}

#[tauri::command]
fn choose_bundle_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let Some(chosen) = app.dialog().file().blocking_pick_folder() else {
        return Ok(None);
    };
    let path = chosen
        .into_path()
        .map_err(|_| "A local bundle folder is required")?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(native_export::ExportState::default())
        .invoke_handler(tauri::generate_handler![
            studio_connection,
            studio_exit,
            choose_bundle_folder,
            native_export::save_studio_export,
            native_export::cancel_studio_export
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
