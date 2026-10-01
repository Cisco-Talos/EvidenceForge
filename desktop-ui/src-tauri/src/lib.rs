#[cfg(target_os = "macos")]
mod macos_icon;
mod native_dialog;
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
async fn choose_bundle_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let path = native_dialog::select_local_path(|complete| {
        app.dialog().file().pick_folder(complete);
    })
    .await?;
    Ok(path.map(|path| path.to_string_lossy().into_owned()))
}

#[tauri::command]
async fn choose_import_file(app: tauri::AppHandle, kind: String) -> Result<Option<String>, String> {
    let extensions: &[&str] = if kind == "scenario" {
        &["yaml", "yml"]
    } else {
        &["efpack"]
    };
    let path = native_dialog::select_local_path(|complete| {
        app.dialog()
            .file()
            .add_filter("EvidenceForge", extensions)
            .pick_file(complete);
    })
    .await?;
    Ok(path.map(|path| path.to_string_lossy().into_owned()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut context = tauri::generate_context!();
    // The default application menu uses Cargo's package name. Use the product
    // name for its labels and About panel, including source-run launches.
    context.package_info_mut().name = "EvidenceForge Studio".into();
    tauri::Builder::default()
        .setup(|_| {
            #[cfg(target_os = "macos")]
            macos_icon::set_dock_icon()?;
            Ok(())
        })
        .menu(|app| {
            let menu = tauri::menu::Menu::default(app)?;
            #[cfg(target_os = "macos")]
            for entry in menu.items()? {
                if let Some(submenu) = entry.as_submenu() {
                    for item in submenu.items()? {
                        if let Some(predefined) = item.as_predefined_menuitem() {
                            let text = predefined.text()?;
                            if text.contains("evidenceforge-studio") {
                                predefined.set_text(
                                    text.replace("evidenceforge-studio", "EvidenceForge Studio"),
                                )?;
                            }
                        }
                    }
                }
            }
            Ok(menu)
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(native_export::ExportState::default())
        .invoke_handler(tauri::generate_handler![
            studio_connection,
            studio_exit,
            choose_bundle_folder,
            choose_import_file,
            native_export::save_studio_export,
            native_export::cancel_studio_export
        ])
        .run(context)
        .expect("error while running tauri application");
}
