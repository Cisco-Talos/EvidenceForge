mod about;
mod helper_lifecycle;
#[cfg(target_os = "linux")]
mod linux_desktop;
#[cfg(target_os = "macos")]
mod macos_icon;
mod native_dialog;
mod native_export;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod standalone;

use std::sync::atomic::{AtomicBool, Ordering};
use tauri::Manager;
use tauri_plugin_dialog::DialogExt;

#[derive(Default)]
struct ExitHandoff(AtomicBool);

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
async fn studio_connection(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    tauri::async_runtime::spawn_blocking(move || connect_helper(app))
        .await
        .map_err(|_| "Studio helper startup did not complete".to_string())?
}

fn connect_helper(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let lifecycle = app.state::<helper_lifecycle::HelperConnection>();
    let _startup = lifecycle.startup()?;
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let runtime = standalone::selected(&app)?;
    // Runtime installation may take time. Closing during that work should not
    // start a helper afterward; an already-started bootstrap is handed off below.
    lifecycle.ensure_open()?;
    let mut command = std::process::Command::new(studio_python());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(runtime) = runtime.as_ref() {
        command = std::process::Command::new(&runtime.python);
        command.args(["-I", "-B"]);
        command.env("EFORGE_STUDIO_RUNTIME_ROOT", &runtime.root);
        command.env_remove("PYTHONHOME");
        command.env_remove("PYTHONPATH");
    }
    let output = command
        .args(["-m", "evidenceforge.studio.bootstrap", "--desktop"])
        .output()
        .map_err(|error| format!("Could not start the Studio service: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    let connection: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("Studio service returned invalid connection data: {error}"))?;
    lifecycle.remember(&connection)?;
    // Retain an attachment that raced exit so the exit worker can release it,
    // but do not give it to a renderer that is already closing.
    lifecycle.ensure_open()?;
    Ok(connection)
}

#[tauri::command]
async fn studio_exit(app: tauri::AppHandle) {
    if !app
        .state::<helper_lifecycle::HelperConnection>()
        .request_exit()
    {
        return;
    }
    // The renderer has already handed off its quit policy. Explicitly release
    // native ownership as well, including maintenance and failed UI handoffs.
    let handoff = app.clone();
    if tauri::async_runtime::spawn_blocking(move || {
        handoff
            .state::<helper_lifecycle::HelperConnection>()
            .detach();
    })
    .await
    .is_err()
    {
        eprintln!(
            "Studio exit handoff did not complete; process monitoring will release the helper"
        );
    }
    app.state::<ExitHandoff>().0.store(true, Ordering::SeqCst);
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
        &["yaml", "yml", "efscenario"]
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
    #[cfg(target_os = "linux")]
    if let Err(error) = linux_desktop::initialize() {
        eprintln!("Could not register the EvidenceForge Studio desktop launcher: {error}");
    }
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
            // Tauri's default Linux menu has no File/Quit entry. Use a custom
            // item so quitting reaches the same durable handoff as window close.
            #[cfg(target_os = "linux")]
            menu.prepend(&tauri::menu::Submenu::with_items(
                app,
                "File",
                true,
                &[&tauri::menu::MenuItem::with_id(
                    app,
                    "studio_quit",
                    "Quit EvidenceForge Studio",
                    true,
                    Some("Ctrl+Q"),
                )?],
            )?)?;
            for entry in menu.items()? {
                if let Some(submenu) = entry.as_submenu() {
                    for (position, item) in submenu.items()?.iter().enumerate() {
                        if let Some(predefined) = item.as_predefined_menuitem() {
                            let text = predefined.text()?;
                            // GTK/Windows include mnemonic markers ("&About").
                            let label = text.replace('&', "");
                            if label == "About" || label.starts_with("About ") {
                                submenu.remove(predefined)?;
                                submenu.insert(
                                    &tauri::menu::MenuItem::with_id(
                                        app,
                                        "studio_about",
                                        "About EvidenceForge Studio",
                                        true,
                                        None::<&str>,
                                    )?,
                                    position,
                                )?;
                                continue;
                            }
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
        .on_menu_event(|app, event| {
            if event.id().as_ref() == "studio_quit" {
                // ExitRequested forwards this to the main window's close handler.
                app.exit(0);
            }
            if event.id().as_ref() == "studio_about" {
                if let Err(error) = about::show(app) {
                    app.dialog()
                        .message(format!("Could not open About: {error}"))
                        .title("EvidenceForge Studio")
                        .show(|_| {});
                }
            }
        })
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .on_window_event(|window, event| {
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    let app = window.app_handle();
                    if !app.state::<ExitHandoff>().0.load(Ordering::SeqCst)
                        && !app
                            .state::<helper_lifecycle::HelperConnection>()
                            .has_connection()
                    {
                        // Cover close/menu Quit before the renderer can install
                        // its handler. Wait for startup and detach off the UI thread.
                        api.prevent_close();
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move { studio_exit(app).await });
                    }
                }
            }
        })
        .manage(native_export::ExportState::default())
        .manage(ExitHandoff::default())
        .manage(helper_lifecycle::HelperConnection::default())
        .invoke_handler(tauri::generate_handler![
            studio_connection,
            studio_exit,
            choose_bundle_folder,
            choose_import_file,
            native_export::save_studio_export,
            native_export::cancel_studio_export
        ])
        .build(context)
        .expect("error while building tauri application")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                // Also cover exits before the renderer's close handler is ready.
                app.state::<helper_lifecycle::HelperConnection>().detach();
            }
            if let tauri::RunEvent::ExitRequested { api, .. } = event {
                if !app.state::<ExitHandoff>().0.load(Ordering::SeqCst) {
                    if let Some(window) = app.get_webview_window("main") {
                        // Menu Quit/Cmd-Q must reach the same React quit-policy handoff
                        // as the window close button. studio_exit permits the final exit.
                        api.prevent_exit();
                        let _ = window.close();
                    }
                }
            }
        });
}
