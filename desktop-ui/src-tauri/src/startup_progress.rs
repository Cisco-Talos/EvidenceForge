use serde::{Deserialize, Serialize};
use tauri::Emitter;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub title: String,
    pub detail: String,
    pub percent: Option<u8>,
}

pub fn report(app: &tauri::AppHandle, title: &str, detail: &str) {
    let _ = app.emit(
        "studio-startup-progress",
        Progress {
            title: title.into(),
            detail: detail.into(),
            percent: None,
        },
    );
}
