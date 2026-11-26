//! Save a network diagram image that the page rendered.
//!
//! The image arrives as the raw command body, so nothing is fetched and no Studio service route is
//! involved. Only PNG data is accepted, the user chooses the destination in a native save dialog,
//! and the file is written through a temporary sibling and renamed into place.

use std::path::PathBuf;

use tauri::{
    ipc::{InvokeBody, Request},
    AppHandle,
};
use tauri_plugin_dialog::DialogExt;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";
const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;

fn validate_png(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err("The diagram image is too large to save".into());
    }
    if bytes.len() < 24 || !bytes.starts_with(PNG_SIGNATURE) || &bytes[12..16] != b"IHDR" {
        return Err("Only PNG diagram images can be saved".into());
    }
    Ok(())
}

/// Decode a percent-encoded header value, so names and folders may use any characters.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let pair = value.get(index + 1..index + 3)?;
            decoded.push(u8::from_str_radix(pair, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

/// A plain PNG file name: no folders, no control characters, and a `.png` extension.
fn image_file_name(value: &str) -> String {
    let name = value
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .unwrap_or("network-diagram");
    let cleaned: String = name
        .chars()
        .map(|character| {
            if character.is_control() || character == ':' {
                '_'
            } else {
                character
            }
        })
        .collect();
    let stem = cleaned.trim().trim_end_matches(".png");
    let stem = if stem.is_empty() || stem.starts_with('.') {
        "network-diagram"
    } else {
        stem
    };
    format!("{stem}.png")
}

fn header(request: &Request<'_>, name: &str) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(percent_decode)
}

#[tauri::command]
pub async fn save_diagram_image(
    app: AppHandle,
    request: Request<'_>,
) -> Result<Option<String>, String> {
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err("The diagram image must be sent as raw bytes".into());
    };
    validate_png(bytes)?;
    let filename = image_file_name(&header(&request, "x-eforge-filename").unwrap_or_default());
    let mut dialog = app
        .dialog()
        .file()
        .set_file_name(&filename)
        .add_filter("PNG image", &["png"]);
    if let Some(directory) = header(&request, "x-eforge-directory").map(PathBuf::from) {
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
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Choose a file name for the diagram image")?;
    let temporary = destination.with_file_name(format!(".{name}.partial"));
    let written = async {
        tokio::fs::write(&temporary, bytes).await?;
        tokio::fs::rename(&temporary, &destination).await
    }
    .await;
    if let Err(error) = written {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(format!("The diagram image could not be saved: {error}"));
    }
    Ok(Some(destination.to_string_lossy().into_owned()))
}

#[cfg(test)]
mod tests {
    use super::{image_file_name, percent_decode, validate_png, PNG_SIGNATURE};

    fn png(len: usize) -> Vec<u8> {
        let mut bytes = PNG_SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0, 0, 0, 13]);
        bytes.extend_from_slice(b"IHDR");
        bytes.resize(len.max(bytes.len()), 0);
        bytes
    }

    #[test]
    fn only_png_images_are_saved() {
        assert!(validate_png(&png(64)).is_ok());
        assert!(validate_png(b"GIF89a not a png at all...").is_err());
        assert!(validate_png(&PNG_SIGNATURE[..4]).is_err());
        let mut wrong_chunk = png(64);
        wrong_chunk[12..16].copy_from_slice(b"tEXt");
        assert!(validate_png(&wrong_chunk).is_err());
    }

    #[test]
    fn suggested_names_stay_in_the_chosen_folder_and_end_in_png() {
        assert_eq!(
            image_file_name("../secret/Talos network"),
            "Talos network.png"
        );
        assert_eq!(
            image_file_name(r"C:\secret\Talos network"),
            "Talos network.png"
        );
        assert_eq!(image_file_name("diagram.png"), "diagram.png");
        assert_eq!(image_file_name(""), "network-diagram.png");
        assert_eq!(image_file_name(".hidden"), "network-diagram.png");
        assert_eq!(image_file_name("a:b"), "a_b.png");
    }

    #[test]
    fn header_values_decode_any_characters() {
        assert_eq!(
            percent_decode("Caf%C3%A9%20map").as_deref(),
            Some("Café map")
        );
        assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%4"), None);
    }
}
