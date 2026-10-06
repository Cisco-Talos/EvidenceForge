use std::path::PathBuf;

use tauri_plugin_dialog::FilePath;
use tokio::sync::oneshot;

type FileSelection = Box<dyn FnOnce(Option<FilePath>) + Send>;

/// Await a native dialog without blocking the AppKit event loop or a runtime worker.
pub async fn select_local_path(
    show: impl FnOnce(FileSelection),
) -> Result<Option<PathBuf>, String> {
    let (sender, receiver) = oneshot::channel();
    show(Box::new(move |selection| {
        let _ = sender.send(selection);
    }));
    let selection = receiver
        .await
        .map_err(|_| "The file picker closed unexpectedly; please try again")?;
    selection
        .map(|selection| {
            selection
                .into_path()
                .map_err(|_| "Select a local file or folder".to_string())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn waiting_picker_yields_and_returns_selection() {
        let (callback_sender, callback_receiver) = oneshot::channel();
        let selection = select_local_path(|complete| {
            assert!(callback_sender.send(complete).is_ok());
        });
        tokio::pin!(selection);
        // This task must run while the dialog is still open, even on a single thread.
        let complete = tokio::select! {
            biased;
            result = &mut selection => panic!("Picker completed before a selection: {result:?}"),
            complete = callback_receiver => complete.unwrap(),
        };
        let path = PathBuf::from("/scenario.yaml");
        complete(Some(path.clone().into()));
        assert_eq!(selection.await, Ok(Some(path)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_picker_returns_no_path() {
        assert_eq!(select_local_path(|complete| complete(None)).await, Ok(None));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lost_dialog_callback_reports_error() {
        let result = select_local_path(drop).await;
        assert!(result.unwrap_err().contains("try again"));
    }
}
