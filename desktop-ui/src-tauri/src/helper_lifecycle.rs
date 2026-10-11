//! Explicit native-shell attachment and exit notification for the shared helper.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

#[derive(Clone, serde::Deserialize)]
struct Connection {
    url: String,
    token: String,
    app_session: String,
}

#[derive(Default)]
pub struct HelperConnection {
    connection: Mutex<Option<Connection>>,
    startup: Mutex<()>,
    closing: AtomicBool,
}

impl HelperConnection {
    /// Serialize bootstrap attempts and let exit wait for any attachment in flight.
    pub fn startup(&self) -> Result<MutexGuard<'_, ()>, String> {
        let guard = self
            .startup
            .lock()
            .map_err(|_| "Could not coordinate Studio's helper startup".to_string())?;
        self.ensure_open()?;
        Ok(guard)
    }

    pub fn ensure_open(&self) -> Result<(), String> {
        if self.closing.load(Ordering::SeqCst) {
            return Err("Studio is closing".into());
        }
        Ok(())
    }

    pub fn has_connection(&self) -> bool {
        self.connection
            .lock()
            .is_ok_and(|connection| connection.is_some())
    }

    /// Only one async exit handoff should own the final native exit.
    pub fn request_exit(&self) -> bool {
        !self.closing.swap(true, Ordering::SeqCst)
    }

    pub fn remember(&self, value: &serde_json::Value) -> Result<(), String> {
        let connection = serde_json::from_value(value.clone())
            .map_err(|_| "Studio helper returned incomplete application identity".to_string())?;
        *self
            .connection
            .lock()
            .map_err(|_| "Could not retain Studio's helper connection".to_string())? =
            Some(connection);
        Ok(())
    }

    /// Release this application only; the helper owns draining and shutdown.
    pub fn detach(&self) {
        self.closing.store(true, Ordering::SeqCst);
        // The async exit command waits here on a worker, leaving the window's
        // event loop free. A bootstrap already in flight must publish its
        // connection before we can explicitly release the application session.
        let _startup = self.startup.lock();
        let connection = match self.connection.lock() {
            Ok(mut connection) => connection.take(),
            Err(_) => None,
        };
        let Some(connection) = connection else {
            return;
        };
        // Wait for the acknowledgement before the native event loop terminates.
        // A dedicated thread avoids nesting a runtime inside a Tauri command.
        let sent = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| ())?;
            runtime.block_on(async {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(2))
                    .build()
                    .map_err(|_| ())?;
                let response = client
                    .post(format!("{}/v1/session/app-exit", connection.url))
                    .header("X-EForge-Token", connection.token)
                    .header("X-EForge-Session", connection.app_session)
                    .send()
                    .await
                    .map_err(|_| ())?;
                if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                    // The renderer's close handoff may already have started exit.
                    return Ok(());
                }
                response.error_for_status().map(|_| ()).map_err(|_| ())
            })
        })
        .join();
        if !matches!(sent, Ok(Ok(()))) {
            eprintln!("Could not notify the Studio helper of app exit; process monitoring will release it");
        }
    }
}
