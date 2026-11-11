//! Relocatable console entry point; no build-machine interpreter path is embedded.
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let result = (|| -> Result<i32, Box<dyn std::error::Error>> {
        let executable = std::env::current_exe()?;
        let root = executable
            .parent()
            .ok_or("No Scripts directory")?
            .parent()
            .ok_or("No runtime directory")?;
        let mut command = Command::new(root.join("python.exe"));
        command
            .args(["-I", "-B", "-X", "utf8", "-m", "evidenceforge"])
            .args(std::env::args_os().skip(1))
            .env_remove("PYTHONHOME")
            .env_remove("PYTHONPATH");
        if root.join("release.json").is_file() {
            command.env("EFORGE_STUDIO_RUNTIME_ROOT", root);
        }
        Ok(command.status()?.code().unwrap_or(1))
    })();
    match result {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(error) => {
            eprintln!("Could not start the bundled EvidenceForge CLI: {error}");
            ExitCode::FAILURE
        }
    }
}
