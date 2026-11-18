use std::path::PathBuf;
use tokio::process::Command;
use crate::error::{GuardError, Result};

#[derive(Clone, Debug)]
pub struct SandboxConfig {
    pub allowed_dir: PathBuf,
    pub allow_env: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            allowed_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            allow_env: vec!["PATH".to_string(), "HOME".to_string()],
        }
    }
}

/// Applies sandbox policy to a command that already has its executable set
/// (via `Command::new`). Appends args, clears env, restricts the working dir.
pub fn configure_command(cmd: &mut Command, config: &SandboxConfig, args: &[String]) -> Result<()> {
    // 1. Set current directory
    if !config.allowed_dir.exists() {
        return Err(GuardError::Sandbox(format!(
            "Allowed directory does not exist: {:?}",
            config.allowed_dir
        )));
    }
    cmd.current_dir(&config.allowed_dir);

    // 2. Clear environment
    cmd.env_clear();

    // 3. Populate base allowed environment variables + platform specifics
    let mut allowed = config.allow_env.clone();

    #[cfg(windows)]
    {
        for var in &["SYSTEMROOT", "COMSPEC", "PATHEXT", "USERPROFILE", "TEMP", "TMP"] {
            if !allowed.iter().any(|v| v.eq_ignore_ascii_case(var)) {
                allowed.push(var.to_string());
            }
        }
    }

    for var in allowed {
        if let Ok(val) = std::env::var(&var) {
            cmd.env(var, val);
        }
    }

    // 4. Setup args
    for arg in args {
        cmd.arg(arg);
    }

    // Setup stdio redirection for pipe
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    Ok(())
}
