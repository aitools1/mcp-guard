use thiserror::Error;

#[derive(Error, Debug)]
pub enum GuardError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON-RPC error: {0}")]
    JsonRpc(#[from] serde_json::Error),

    #[error("Sandbox setup error: {0}")]
    Sandbox(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("Config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, GuardError>;
