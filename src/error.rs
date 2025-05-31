use std::io;
use std::net::AddrParseError;
use std::num::ParseIntError;
use std::string::{FromUtf16Error, FromUtf8Error};
use thiserror::Error;

/// The error type for network diagnostics operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// I/O error occurred during system call
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Failed to parse network address
    #[error("Address parse error: {0}")]
    AddrParse(#[from] AddrParseError),

    /// Failed to parse integer from system output
    #[error("Integer parse error: {0}")]
    ParseInt(#[from] ParseIntError),

    /// Failed to parse UTF-8 string
    #[error("UTF-8 parse error: {0}")]
    Utf8Parse(#[from] FromUtf8Error),

    /// Failed to parse UTF-16 string (Windows)
    #[error("UTF-16 parse error: {0}")]
    Utf16Parse(#[from] FromUtf16Error),

    /// Platform-specific system call failed
    #[error("System call '{operation}' failed with code {code}")]
    SystemCall { operation: String, code: i32 },

    /// Feature not supported on this platform
    #[error("Feature '{feature}' not supported on {platform}")]
    UnsupportedPlatform { feature: String, platform: String },

    /// Failed to access system file or resource
    #[error("Failed to access {resource}: {reason}")]
    ResourceAccess { resource: String, reason: String },

    /// Invalid data format encountered
    #[error("Invalid data format in {0}: {1}")]
    InvalidFormat(String, String),

    /// Permission denied accessing system resource
    #[error("Permission denied accessing {resource}. Try running with elevated privileges.")]
    PermissionDenied { resource: String },

    /// Network interface not found
    #[error("Network interface '{name}' not found")]
    InterfaceNotFound { name: String },

    /// Socket not found or no longer exists
    #[error("Socket not found: {details}")]
    SocketNotFound { details: String },

    /// Configuration file not found or invalid
    #[error("Configuration error: {details}")]
    ConfigError { details: String },
}

impl Error {
    /// Create a new system call error
    pub fn system_call(operation: impl Into<String>, code: i32) -> Self {
        Self::SystemCall {
            operation: operation.into(),
            code,
        }
    }

    /// Create a new unsupported platform error
    pub fn unsupported_platform(feature: impl Into<String>) -> Self {
        Self::UnsupportedPlatform {
            feature: feature.into(),
            platform: std::env::consts::OS.to_string(),
        }
    }

    /// Create a new resource access error
    pub fn resource_access(resource: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::ResourceAccess {
            resource: resource.into(),
            reason: reason.into(),
        }
    }

    /// Create a new invalid format error
    pub fn invalid_format(source: impl Into<String>, details: impl Into<String>) -> Self {
        Self::InvalidFormat(source.into(), details.into())
    }

    /// Create a new permission denied error
    pub fn permission_denied(resource: impl Into<String>) -> Self {
        Self::PermissionDenied {
            resource: resource.into(),
        }
    }

    /// Create a new interface not found error
    pub fn interface_not_found(name: impl Into<String>) -> Self {
        Self::InterfaceNotFound { name: name.into() }
    }

    /// Create a new socket not found error
    pub fn socket_not_found(details: impl Into<String>) -> Self {
        Self::SocketNotFound {
            details: details.into(),
        }
    }

    /// Create a new configuration error
    pub fn config_error(details: impl Into<String>) -> Self {
        Self::ConfigError {
            details: details.into(),
        }
    }
}

/// A specialized `Result` type for network diagnostics operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during network operations
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] ParseIntError),
    #[error("Platform error: {0}")]
    Platform(String),
    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    #[error("Invalid MAC address: {0}")]
    InvalidMacAddress(String),
    #[error("Unsupported platform")]
    UnsupportedPlatform,
    #[error("Invalid data")]
    InvalidData,
    #[error("OS error: {0}")]
    OsError(i32),
    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),
}

impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Self {
        match err {
            NetworkError::Io(e) => Self::Io(e),
            NetworkError::Parse(e) => Self::ParseInt(e),
            NetworkError::Platform(msg) => Self::SystemCall {
                operation: msg,
                code: -1,
            },
            NetworkError::InvalidIpAddress(msg) => {
                Self::InvalidFormat("IP address".to_string(), msg)
            }
            NetworkError::InvalidMacAddress(msg) => {
                Self::InvalidFormat("MAC address".to_string(), msg)
            }
            NetworkError::UnsupportedPlatform => Self::unsupported_platform("socket operation"),
            NetworkError::InvalidData => {
                Self::InvalidFormat("socket data".to_string(), "invalid format".to_string())
            }
            NetworkError::OsError(code) => Self::SystemCall {
                operation: "socket operation".to_string(),
                code,
            },
            NetworkError::InterfaceNotFound(name) => Self::InterfaceNotFound { name },
        }
    }
}
