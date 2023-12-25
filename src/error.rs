use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to reading: {0}")]
    FailedReading(std::io::Error),

    #[error("Invalid mdx {0} checksum")]
    InvalidCheckSum(&'static str),

    #[error("No GeneratedByEngineVersion found in header")]
    NoVersion,

    #[error("Invalid version({0})")]
    InvalidVersion(String),

    #[error("Unsupported version({0})")]
    UnsupportedVersion(u8),

    #[error("Invalid data")]
    InvalidData,

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("Invalid encrypt method: {0}")]
    InvalidEncryptMethod(u32),

    #[error("Invalid compress method: {0}")]
    InvalidCompressMethod(u32),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::FailedReading(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
