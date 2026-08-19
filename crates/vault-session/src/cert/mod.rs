//! What the error type and the column renderer name, and neither reads a
//! certificate.

pub mod metadata;
pub mod serial;

pub use metadata::{CertificateColumn, CertificateMetadata};
pub use serial::SerialNumber;
