use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateData {
    pub certificate: String,
    pub revocation_time: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateResponse {
    pub data: CertificateData,
}

impl CertificateData {
    pub fn is_revoked(&self) -> bool {
        self.revocation_time.is_some_and(|t| t > 0)
    }
}
