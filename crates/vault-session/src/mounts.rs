use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountInfo {
    #[serde(rename = "type")]
    pub mount_type: String,
    pub description: Option<String>,
    pub options: Option<HashMap<String, serde_json::Value>>,
    pub config: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountsResponse {
    pub data: HashMap<String, MountInfo>,
}

impl MountInfo {
    pub fn get_version(&self) -> Option<&str> {
        self.options.as_ref()?.get("version")?.as_str()
    }

    pub fn is_pki(&self) -> bool {
        self.mount_type == "pki"
    }

    pub fn is_kv(&self) -> bool {
        self.mount_type == "kv"
    }
}
