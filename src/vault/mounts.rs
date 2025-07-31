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

    pub fn display_name(&self) -> String {
        if self.mount_type == "kv" {
            if let Some(version) = self.get_version() {
                format!("{} v{}", self.mount_type, version)
            } else {
                format!("{} v1", self.mount_type)
            }
        } else {
            self.mount_type.clone()
        }
    }

    pub fn is_pki(&self) -> bool {
        self.mount_type == "pki"
    }

    pub fn is_kv(&self) -> bool {
        self.mount_type == "kv"
    }
}

impl MountsResponse {
    pub fn pki_mounts(&self) -> Vec<String> {
        self.data
            .iter()
            .filter_map(|(path, info)| {
                if info.is_pki() {
                    Some(path.trim_end_matches('/').to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn kv_mounts(&self) -> Vec<String> {
        self.data
            .iter()
            .filter_map(|(path, info)| {
                if info.is_kv() {
                    Some(path.trim_end_matches('/').to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn as_table_data(&self) -> Vec<Vec<String>> {
        let mut mount_list: Vec<_> = self.data.iter().collect();
        mount_list.sort_by_key(|(path, _)| *path);

        mount_list
            .iter()
            .map(|(mount_path, mount_info)| {
                vec![
                    mount_path.trim_end_matches('/').to_string(),
                    mount_info.display_name(),
                ]
            })
            .collect()
    }
}
