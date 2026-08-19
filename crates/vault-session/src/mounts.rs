use crate::client::KvLayout;
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

/// The mounts a token can see, as `sys/internal/ui/mounts` reports them.
///
/// `sys/mounts` is the complete listing and needs a privilege a narrow role is
/// not given; this one answers with what the token is allowed to reach, which
/// is what a program verifying its own credentials can ask for.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VisibleMounts {
    #[serde(default)]
    pub secret: HashMap<String, MountInfo>,
    #[serde(default)]
    pub auth: HashMap<String, MountInfo>,
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

    /// Which layout a KV mount addresses a secret through. `None` for a mount
    /// that is not KV, which has no layout to have.
    pub fn kv_layout(&self) -> Option<KvLayout> {
        match self.is_kv() {
            false => None,
            true => Some(match self.get_version() {
                Some("2") => KvLayout::Versioned,
                _ => KvLayout::Flat,
            }),
        }
    }
}

impl VisibleMounts {
    /// The KV mounts, without their trailing separator, each with the layout
    /// it reported.
    pub fn kv_mounts(&self) -> Vec<(String, KvLayout)> {
        self.secret
            .iter()
            .filter_map(|(path, info)| {
                Some((path.trim_end_matches('/').to_string(), info.kv_layout()?))
            })
            .collect()
    }

    /// The auth mounts, without their trailing separator, each with its type.
    pub fn auth_mounts(&self) -> Vec<(String, String)> {
        self.auth
            .iter()
            .map(|(path, info)| {
                (
                    path.trim_end_matches('/').to_string(),
                    info.mount_type.clone(),
                )
            })
            .collect()
    }
}
