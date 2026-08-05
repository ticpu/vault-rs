//! Fixtures shared by the storage test modules: a stub Vault, a scratch
//! artifact tree, and a writer for entries in it.

use crate::storage::local::{CertificateData, LocalStorage};
use crate::storage::metadata::{CertStatus, StoredIdentity, StoredMetadata};
use crate::vault::client::VaultClient;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const CLUSTER: &str = "cluster-under-test";

pub fn leaf_pem() -> String {
    fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/cert/testdata/leaf-client.pem"
    ))
    .expect("fixture")
}

pub fn scratch(name: &str) -> PathBuf {
    let dir =
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target/storage-tests")).join(name);
    // discard-ok: test scratch; the directory usually does not exist yet
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// A Vault that answers the master-key read and reports `cluster`.
pub async fn stub_vault(cluster: &str, key: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret/": { "type": "kv", "options": { "version": "2" } } }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/vault-rs/encryption-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "key": key } }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "cluster_id": cluster })))
        .mount(&server)
        .await;
    server
}

pub fn store(server: &MockServer, root: &Path) -> LocalStorage {
    LocalStorage::for_test(
        VaultClient::for_test(server.uri(), "test-token".to_string()).expect("test client"),
        root.to_path_buf(),
    )
}

pub async fn write_entry(storage: &LocalStorage, cn: &str, serial: &str, key: &str) {
    storage
        .store_certificate(CertificateData {
            pki_mount: "pki",
            cn,
            serial,
            certificate_pem: &leaf_pem(),
            private_key_pem: key,
            ca_chain_pem: "",
            metadata: StoredMetadata {
                crypto: Some("ec".to_string()),
                created: chrono::Utc::now(),
                file_info: Default::default(),
                meta: StoredIdentity {
                    role: Some("client".to_string()),
                    status: CertStatus::Active,
                },
            },
        })
        .await
        .expect("storing");
}
