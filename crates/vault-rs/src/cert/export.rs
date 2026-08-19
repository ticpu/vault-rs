use crate::cert::SerialNumber;
use crate::cli::args::ExportFormat;
use crate::storage::local::LocalStorage;
use crate::storage::metadata::normalize_serial;
use crate::storage::provenance::Provenance;
use crate::storage::CertificateStorage;
use crate::utils::errors::{Result, VaultCliError};
use crate::utils::pem::{PemCertificate, PemCertificateBundle, PemCertificateChain, PemPrivateKey};
use crate::utils::{
    parse_certificate_chain, write_output_or_print, write_output_or_print_bytes, write_to_file,
};
use crate::vault::client::VaultClient;
use crate::vault::PkiClient;
use std::fs;
use std::path::Path;
use x509_parser::pem::parse_x509_pem;

pub struct ExportCertificateRequest {
    pub pem_data: String,
    pub mount: String,
    pub identifier: String,
    pub format: ExportFormat,
    pub output_dir: Option<String>,
    pub no_passphrase: bool,
    pub text: bool,
    pub with_provenance: bool,
}

async fn find_certificate_in_storage(
    storage: &LocalStorage,
    identifier: &str,
) -> Result<Option<CertificateStorage>> {
    // A lookup that finds what it wanted does not care what else was
    // unreadable; one that does not has to say so rather than report a clean
    // absence, so the failures ride along to the caller's error.
    let (certs, unreadable) = storage.list_certificates().await?.into_parts();

    // discard-ok: probe; an identifier that is not a serial is looked up by CN
    if let Ok(serial) = SerialNumber::parse(identifier) {
        // Stored serials are colon-less and lower-case; comparing against the
        // colon form matches nothing and falls silently through to the CN.
        let wanted = normalize_serial(&serial.as_colon_hex());

        if let Some(cert) = certs
            .iter()
            .find(|cert| cert.meta.serial == wanted)
            .cloned()
        {
            return Ok(Some(cert));
        }
    }

    if let Some(cert) = certs
        .iter()
        .find(|cert| cert.meta.cn == identifier)
        .cloned()
    {
        return Ok(Some(cert));
    }

    if !unreadable.is_empty() {
        return Err(VaultCliError::IncompleteRead(format!(
            "'{identifier}' was not found, and {} stored artifact(s) could not be read, so this \
             absence is not authoritative. Run `{} storage list` for what is wrong with them.",
            unreadable.len(),
            crate::utils::PROGRAM_NAME
        )));
    }
    Ok(None)
}

/// The stored private key, or nothing where the artifact holds none.
///
/// A CSR-signed artifact keeps its key with the requester, so a stored key may
/// decrypt to an empty string. That has to reach the caller as an absence:
/// `Some(empty)` is how a bundle asked for with a key comes out without one
/// and says nothing about it.
fn stored_key(pem: String) -> Option<PemPrivateKey> {
    match pem.trim().is_empty() {
        true => None,
        false => Some(PemPrivateKey::new(pem)),
    }
}

async fn get_certificate_data_from_storage(
    storage: &LocalStorage,
    cert_record: &CertificateStorage,
) -> Result<(String, String, String)> {
    let (certificate_pem, private_key, ca_chain_pem, _) = storage
        .get_certificate(
            &cert_record.pki_mount,
            &cert_record.meta.cn,
            Some(&cert_record.meta.serial),
        )
        .await?;
    Ok((certificate_pem, private_key, ca_chain_pem))
}

fn build_ca_chain(ca_chain_pem: &str) -> Result<PemCertificateChain> {
    let mut ca_chain = PemCertificateChain::new();
    if !ca_chain_pem.is_empty() {
        for ca_cert in parse_certificate_chain(ca_chain_pem)? {
            ca_chain.add_certificate(ca_cert);
        }
    }
    Ok(ca_chain)
}

async fn get_certificate_bundle_from_storage(
    client: &VaultClient,
    identifier: &str,
) -> Result<(Option<PemPrivateKey>, PemCertificate, PemCertificateChain)> {
    let storage = LocalStorage::with_client(client.clone())?;

    let cert_record = find_certificate_in_storage(&storage, identifier)
        .await?
        .ok_or_else(|| {
            VaultCliError::InvalidInput(format!(
                "Certificate '{identifier}' not found in local storage"
            ))
        })?;

    let (certificate_pem, private_key, ca_chain_pem) =
        get_certificate_data_from_storage(&storage, &cert_record).await?;

    let pem_key = stored_key(private_key);
    let pem_cert = PemCertificate::new(certificate_pem);
    let ca_chain = build_ca_chain(&ca_chain_pem)?;

    Ok((pem_key, pem_cert, ca_chain))
}

async fn export_p12(client: &VaultClient, request: &ExportCertificateRequest) -> Result<()> {
    // P12 export requires both certificate and private key from local storage.
    // find_certificate_in_storage/get_certificate_data_from_storage (not the
    // combined get_certificate_bundle_from_storage) so a decrypt failure or
    // corrupt index reports its own cause instead of "not found".
    let storage = LocalStorage::with_client(client.clone())?;

    let cert_record = find_certificate_in_storage(&storage, &request.identifier)
        .await?
        .ok_or_else(|| {
            VaultCliError::InvalidInput(format!(
                "P12 export requires private key. Certificate '{}' not found in local storage.",
                request.identifier
            ))
        })?;

    let (certificate_pem, private_key, ca_chain_pem) =
        get_certificate_data_from_storage(&storage, &cert_record)
            .await
            .map_err(|e| {
                VaultCliError::InvalidInput(format!(
                    "Failed to retrieve private key for '{}': {e}",
                    request.identifier
                ))
            })?;

    // Caught here rather than left to openssl, which fails with "Could not find
    // private key from -inkey file" and names neither the artifact nor why.
    if private_key.trim().is_empty() {
        return Err(VaultCliError::InvalidInput(format!(
            "'{}' is stored without a private key, so a PKCS#12 bundle cannot be built from it. \
             Use --format chain for a keyless artifact.",
            request.identifier
        )));
    }

    let private_key = PemPrivateKey::new(private_key);
    let certificate = PemCertificate::new(certificate_pem);
    let ca_chain = build_ca_chain(&ca_chain_pem)?;

    let dir = request.output_dir.as_deref().unwrap_or(".");
    let p12_filename = format!("{}.p12", sanitize_filename(&request.identifier));
    let p12_path = Path::new(dir).join(&p12_filename);

    fs::create_dir_all(dir)?;

    // Read before moving into the bundle; emptiness was rejected above.
    let private_key_pem = private_key.pem_data().to_string();
    let bundle = PemCertificateBundle::new(Some(private_key), certificate, ca_chain);

    match crate::utils::create_p12_file(
        &p12_path,
        &private_key_pem,
        bundle.certificate().pem_data(),
        &bundle.ca_chain().pem_data(),
        request.no_passphrase,
    ) {
        Ok(()) => {
            eprintln!("P12 certificate exported to: {}", p12_path.display());
            Ok(())
        }
        Err(e) => Err(VaultCliError::InvalidInput(format!(
            "Failed to create P12: {e}"
        ))),
    }
}

/// Bundle format: private key + certificate + CA chain in PEM format. Requires
/// the key to be held in local storage — the keyless artifact is `chain`.
async fn export_bundle(
    client: &VaultClient,
    request: &ExportCertificateRequest,
    provenance: Option<&str>,
) -> Result<()> {
    let (private_key, cert_from_storage, ca_chain_from_storage) =
        get_certificate_bundle_from_storage(client, &request.identifier)
            .await
            .map_err(|e| {
                VaultCliError::InvalidInput(format!(
                    "Bundle export requires a private key held in local storage for '{}': {e}. \
                     Use --format chain for a keyless artifact.",
                    request.identifier
                ))
            })?;

    let private_key = private_key.ok_or_else(|| {
        VaultCliError::InvalidInput(format!(
            "'{}' is stored without a private key, so a bundle cannot be assembled from it. \
             Use --format chain for a keyless artifact.",
            request.identifier
        ))
    })?;

    let ca_chain = ca_chain_from_storage.without_root()?;
    let bundle = PemCertificateBundle::new(Some(private_key), cert_from_storage, ca_chain);
    let output_content = with_provenance(bundle.output(request.text), provenance);
    write_output_or_print(
        request.output_dir.as_deref(),
        &format!("{}.pem", sanitize_filename(&request.identifier)),
        &output_content,
    )
}

/// Default PEM format - output to stdout (pipe-friendly) or file
async fn export_pem_certificate(
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
    provenance: Option<&str>,
) -> Result<()> {
    let output_content = with_provenance(certificate.output(request.text), provenance);

    if let Some(ref dir) = request.output_dir {
        write_to_file(
            dir,
            &format!("{}.pem", sanitize_filename(&request.identifier)),
            &output_content,
        )
    } else {
        // Output to stdout for piping (already has newline)
        print!("{output_content}");
        Ok(())
    }
}

fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let (_, pem) = parse_x509_pem(pem_data.as_bytes()).map_err(|e| {
        VaultCliError::CertParsing(format!("Failed to parse PEM for DER export: {e}"))
    })?;
    Ok(pem.contents)
}

async fn export_der_certificate(
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
) -> Result<()> {
    let der = pem_to_der(certificate.pem_data())?;
    write_output_or_print_bytes(
        request.output_dir.as_deref(),
        &format!("{}.der", sanitize_filename(&request.identifier)),
        &der,
    )
}

/// Get full certificate chain and create chain object. `include_root` selects between
/// `chain` (external handoff, root dropped) and `chain-with-root` (internal trust
/// configuration) — see docs/design-rationale.md.
async fn export_certificate_chain(
    client: &VaultClient,
    request: &ExportCertificateRequest,
    certificate: PemCertificate,
    include_root: bool,
    provenance: Option<&str>,
) -> Result<()> {
    let ca_chain_pem = client.get_ca_chain(&request.mount).await?;
    let ca_chain = build_ca_chain(&ca_chain_pem)?;
    if ca_chain.certificates().is_empty() {
        return Err(VaultCliError::InvalidInput(format!(
            "Mount '{}' has no CA chain configured",
            request.mount
        )));
    }

    // without_root() must apply to the CA chain only: applying it after the
    // leaf is prepended filters a self-signed leaf too (e.g. exporting a root
    // CA itself), silently writing an empty file.
    let ca_chain = if include_root {
        ca_chain
    } else {
        ca_chain.without_root()?
    };

    let mut chain = PemCertificateChain::new();
    chain.add_certificate(certificate);
    for cert in ca_chain.certificates() {
        chain.add_certificate(cert.clone());
    }

    if chain.certificates().len() <= 1 {
        let msg = if include_root {
            format!(
                "Mount '{}' CA chain is empty; nothing to export besides the leaf. Use --format pem instead.",
                request.mount
            )
        } else {
            format!(
                "Mount '{}' CA chain is only the self-signed root, which is dropped for external handoff, leaving nothing to export. Use --format pem for the leaf alone, or --format chain-with-root to include the root.",
                request.mount
            )
        };
        return Err(VaultCliError::InvalidInput(msg));
    }

    let output_content = with_provenance(chain.output(request.text), provenance);
    let suffix = if include_root {
        "chain-with-root"
    } else {
        "chain"
    };

    if let Some(ref dir) = request.output_dir {
        write_to_file(
            dir,
            &format!("{}_{suffix}.pem", sanitize_filename(&request.identifier)),
            &output_content,
        )
    } else {
        print!("{output_content}");
        Ok(())
    }
}

async fn export_key(client: &VaultClient, request: &ExportCertificateRequest) -> Result<()> {
    let storage = LocalStorage::with_client(client.clone())?;

    let cert_record = find_certificate_in_storage(&storage, &request.identifier)
        .await?
        .ok_or_else(|| VaultCliError::InvalidInput(
            format!("Private key for '{}' not found in local storage. Keys are only available for certificates created with vault-rs.", request.identifier)
        ))?;

    let (_, private_key, _) = get_certificate_data_from_storage(&storage, &cert_record)
        .await
        .map_err(|e| VaultCliError::InvalidInput(format!("Failed to retrieve private key: {e}")))?;

    if let Some(ref dir) = request.output_dir {
        write_to_file(
            dir,
            &format!("{}.key", sanitize_filename(&request.identifier)),
            &private_key,
        )
    } else {
        println!("{private_key}");
        Ok(())
    }
}

pub async fn export_certificate(
    client: &VaultClient,
    request: ExportCertificateRequest,
) -> Result<()> {
    let parsed_certs = parse_certificate_chain(&request.pem_data)?;
    let certificate = if let Some(first_cert) = parsed_certs.first() {
        first_cert.clone()
    } else {
        return Err(VaultCliError::InvalidInput(
            "No valid certificate found in PEM data".to_string(),
        ));
    };

    // Resolved once, before any format runs, so a format that cannot carry it
    // refuses before writing anything.
    let provenance = provenance_block(client, &request).await?;
    let provenance = provenance.as_deref();

    match request.format {
        ExportFormat::Pem => export_pem_certificate(&request, certificate, provenance).await,
        ExportFormat::Der => export_der_certificate(&request, certificate).await,
        ExportFormat::Chain => {
            export_certificate_chain(client, &request, certificate, false, provenance).await
        }
        ExportFormat::ChainWithRoot => {
            export_certificate_chain(client, &request, certificate, true, provenance).await
        }
        ExportFormat::Key => export_key(client, &request).await,
        ExportFormat::P12 => export_p12(client, &request).await,
        ExportFormat::Bundle => export_bundle(client, &request, provenance).await,
    }
}

/// The provenance block to append, when asked for and the format can carry it.
///
/// A binary format has nowhere to put it, and a key on its own is not the
/// artifact it describes. Refused rather than dropped: a flag that silently
/// does nothing is how an operator ships an artifact believing it carries
/// something it does not.
async fn provenance_block(
    client: &VaultClient,
    request: &ExportCertificateRequest,
) -> Result<Option<String>> {
    if !request.with_provenance {
        return Ok(None);
    }

    match request.format {
        ExportFormat::Pem
        | ExportFormat::Chain
        | ExportFormat::ChainWithRoot
        | ExportFormat::Bundle => {}
        ref format => {
            return Err(VaultCliError::InvalidInput(format!(
                "--with-provenance has nowhere to go in {format:?} output. Use pem, chain, \
                 chain-with-root or bundle."
            )))
        }
    }

    // The role lives only in the local store; Vault, which the rest of this
    // command reads from, has never recorded one.
    let storage = LocalStorage::with_client(client.clone())?;
    let record = find_certificate_in_storage(&storage, &request.identifier)
        .await?
        .ok_or_else(|| {
            VaultCliError::InvalidInput(format!(
                "--with-provenance needs '{}' in the local store, and it is not there. The mount \
                 and issuing role exist nowhere else, so there is nothing to embed.",
                request.identifier
            ))
        })?;

    Ok(Some(
        Provenance::new(
            record.pki_mount.clone(),
            record.meta.role.clone(),
            record.meta.crypto.clone(),
            record.meta.status.clone(),
            record.created,
        )
        .to_pem_block()?,
    ))
}

/// Append the provenance block, which goes last.
///
/// `parse_x509_pem` decodes the first block it finds without checking the
/// label, so a leading provenance block would hand its bytes to a DER parser
/// in every reader that takes a whole file.
fn with_provenance(content: String, provenance: Option<&str>) -> String {
    match provenance {
        Some(block) => format!("{content}{block}"),
        None => content,
    }
}

fn sanitize_filename(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if c.is_whitespace() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            if !in_run {
                result.push('_');
                in_run = true;
            }
        } else {
            result.push(c);
            in_run = false;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn testdata(name: &str) -> String {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cert/testdata/");
        std::fs::read_to_string(format!("{path}{name}.pem"))
            .unwrap_or_else(|e| panic!("missing fixture {name}.pem: {e}"))
    }

    #[test]
    fn der_export_is_valid_der_matching_the_pem_subject() {
        let pem_text = testdata("leaf-client");
        let der = pem_to_der(&pem_text).expect("PEM fixture should convert to DER");

        assert_eq!(der[0], 0x30, "DER certificates are a SEQUENCE (tag 0x30)");

        let (_, from_der) = X509Certificate::from_der(&der).expect("DER should reparse");
        let (_, pem) = parse_x509_pem(pem_text.as_bytes()).expect("fixture should parse as PEM");
        let (_, from_pem) =
            X509Certificate::from_der(&pem.contents).expect("PEM contents should parse");

        assert_eq!(from_der.subject(), from_pem.subject());
    }

    #[test]
    fn certificate_chain_assembly_keeps_a_self_signed_leaf() {
        let root_pem = testdata("ca-root");
        let leaf = PemCertificate::new(root_pem.clone());

        // without_root() must run on the CA chain before the leaf is added;
        // otherwise exporting a self-signed root as the leaf filters it too.
        let ca_chain = build_ca_chain(&root_pem)
            .expect("fixture parses")
            .without_root()
            .expect("self-signed check should succeed");

        let mut chain = PemCertificateChain::new();
        chain.add_certificate(leaf.clone());
        for cert in ca_chain.certificates() {
            chain.add_certificate(cert.clone());
        }

        assert_eq!(
            chain.certificates().len(),
            1,
            "root is self-signed and dropped from the CA chain, leaf remains"
        );
        assert_eq!(chain.certificates()[0].pem_data(), leaf.pem_data());
    }

    /// A stored artifact with no key must present as having none. Reporting
    /// it as an empty key produces a bundle without one, at exit 0, from a
    /// command documented to need a key.
    #[test]
    fn a_keyless_artifact_reports_no_key_rather_than_an_empty_one() {
        assert!(stored_key(String::new()).is_none());
        assert!(stored_key("\n  \n".to_string()).is_none());
        // Anything with content is carried through: the store decides what a
        // key is, this only decides whether one is there.
        assert!(stored_key("key material".to_string()).is_some());
    }

    #[test]
    fn sanitize_filename_replaces_and_collapses_whitespace() {
        assert_eq!(sanitize_filename("CC Root CA E1"), "CC_Root_CA_E1");
        assert_eq!(sanitize_filename("CC  Root:CA"), "CC_Root_CA");
        assert_eq!(
            sanitize_filename("a/b\\c*d?e\"f<g>h|i"),
            "a_b_c_d_e_f_g_h_i"
        );
    }

    /// A local store with no matching record makes `get_certificate_bundle_from_storage`
    /// fail without ever reaching the network, so this exercises `export_bundle`'s
    /// real error path without a stub Vault server.
    #[tokio::test]
    async fn bundle_export_without_a_stored_key_is_an_error() {
        let client =
            VaultClient::with_token("http://127.0.0.1:1".to_string(), "test-token".to_string())
                .expect("test client");

        let request = ExportCertificateRequest {
            pem_data: testdata("leaf-client"),
            mount: "pki".to_string(),
            identifier: format!("no-such-cert-{}", std::process::id()),
            format: ExportFormat::Bundle,
            output_dir: None,
            no_passphrase: false,
            text: false,
            with_provenance: false,
        };

        let err = export_bundle(&client, &request, None).await.expect_err(
            "bundle export must fail without a stored key, never fall back to keyless output",
        );
        assert!(
            err.to_string()
                .contains("Bundle export requires a private key"),
            "unexpected error: {err}"
        );
    }
}
