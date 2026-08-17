//! `metadata` and `serial` are outside the `cli` feature: the error type and
//! the column renderer name them, and neither reads a certificate.

pub mod metadata;
pub mod serial;

pub use metadata::{CertificateColumn, CertificateMetadata};
pub use serial::SerialNumber;

#[cfg(feature = "cli")]
pub mod ca_info;
#[cfg(feature = "cli")]
pub mod cache;
#[cfg(feature = "cli")]
pub mod create;
#[cfg(feature = "cli")]
pub mod csr;
#[cfg(feature = "cli")]
pub mod export;
#[cfg(feature = "cli")]
pub mod inspect;
#[cfg(feature = "cli")]
pub mod listing;
#[cfg(feature = "cli")]
pub mod lookup;
#[cfg(feature = "cli")]
pub mod parser;
#[cfg(feature = "cli")]
pub mod plan;
#[cfg(feature = "cli")]
pub mod report;
#[cfg(feature = "cli")]
pub mod revoke;
#[cfg(feature = "cli")]
pub mod role_info;
#[cfg(feature = "cli")]
pub mod service;
#[cfg(feature = "cli")]
pub mod show;
#[cfg(feature = "cli")]
pub mod sign;
#[cfg(feature = "cli")]
pub mod verify;

#[cfg(feature = "cli")]
pub use certificates::*;

#[cfg(feature = "cli")]
mod certificates {
    pub use super::ca_info::show_ca_info;
    pub use super::cache::CertificateCache;
    pub use super::create::{create_certificate, CreateCertificateRequest};
    pub use super::csr::{parse_csr_pem, CsrInfo};
    pub use super::export::{export_certificate, ExportCertificateRequest};
    pub use super::inspect::{inspect_csr, InspectCsrRequest};
    pub use super::listing::{CertListFilter, CertificateListingService, StorageListRequest};
    pub use super::lookup::find_certificate_by_identifier;
    pub use super::parser::CertificateParser;
    pub use super::plan::{build_plan, PlanInput};
    pub use super::report::{
        identity_field_lines, print_handoff_note, print_identity_fields, IdentityField,
    };
    pub use super::revoke::{revoke_certificate, RevokeRequest};
    pub use super::role_info::show_role_info;
    pub use super::service::CertificateService;
    pub use super::show::show_certificate;
    pub use super::sign::{sign_certificate_from_csr, CsrSignRequest};
    pub use super::verify::{verify_certificate, Purpose, VerifyRequest};
}
