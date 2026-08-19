pub use vault_session::cert::{
    metadata, serial, CertificateColumn, CertificateMetadata, SerialNumber,
};

pub mod ca_info;
pub mod cache;
pub mod create;
pub mod csr;
pub mod export;
pub mod inspect;
pub mod listing;
pub mod lookup;
pub mod parser;
pub mod plan;
pub mod report;
pub mod revoke;
pub mod role_info;
pub mod service;
pub mod show;
pub mod sign;
pub mod verify;

pub use certificates::*;

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
