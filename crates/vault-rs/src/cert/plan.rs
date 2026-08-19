//! Builds the `--dry-run` plan: what the role — and, where the role allows
//! it, the invocation — determines Vault will issue, with each field's
//! source named (see docs/design-rationale.md, "The issuing role, not the
//! invocation, defines the issued identity").

use crate::cert::csr::CsrInfo;
use crate::cert::report::IdentityField;
use crate::vault::pki::RoleConfig;

pub struct PlanInput<'a> {
    pub role: &'a RoleConfig,
    /// `None` when the command has no CN argument, so there is no invocation
    /// to compare the role against and none to attribute a value to.
    pub cn_arg: Option<&'a str>,
    pub crypto_arg: Option<&'a str>,
    pub alt_names_arg: &'a [String],
    pub ip_sans_arg: &'a [String],
    pub ttl_arg: Option<&'a str>,
    /// `Some` for `cert sign` (a CSR is being signed), `None` for `cert
    /// create` (Vault generates the key and takes the CN unconditionally
    /// from the argument).
    pub csr: Option<&'a CsrInfo>,
    pub issuer_cn: &'a str,
}

type RdnGetter = fn(&RoleConfig) -> &Vec<String>;

const SUBJECT_RDNS: &[(&str, RdnGetter)] = &[
    ("C", |r| &r.country),
    ("ST", |r| &r.province),
    ("L", |r| &r.locality),
    ("O", |r| &r.organization),
    ("OU", |r| &r.ou),
    ("STREET", |r| &r.street_address),
    ("POSTAL", |r| &r.postal_code),
];

pub fn build_plan(input: &PlanInput) -> Vec<IdentityField> {
    let cn = effective_cn(input);

    let mut fields = vec![
        subject_field(input, &cn),
        eku_field(input.role),
        san_field(input, &cn),
        validity_field(input),
    ];
    if let Some(key) = key_field(input) {
        fields.push(key);
    }
    fields.push(IdentityField::plain("issuer", input.issuer_cn.to_string()));
    fields
}

/// The CN Vault will actually use, and where it came from. Only `cert sign`
/// with `use_csr_common_name=true` can make the `--cn` argument inert; every
/// other combination uses the argument.
struct EffectiveCn {
    value: String,
    note: String,
}

fn effective_cn(input: &PlanInput) -> EffectiveCn {
    match input.csr {
        Some(csr) if input.role.use_csr_common_name => EffectiveCn {
            value: csr
                .subject_cn
                .clone()
                .unwrap_or_else(|| "(CSR has no CN)".to_string()),
            note: match input.cn_arg {
                Some(arg) => {
                    format!("from CSR (role use_csr_common_name=true; argument \"{arg}\" unused)")
                }
                None => "from CSR (role use_csr_common_name=true)".to_string(),
            },
        },
        // The argument supplies the value here, not just the annotation, so
        // without one there is nothing to report: naming a CN would invent it.
        Some(_) => match input.cn_arg {
            Some(arg) => EffectiveCn {
                value: arg.to_string(),
                note: "from argument (role use_csr_common_name=false)".to_string(),
            },
            None => EffectiveCn {
                value: "(not determined until sign time)".to_string(),
                note: "role use_csr_common_name=false, so the CN comes from whatever \
                       cert sign is given"
                    .to_string(),
            },
        },
        // Vault takes the CN from the argument unconditionally here, so with no
        // argument there is no value yet — reading one off an absent field
        // would render a certificate with an empty subject as the plan.
        None => match input.cn_arg {
            Some(arg) => EffectiveCn {
                value: arg.to_string(),
                note: "from argument".to_string(),
            },
            None => EffectiveCn {
                value: "(supplied at issuance)".to_string(),
                note: "from the argument given to cert create".to_string(),
            },
        },
    }
}

fn subject_field(input: &PlanInput, cn: &EffectiveCn) -> IdentityField {
    let mut parts = Vec::new();
    let mut present = Vec::new();
    for (abbrev, getter) in SUBJECT_RDNS {
        let values: Vec<&String> = getter(input.role)
            .iter()
            .filter(|v| !v.is_empty())
            .collect();
        if !values.is_empty() {
            present.push(*abbrev);
        }
        for value in values {
            parts.push(format!("{abbrev}={value}"));
        }
    }
    parts.push(format!("CN={}", cn.value));

    let mut field = IdentityField::plain("subject", parts.join(", "));
    field.details.push(("CN".to_string(), cn.note.clone()));
    if !present.is_empty() {
        field
            .details
            .push((present.join("/"), "from role".to_string()));
    }
    field
}

fn eku_field(role: &RoleConfig) -> IdentityField {
    let mut entries = Vec::new();
    if role.server_flag {
        entries.push(("ServerAuth".to_string(), "role server_flag".to_string()));
    }
    if role.client_flag {
        entries.push(("ClientAuth".to_string(), "role client_flag".to_string()));
    }
    for usage in &role.ext_key_usage {
        if !entries.iter().any(|(v, _)| v == usage) {
            entries.push((usage.clone(), "role ext_key_usage".to_string()));
        }
    }
    IdentityField::from_sourced_values(
        "eku",
        entries,
        Some("role sets no client_flag, server_flag or ext_key_usage"),
    )
}

/// Three independent sources, governed by different role flags: the CSR's own
/// SAN extension (`use_csr_sans`), the common name folded in as a DNS SAN
/// (`exclude_cn_from_sans`), and the `--alt-names`/`--ip-sans` request
/// parameters, which Vault honors regardless of either flag.
///
/// The folded-in CN is the one entry not derived from configuration read here.
/// Vault does not report `exclude_cn_from_sans` on a role read — it is accepted
/// on write and never echoed — so whether the CN becomes a SAN cannot be known,
/// only predicted from the documented default. The annotation says so; every
/// other one names a field that was actually read.
fn san_field(input: &PlanInput, cn: &EffectiveCn) -> IdentityField {
    let mut entries = Vec::new();
    let csr_sans = input.csr.map(|csr| csr.sans.as_slice()).unwrap_or(&[]);

    if input.role.use_csr_sans {
        for san in csr_sans {
            entries.push((san.clone(), "from CSR (role use_csr_sans=true)".to_string()));
        }
    }
    entries.push((
        format!("DNS:{}", cn.value),
        "expected from Vault; suppressed if the role sets exclude_cn_from_sans, which it does not report".to_string(),
    ));
    for name in input.alt_names_arg {
        entries.push((format!("DNS:{name}"), "argument --alt-names".to_string()));
    }
    for ip in input.ip_sans_arg {
        entries.push((format!("IP:{ip}"), "argument --ip-sans".to_string()));
    }

    let mut field = IdentityField::from_sourced_values("san", entries, Some("no SANs will be set"));

    // Naming what will be dropped is the point of the rehearsal: the requester
    // cannot fix a discarded SAN after the fact, it needs a new CSR.
    if !input.role.use_csr_sans && !csr_sans.is_empty() {
        field.details.push((
            csr_sans.join(", "),
            "dropped: role use_csr_sans=false".to_string(),
        ));
    }

    field
}

fn validity_field(input: &PlanInput) -> IdentityField {
    let role = input.role;
    if let Some(ttl) = input.ttl_arg {
        let annotation = if role.max_ttl > 0 {
            format!(
                "argument; role max_ttl caps at {}",
                format_hours(role.max_ttl)
            )
        } else {
            "argument".to_string()
        };
        return IdentityField::annotated("validity", ttl.to_string(), annotation);
    }

    if role.ttl > 0 {
        let annotation = if role.max_ttl > 0 && role.max_ttl != role.ttl {
            format!("role default; max {}", format_hours(role.max_ttl))
        } else {
            "role default".to_string()
        };
        return IdentityField::annotated("validity", format_hours(role.ttl), annotation);
    }

    if role.max_ttl > 0 {
        return IdentityField::annotated(
            "validity",
            format_hours(role.max_ttl),
            "role max_ttl; role sets no explicit default",
        );
    }

    IdentityField::annotated(
        "validity",
        "unknown",
        "role pins neither ttl nor max_ttl; determined by the mount's default lease TTL",
    )
}

fn format_hours(seconds: u64) -> String {
    if seconds > 0 && seconds.is_multiple_of(3600) {
        format!("{}h", seconds / 3600)
    } else {
        format!("{seconds}s")
    }
}

fn key_field(input: &PlanInput) -> Option<IdentityField> {
    if let Some(csr) = input.csr {
        return Some(IdentityField::annotated(
            "key",
            csr.key_description.clone(),
            "from CSR",
        ));
    }

    if input.role.key_type.is_empty() {
        return None;
    }

    let value = if input.role.key_bits > 0 {
        format!(
            "{} {}",
            input.role.key_type.to_uppercase(),
            input.role.key_bits
        )
    } else {
        input.role.key_type.to_uppercase()
    };

    let annotation = if input.crypto_arg.is_some() {
        "role key_type/key_bits (--crypto argument does not influence the issued key)".to_string()
    } else {
        "role key_type/key_bits".to_string()
    };

    Some(IdentityField::annotated("key", value, annotation))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The motivating case: `use_csr_common_name=true` makes `--cn` inert,
    /// `use_csr_sans=false` drops the CSR's own SANs, and OU/O/C come from
    /// the role regardless.
    fn csr_signing_role() -> RoleConfig {
        RoleConfig {
            use_csr_common_name: true,
            use_csr_sans: false,
            ext_key_usage: vec![],
            client_flag: true,
            server_flag: false,
            ttl: 0,
            max_ttl: 157_680_000, // 43800h
            key_type: String::new(),
            key_bits: 0,
            ou: vec!["User TLS Authentication".to_string()],
            organization: vec!["Example Org".to_string()],
            country: vec!["CA".to_string()],
            ..Default::default()
        }
    }

    fn csr_with_cn(cn: &str) -> CsrInfo {
        CsrInfo {
            subject: format!("CN={cn}"),
            subject_cn: Some(cn.to_string()),
            sans: vec![format!("DNS:{cn}.example.test")],
            key_description: "EC prime256v1".to_string(),
            requested_extensions: vec!["subjectAltName".to_string()],
        }
    }

    fn field<'a>(fields: &'a [IdentityField], label: &str) -> &'a IdentityField {
        fields
            .iter()
            .find(|f| f.label == label)
            .unwrap_or_else(|| panic!("no {label} field"))
    }

    /// `inspect-csr` has no CN argument, so the plan must not report one as
    /// unused — that names an argument the verb does not have.
    #[test]
    fn without_an_argument_the_plan_claims_none() {
        let role = csr_signing_role();
        let csr = csr_with_cn("partner-app");
        let input = PlanInput {
            role: &role,
            cn_arg: None,
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };

        let fields = build_plan(&input);
        let subject = field(&fields, "subject");
        assert!(subject.value.ends_with("CN=partner-app"));
        for (_, note) in &subject.details {
            assert!(!note.contains("argument"), "{note}");
        }
    }

    /// With `use_csr_common_name=false` the argument supplies the value, not
    /// just the annotation, so absent one there is no CN to report. Rendering
    /// an empty `CN=` annotated "from argument" would be a fabricated reading.
    #[test]
    fn without_an_argument_a_role_that_needs_one_reports_no_cn() {
        let role = RoleConfig {
            use_csr_common_name: false,
            ..csr_signing_role()
        };
        let csr = csr_with_cn("partner-app");
        let input = PlanInput {
            role: &role,
            cn_arg: None,
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };

        let fields = build_plan(&input);
        let subject = field(&fields, "subject");
        assert!(!subject.value.contains("CN=,"), "{}", subject.value);
        assert!(!subject.value.ends_with("CN="), "{}", subject.value);
        let cn_note = &subject
            .details
            .iter()
            .find(|(k, _)| k == "CN")
            .expect("CN detail")
            .1;
        assert!(!cn_note.contains("from argument"), "{cn_note}");
    }

    #[test]
    fn inert_cn_argument_is_named_as_such() {
        let role = csr_signing_role();
        let csr = csr_with_cn("partner-app");
        let input = PlanInput {
            role: &role,
            cn_arg: Some("wrong-cn"),
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };

        let fields = build_plan(&input);
        let subject = field(&fields, "subject");
        assert_eq!(
            subject.value,
            "C=CA, O=Example Org, OU=User TLS Authentication, CN=partner-app"
        );
        let cn_detail = subject
            .details
            .iter()
            .find(|(label, _)| label == "CN")
            .unwrap();
        assert!(cn_detail.1.contains("from CSR"));
        assert!(cn_detail.1.contains("argument \"wrong-cn\" unused"));
    }

    #[test]
    fn csr_sans_are_dropped_but_cn_is_still_folded_in() {
        let role = csr_signing_role();
        let csr = csr_with_cn("partner-app");
        let input = PlanInput {
            role: &role,
            cn_arg: Some("partner-app"),
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };

        let fields = build_plan(&input);
        let san = field(&fields, "san");
        assert_eq!(san.value, "DNS:partner-app");
        // What the requester loses is named, and named as a drop rather than
        // listed among the values that will be set.
        assert!(
            san.details
                .iter()
                .any(|(values, note)| values.contains("partner-app.example.test")
                    && note.contains("use_csr_sans=false")),
            "{:?}",
            san.details
        );
    }

    /// A CSR carrying no SANs has none to drop, so nothing may be reported as
    /// dropped.
    #[test]
    fn nothing_is_reported_dropped_when_the_csr_has_no_sans() {
        let role = csr_signing_role();
        let mut csr = csr_with_cn("partner-app");
        csr.sans.clear();
        let input = PlanInput {
            role: &role,
            cn_arg: Some("partner-app"),
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };

        let san = &build_plan(&input);
        let san = field(san, "san");
        assert_eq!(san.value, "DNS:partner-app");
        assert!(san.details.is_empty(), "{:?}", san.details);
    }

    #[test]
    fn client_flag_drives_eku_not_ext_key_usage() {
        let role = csr_signing_role();
        let fields = build_plan_for_role(&role);
        let eku = field(&fields, "eku");
        assert_eq!(eku.value, "ClientAuth");
        assert_eq!(eku.annotation.as_deref(), Some("role client_flag"));
    }

    #[test]
    fn validity_falls_back_to_max_ttl_when_role_has_no_default() {
        let role = csr_signing_role();
        let fields = build_plan_for_role(&role);
        let validity = field(&fields, "validity");
        assert_eq!(validity.value, "43800h");
        assert!(validity.annotation.as_ref().unwrap().contains("max_ttl"));
    }

    #[test]
    fn alt_names_argument_remains_active_even_when_csr_sans_are_dropped() {
        let role = csr_signing_role();
        let csr = csr_with_cn("partner-app");
        let alt_names = vec!["extra.example.test".to_string()];
        let input = PlanInput {
            role: &role,
            cn_arg: Some("partner-app"),
            crypto_arg: None,
            alt_names_arg: &alt_names,
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };

        let fields = build_plan(&input);
        let san = field(&fields, "san");
        assert!(san.value.contains("DNS:extra.example.test"));
        assert!(san.value.contains("DNS:partner-app"));
        // Two distinct sources: broken down, not collapsed into one annotation.
        assert!(san.annotation.is_none());
        // Both sources, plus the note for what the role discards.
        assert_eq!(san.details.len(), 3, "{:?}", san.details);
    }

    #[test]
    fn crypto_argument_is_flagged_as_inert_for_create() {
        let mut role = csr_signing_role();
        role.key_type = "ec".to_string();
        role.key_bits = 256;
        let input = PlanInput {
            role: &role,
            cn_arg: Some("host.example.test"),
            crypto_arg: Some("rsa"),
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: None,
            issuer_cn: "Example Issuing CA",
        };

        let fields = build_plan(&input);
        let key = field(&fields, "key");
        assert_eq!(key.value, "EC 256");
        assert!(key
            .annotation
            .as_ref()
            .unwrap()
            .contains("does not influence the issued key"));
    }

    fn build_plan_for_role(role: &RoleConfig) -> Vec<IdentityField> {
        let csr = csr_with_cn("partner-app");
        let input = PlanInput {
            role,
            cn_arg: Some("partner-app"),
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: Some(&csr),
            issuer_cn: "Example Issuing CA",
        };
        build_plan(&input)
    }

    /// `cert role-info` renders through this builder with no CSR and no
    /// invocation, so the CN has no source yet. Reading one off the absent
    /// argument put an empty subject in the plan, which reads as a certificate
    /// that would be issued with no name.
    #[test]
    fn with_no_csr_and_no_argument_the_cn_is_owed_to_the_issuance() {
        let role = RoleConfig {
            organization: vec!["Example Org".to_string()],
            ..RoleConfig::default()
        };
        let fields = build_plan(&PlanInput {
            role: &role,
            cn_arg: None,
            crypto_arg: None,
            alt_names_arg: &[],
            ip_sans_arg: &[],
            ttl_arg: None,
            csr: None,
            issuer_cn: "Example Issuing CA",
        });

        let subject = field(&fields, "subject");
        assert!(
            !subject.value.contains("CN=,") && !subject.value.ends_with("CN="),
            "an absent CN rendered as an empty one: {}",
            subject.value
        );
        assert!(
            subject.value.contains("supplied at issuance"),
            "{}",
            subject.value
        );
        // What the role does fix is still reported as the role's.
        assert!(subject.value.contains("O=Example Org"), "{}", subject.value);
    }
}
