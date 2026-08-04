//! Shared rendering for an issuance's identity: what `--dry-run` predicts and
//! what a completed sign/create actually produced use the same field shape,
//! so the two are directly comparable (see docs/design-rationale.md, "The
//! issuing role, not the invocation, defines the issued identity").

const LABEL_WIDTH: usize = 10;
const VALUE_WIDTH: usize = 30;

/// One labeled fact about an issuance. `annotation` is a single inline note;
/// `details` breaks a field down by source when more than one applies (e.g. a
/// subject's CN and its OU/O/C come from different places).
pub struct IdentityField {
    pub label: &'static str,
    pub value: String,
    pub annotation: Option<String>,
    pub details: Vec<(String, String)>,
}

impl IdentityField {
    pub fn plain(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            annotation: None,
            details: Vec::new(),
        }
    }

    pub fn annotated(
        label: &'static str,
        value: impl Into<String>,
        annotation: impl Into<String>,
    ) -> Self {
        Self {
            label,
            value: value.into(),
            annotation: Some(annotation.into()),
            details: Vec::new(),
        }
    }

    /// Build a field from values that may come from more than one source: a
    /// single source becomes an inline annotation, several become a
    /// per-source breakdown so no source is misattributed to another.
    pub fn from_sourced_values(
        label: &'static str,
        entries: Vec<(String, String)>,
        empty_note: Option<&str>,
    ) -> Self {
        if entries.is_empty() {
            return Self {
                label,
                value: "none".to_string(),
                annotation: empty_note.map(str::to_string),
                details: Vec::new(),
            };
        }

        let mut sources = Vec::new();
        for (_, source) in &entries {
            if !sources.contains(source) {
                sources.push(source.clone());
            }
        }

        let value = entries
            .iter()
            .map(|(v, _)| v.as_str())
            .collect::<Vec<_>>()
            .join(", ");

        if sources.len() == 1 {
            return Self::annotated(label, value, sources.into_iter().next().unwrap());
        }

        let details = sources
            .into_iter()
            .map(|source| {
                let values = entries
                    .iter()
                    .filter(|(_, s)| *s == source)
                    .map(|(v, _)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                (values, source)
            })
            .collect();

        Self {
            label,
            value,
            annotation: None,
            details,
        }
    }
}

/// Print the fields to stderr: a rehearsal or report is status for a person,
/// never data (see docs/design-rationale.md, "Austerity applies to the data
/// stream only").
pub fn print_identity_fields(fields: &[IdentityField]) {
    for field in fields {
        match &field.annotation {
            Some(note) => eprintln!(
                "{:<LABEL_WIDTH$}{:<VALUE_WIDTH$}({note})",
                field.label, field.value
            ),
            None => eprintln!("{:<LABEL_WIDTH$}{}", field.label, field.value),
        }

        if !field.details.is_empty() {
            let sub_width = field
                .details
                .iter()
                .map(|(sub, _)| sub.chars().count())
                .max()
                .unwrap_or(0)
                + 2;
            for (sub_label, text) in &field.details {
                eprintln!("{:LABEL_WIDTH$}{:<sub_width$}{text}", "", sub_label);
            }
        }
    }
}
