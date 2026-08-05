use crate::utils::errors::{Result, VaultCliError};
use std::fmt::Write as _;

/// One thing that could not be read while assembling an answer.
pub struct Incomplete {
    /// What could not be read: a serial, a mount path.
    pub subject: String,
    /// `None` when the whole record was skipped. `Some` when the record is in
    /// the answer and only this field is missing from it.
    pub field: Option<&'static str>,
    pub error: VaultCliError,
}

impl Incomplete {
    pub fn record(subject: impl Into<String>, error: VaultCliError) -> Self {
        Self {
            subject: subject.into(),
            field: None,
            error,
        }
    }

    pub fn unread_field(
        subject: impl Into<String>,
        field: &'static str,
        error: VaultCliError,
    ) -> Self {
        Self {
            subject: subject.into(),
            field: Some(field),
            error,
        }
    }

    pub fn describe(&self) -> String {
        let cause = chain(&self.error);
        match self.field {
            Some(field) => format!("{}: {field} unreadable: {cause}", self.subject),
            None => format!("{}: skipped: {cause}", self.subject),
        }
    }
}

/// An error and every cause under it. The report is baked into a string here,
/// so a chain printed only where the process exits is not printed at all —
/// and the variants that carry a `#[from]` say nothing without their source.
fn chain(error: &VaultCliError) -> String {
    let mut rendered = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        // discard-ok: writing into a String is infallible
        let _ = write!(rendered, ": {cause}");
        source = cause.source();
    }
    rendered
}

/// An answer plus whatever stopped it from being complete.
///
/// Resolving it is a single call so that no caller can report the results
/// without also reporting what is missing from them.
pub struct Partial<T> {
    items: Vec<T>,
    failures: Vec<Incomplete>,
    remedy: Option<String>,
}

impl<T> Default for Partial<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Partial<T> {
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            failures: Vec::new(),
            remedy: None,
        }
    }

    pub fn push(&mut self, item: T) {
        self.items.push(item);
    }

    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.items.iter()
    }

    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    /// Whether anything failed for the given reason, so a producer can offer
    /// the remedy that fits rather than every remedy it knows.
    pub fn any_failure(&self, predicate: impl Fn(&VaultCliError) -> bool) -> bool {
        self.failures.iter().any(|f| predicate(&f.error))
    }

    /// What to do about the failures, from the producer that knows what they
    /// are. Refusing is the operator's whole route out, so the message has to
    /// carry every way back and not just the one that is easiest to name.
    pub fn set_remedy(&mut self, remedy: Option<String>) {
        self.remedy = remedy;
    }

    pub fn extend(&mut self, items: impl IntoIterator<Item = T>) {
        self.items.extend(items);
    }

    pub fn fail(&mut self, failure: Incomplete) {
        self.failures.push(failure);
    }

    /// Folds another partial answer into this one, keeping both sets of
    /// failures. Used when one command assembles several sources.
    pub fn absorb(&mut self, other: Partial<T>) {
        self.items.extend(other.items);
        self.failures.extend(other.failures);
    }

    pub fn items_mut(&mut self) -> &mut Vec<T> {
        &mut self.items
    }

    /// Both halves, for a caller whose question is not "list everything" and
    /// so cannot use `resolve`'s all-or-nothing policy — a lookup that found
    /// what it wanted does not care what else was unreadable, and one that did
    /// not has to say so rather than report a clean absence.
    pub fn into_parts(self) -> (Vec<T>, Vec<Incomplete>) {
        (self.items, self.failures)
    }

    /// The answer, if the caller is entitled to it.
    ///
    /// Complete, or `allow_partial`: the items, with every skipped subject and
    /// unread field named on stderr. Otherwise an error naming them all and the
    /// flag, because an exit code that must also mean "answered, partially"
    /// cannot be acted on. See docs/design-rationale.md, "An incomplete answer
    /// is refused, not annotated".
    pub fn resolve(self, allow_partial: bool) -> Result<Vec<T>> {
        if self.failures.is_empty() {
            return Ok(self.items);
        }

        // A skipped record is absent from `items`; a record with an unread
        // field is present in it. Only the first adds to the total.
        let skipped = self.failures.iter().filter(|f| f.field.is_none()).count();
        let total = self.items.len() + skipped;

        if allow_partial {
            eprintln!("{} of {total} records incomplete:", self.failures.len());
            for failure in &self.failures {
                eprintln!("  {}", failure.describe());
            }
            if let Some(ref remedy) = self.remedy {
                eprintln!("\n{remedy}");
            }
            return Ok(self.items);
        }

        let mut report = format!(
            "{} of {total} records could not be fully read, so this answer would be incomplete:\n",
            self.failures.len()
        );
        for failure in &self.failures {
            // discard-ok: writing into a String is infallible
            let _ = writeln!(report, "  {}", failure.describe());
        }
        if let Some(ref remedy) = self.remedy {
            // discard-ok: writing into a String is infallible
            let _ = write!(report, "\n{remedy}\n");
        }
        report.push_str("\nPass --allow-partial to work with what could be read.");

        Err(VaultCliError::IncompleteRead(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err() -> VaultCliError {
        VaultCliError::Storage("connection refused".to_string())
    }

    fn partial() -> Partial<u8> {
        let mut p = Partial::new();
        p.push(1);
        p.fail(Incomplete::record("0a:0b", err()));
        p
    }

    #[test]
    fn a_complete_answer_resolves_either_way() {
        let mut p = Partial::new();
        p.push(1u8);
        assert_eq!(p.resolve(false).unwrap(), [1]);
    }

    /// The whole point: without the flag there is no answer, only an error.
    #[test]
    fn an_incomplete_answer_is_refused_by_default() {
        let err = partial().resolve(false).unwrap_err().to_string();
        assert!(err.contains("0a:0b"), "{err}");
        assert!(err.contains("connection refused"), "{err}");
        assert!(err.contains("--allow-partial"), "{err}");
    }

    #[test]
    fn the_flag_yields_what_was_read() {
        assert_eq!(partial().resolve(true).unwrap(), [1]);
    }

    fn unread_field() -> Partial<u8> {
        let mut p = Partial::new();
        p.push(1);
        p.fail(Incomplete::unread_field("pki/", "crypto_type", err()));
        p
    }

    /// A field failure keeps its record in the answer — the mount name read
    /// fine, only the secondary query did not — while a record failure does not.
    #[test]
    fn a_field_failure_keeps_its_record() {
        assert_eq!(unread_field().resolve(true).unwrap(), [1]);
    }

    /// It is still incomplete, so it is still refused by default.
    #[test]
    fn a_field_failure_is_refused_by_default_and_names_the_field() {
        let err = unread_field().resolve(false).unwrap_err().to_string();
        assert!(err.contains("crypto_type"), "{err}");
        assert!(err.contains("pki/"), "{err}");
    }
}
