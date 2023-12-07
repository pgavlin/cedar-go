use crate::RawString;
use c_macros::CVec;

CVec!(Labels = [LabeledSpan]);

impl From<Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>>> for Labels {
    fn from(labels: Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>>) -> Self {
        match labels {
            None => Labels::empty(),
            Some(labels) => Vec::from_iter(labels.map(|l| l.into())).into(),
        }
    }
}

#[repr(C)]
pub struct LabeledSpan {
    text: RawString,
    offset: usize,
    len: usize,
}

impl LabeledSpan {
    pub fn new(text: RawString, offset: usize, len: usize) -> LabeledSpan {
        LabeledSpan { text: text, offset: offset, len: len }
    }
}

impl From<miette::LabeledSpan> for LabeledSpan {
    fn from(span: miette::LabeledSpan) -> Self {
        let text = match span.label() {
            None => RawString::empty(),
            Some(s) => String::from(s).into(),
        };
        LabeledSpan { text: text, offset: span.offset(), len: span.len() }
    }
}

#[repr(u8)]
pub enum Severity {
    None,
    Advice,
    Warning,
    Error,
}

impl From<Option<miette::Severity>> for Severity {
    fn from(s: Option<miette::Severity>) -> Self {
        match s {
            None => Severity::None,
            Some(s) => match s {
                miette::Severity::Advice => Severity::Advice,
                miette::Severity::Warning => Severity::Warning,
                miette::Severity::Error => Severity::Error,
            },
        }
    }
}

CVec!(Diagnostics = [Diagnostic]);

impl From<Vec<cedar_policy_core::parser::err::ParseError>> for Diagnostics {
    fn from(parse_errors: Vec<cedar_policy_core::parser::err::ParseError>) -> Diagnostics {
        Vec::from_iter(parse_errors.into_iter().map(|err| match err {
            cedar_policy_core::parser::err::ParseError::ToCST(err) => err.into(),
            cedar_policy_core::parser::err::ParseError::ToAST(s) => Diagnostic::from_str(s),
            cedar_policy_core::parser::err::ParseError::RestrictedExpressionError(err) => Diagnostic::from_str(err.to_string()),
        })).into()
    }
}

#[repr(C)]
pub struct Diagnostic {
    code: RawString,
    labels: Labels,
    severity: Severity,
    help: RawString,
    url: RawString,
}

impl Diagnostic {
    pub fn new(labels: Labels, severity: Severity) -> Diagnostic {
        Diagnostic {
            code: RawString::empty(),
            labels: labels,
            severity: severity,
            help: RawString::empty(),
            url: RawString::empty(),
        }
    }

    pub fn from_str(s: String) -> Diagnostic {
        Diagnostic::new(vec![LabeledSpan::new(s.into(), 0, 0)].into(), Severity::Error)
    }
}

impl<T: miette::Diagnostic> From<T> for Diagnostic {
    fn from(diag: T) -> Self {
        Diagnostic {
            code: diag.code().into(),
            labels: diag.labels().into(),
            severity: diag.severity().into(),
            help: diag.help().into(),
            url: diag.help().into(),
        }
    }
}
