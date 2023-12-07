use crate::{Diagnostic, Diagnostics, LabeledSpan, PolicySet, Schema, Severity};
use c_macros::CBox;

CBox!(Validator = &cedar_policy::Validator);

#[no_mangle]
pub extern "C" fn new_validator(s: Schema) -> Validator {
    Box::new(cedar_policy::Validator::new(s.clone())).into()
}

#[no_mangle]
pub extern "C" fn validate(validator: Validator, policy_set: PolicySet) -> Diagnostics {
    let result = validator.validate(&policy_set, cedar_policy::ValidationMode::Permissive);
    if result.validation_passed() {
        Diagnostics::empty()
    } else {
        Vec::from_iter(result.validation_errors().map(|err| {
            let msg = err.error_kind().to_string();
            let loc = err.location();
            let (offset, len) = match loc.range_start() {
                None => (0, 0),
                Some(offset) => (offset, loc.range_end().unwrap() - offset),
            };
            Diagnostic::new(vec![LabeledSpan::new(msg.into(), offset, len)].into(), Severity::Error)
        })).into()
    }
}
