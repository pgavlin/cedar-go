use crate::{Diagnostic, Diagnostics};
use c_macros::CBox;
use std::ffi::CStr;
use std::str::FromStr;

CBox!(Schema = &cedar_policy::Schema);

#[no_mangle]
pub extern "C" fn parse_schema(input: *const libc::c_char, s: &mut Schema) -> Diagnostics {
    let input_cstr = unsafe { CStr::from_ptr(input) };
    match cedar_policy::Schema::from_str(input_cstr.to_str().unwrap()) {
        Ok(schema) => {
            *s = Box::new(schema).into();
            Diagnostics::empty()
        },
        Err(err) => match err {
            cedar_policy::SchemaError::EntityTypeParse(parse_errors) => parse_errors.0.into(), 
            cedar_policy::SchemaError::NamespaceParse(parse_errors) => parse_errors.0.into(),
            cedar_policy::SchemaError::CommonTypeParseError(parse_errors) => parse_errors.0.into(),
            cedar_policy::SchemaError::ExtensionTypeParse(parse_errors) => parse_errors.0.into(),
            err => vec![Diagnostic::from_str(err.to_string())].into()
        },
    }
}
