use crate::Diagnostics;
use c_macros::CBox;
use std::ffi::CStr;
use std::str::FromStr;

CBox!(PolicySet = &cedar_policy::PolicySet);

#[no_mangle]
pub extern "C" fn parse_policies(input: *const libc::c_char, policy_set: &mut PolicySet) -> Diagnostics {
    let input_cstr = unsafe { CStr::from_ptr(input) };
    match cedar_policy::PolicySet::from_str(input_cstr.to_str().unwrap()) {
        Ok(set) => {
            *policy_set = Box::new(set).into();
            Diagnostics::empty()
        },
        Err(parse_errors) => parse_errors.0.into(),
    }
}
