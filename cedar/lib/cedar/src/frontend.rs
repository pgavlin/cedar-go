use crate::RawString;

use cedar_policy::frontend::is_authorized::json_is_authorized as cedar_json_is_authorized;
use std::ffi::CStr;

#[no_mangle]
pub extern "C" fn json_is_authorized(input: *const libc::c_char) -> RawString {
    let input_cstr = unsafe { CStr::from_ptr(input) };
    let input = input_cstr.to_str().unwrap();
    match serde_json::to_string(&cedar_json_is_authorized(input)) {
        Err(_) => RawString::empty(),
        Ok(s) => s.into(),
    }
}
