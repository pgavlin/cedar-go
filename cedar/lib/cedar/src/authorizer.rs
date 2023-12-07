use crate::{Diagnostic, Diagnostics, PolicySet, RawStrings, Schema};
use c_macros::CBox;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;

CBox!(Authorizer = &cedar_policy::Authorizer);

#[no_mangle]
pub extern "C" fn new_authorizer() -> Authorizer {
    Box::new(cedar_policy::Authorizer::new()).into()
}

#[repr(C)]
pub struct Decision {
    allow: bool,
    reasons: RawStrings,
}

impl Decision {
    pub fn new(allow: bool, reasons: RawStrings) -> Decision {
        Decision { allow: allow, reasons: reasons }
    }
}

#[no_mangle]
pub extern "C" fn is_authorized(a: Authorizer, request_json: *const libc::c_char, p: PolicySet, s: Schema, decision: &mut Decision) -> Diagnostics {
    let request_cstr = unsafe { CStr::from_ptr(request_json) };
    let request_str = request_cstr.to_str().unwrap();

    let call = match serde_json::from_str::<AuthorizationCall>(request_str) {
        Ok(call) => call,
        Err(err) => return vec![Diagnostic::from_str(err.to_string())].into(),
    };

    let mut diags = Vec::new();

    let principal = match call.principal {
        None => None,
        Some(v) => match cedar_policy::EntityUid::from_json(v) {
            Ok(e) => Some(e),
            Err(err) => {
                diags.push(Diagnostic::from_str(format!("Failed to parse principal: {}", err)));
                None
            },
        },
    };
    let action = match call.action {
        None => None,
        Some(v) => match cedar_policy::EntityUid::from_json(v) {
            Ok(a) => Some(a),
            Err(err) => {
                diags.push(Diagnostic::from_str(format!("Failed to parse action: {}", err)));
                None
            },
        },
    };
    let resource = match call.resource {
        None => None,
        Some(v) => match cedar_policy::EntityUid::from_json(v) {
            Ok(e) => Some(e),
            Err(err) => {
                diags.push(Diagnostic::from_str(format!("Failed to parse resource: {}", err)));
                None
            },
        },
    };
    let context = match call.context {
        None => cedar_policy::Context::empty(),
        Some(v) => match cedar_policy::Context::from_json_value(v, s.as_ref().map(|s| (s, action.as_ref().unwrap()))) {
            Ok(c) => c,
            Err(err) => {
                diags.push(Diagnostic::from_str(format!("Failed to parse context: {}", err)));
                cedar_policy::Context::empty()
            },
        },
    };
    let entities = match call.entities {
        None => cedar_policy::Entities::empty(),
        Some(v) => match cedar_policy::Entities::from_json_value(v, s.as_ref()) {
            Ok(e) => e,
            Err(err) => {
                diags.push(Diagnostic::from_str(format!("Failed to parse context: {}", err)));
                cedar_policy::Entities::empty()
            },
        },
    };

    if diags.len() != 0 {
        return diags.into();
    }

    let req = cedar_policy::Request::new(principal, action, resource, context);
    let resp = a.is_authorized(&req, &p, &entities);
    let diags = resp.diagnostics();

    let errors = Vec::from_iter(diags.errors().map(|e| Diagnostic::from_str(e.to_string())));
    if errors.len() != 0 {
        return errors.into();
    }

    let allow = resp.decision() == cedar_policy::Decision::Allow;
    *decision = Decision::new(allow, Vec::from_iter(diags.reason().map(|id| id.to_string().into())).into());
    Diagnostics::empty()
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationCall {
    pub principal: Option<serde_json::Value>,
    pub action: Option<serde_json::Value>,
    pub resource: Option<serde_json::Value>,
    pub context: Option<serde_json::Value>,
    pub entities: Option<serde_json::Value>,
}
