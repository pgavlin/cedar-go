use c_macros::CVec;

#[repr(C)]
pub struct RawString {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl RawString {
    pub fn empty() -> Self {
        String::new().into()
    }
}

impl From<String> for RawString {
    fn from(s: String) -> Self {
        let (ptr, len, cap) = s.into_raw_parts();
        RawString {ptr: ptr, len: len, cap: cap}
    }
}

impl std::ops::Deref for RawString {
    type Target = str;

    fn deref(&self) -> &str {
        unsafe {
            let bytes = std::slice::from_raw_parts(self.ptr, self.len);
            std::str::from_utf8_unchecked(bytes)
        }
    }
}

impl From<Option<String>> for RawString {
    fn from(s: Option<String>) -> Self {
        match s {
            None => RawString::empty(),
            Some(s) => s.into(),
        }
    }
}

impl<'a> From<Option<Box<dyn std::fmt::Display + 'a>>> for RawString {
    fn from(s: Option<Box<dyn std::fmt::Display + 'a>>) -> Self {
        match s {
            None => RawString::empty(),
            Some(disp) => format!("{}", &disp).into(),
        }
    }
}

trait ToRawString {
    fn to_raw_string(&self) -> RawString;
}

impl<T: std::fmt::Display + ?Sized> ToRawString for T {
    default fn to_raw_string(&self) -> RawString {
        self.to_string().into()
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: RawString) {
    unsafe { String::from_raw_parts(s.ptr, s.len, s.cap) };
}

CVec!(RawStrings = [RawString]);
