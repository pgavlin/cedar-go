#![feature(vec_into_raw_parts)]

use c_macros::CBox;

pub struct MyStruct {}

CBox!(CMyStruct = &MyStruct);

fn main() {
}
