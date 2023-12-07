#![feature(vec_into_raw_parts)]

use c_macros::CVec;

pub struct MyStruct {}

CVec!(MyStructs = [MyStruct]);

fn main() {
}
