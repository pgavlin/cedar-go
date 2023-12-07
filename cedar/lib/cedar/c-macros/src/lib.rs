extern crate proc_macro;

use syn;

mod c_box;
mod c_vec;

#[proc_macro]
#[allow(non_snake_case)]
pub fn CBox(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    c_box::c_box(syn::parse_macro_input!(input as c_box::Decl)).into()
}

#[proc_macro]
#[allow(non_snake_case)]
pub fn CVec(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    c_vec::c_vec(syn::parse_macro_input!(input as c_vec::Decl)).into()
}

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("test/ui/c_box.rs");
    t.pass("test/ui/c_vec.rs");
}
