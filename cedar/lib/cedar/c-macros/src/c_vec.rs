use convert_case::Casing;
use quote::quote_spanned;
use syn::Token;
use syn::spanned::Spanned;

pub struct Decl {
    pub ident: syn::Ident,
    pub eq_token: Token![=],
    pub ty: syn::TypeSlice,
}

impl syn::parse::Parse for Decl {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        Ok(Decl {
            ident: input.parse()?,
            eq_token: input.parse()?,
            ty: input.parse()?,
        })
    }
}

impl quote::ToTokens for Decl {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.ident.to_tokens(tokens);
        self.eq_token.to_tokens(tokens);
        self.ty.to_tokens(tokens);
    }
}

pub fn c_vec(type_: Decl) -> proc_macro2::TokenStream {
    let span = type_.span();
    let elem = type_.ty.elem;
    let name = &type_.ident;
    let free_name = syn::Ident::new(&format!("free_{}", name.to_string().to_case(convert_case::Case::Snake)), span);

    quote_spanned! {span=>
        #[repr(C)]
        pub struct #name {
            ptr: *mut #elem,
            len: usize,
            cap: usize,
        }

        impl #name {
            pub fn empty() -> #name {
                #name { ptr: std::ptr::null_mut(), len: 0, cap: 0 }
            }

            pub fn as_slice(&self) -> &[#elem] {
                unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
            }
        }

        impl std::ops::Deref for #name {
            type Target = [#elem];

            fn deref(&self) -> &Self::Target {
                self.as_slice()
            }
        }

        impl From<Vec<#elem>> for #name {
            fn from(v: Vec<#elem>) -> Self {
                let (ptr, len, cap) = v.into_raw_parts();
                #name { ptr: ptr, len: len, cap: cap }
            }
        }

        #[no_mangle]
        pub extern "C" fn #free_name(b: #name) {
            unsafe { Vec::<#elem>::from_raw_parts(b.ptr, b.len, b.cap) };
        }
    }
}
