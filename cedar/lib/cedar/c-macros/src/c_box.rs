use convert_case::Casing;
use quote::quote_spanned;
use syn::Token;
use syn::spanned::Spanned;

pub struct Decl {
    pub ident: syn::Ident,
    pub eq_token: Token![=],
    pub and_token: syn::token::And,
    pub ty: Box<syn::Type>,
}

impl syn::parse::Parse for Decl {
    fn parse(input: syn::parse::ParseStream) -> syn::parse::Result<Self> {
        Ok(Decl {
            ident: input.parse()?,
            eq_token: input.parse()?,
            and_token: input.parse()?,
            ty: Box::new(input.call(syn::Type::without_plus)?),
        })
    }
}

impl quote::ToTokens for Decl {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.ident.to_tokens(tokens);
        self.eq_token.to_tokens(tokens);
        self.and_token.to_tokens(tokens);
        self.ty.to_tokens(tokens);
    }
}

pub fn c_box(decl: Decl) -> proc_macro2::TokenStream {
    let span = decl.span();
    let name = &decl.ident;
    let free_name = syn::Ident::new(&format!("free_{}", name.to_string().to_case(convert_case::Case::Snake)), span);
    let elem = &decl.ty;

    quote_spanned! {span=>
        #[repr(C)]
        pub struct #name {
            ptr: *mut #elem
        }

        impl #name {
            pub fn as_ref(&self) -> Option<&#elem> {
                unsafe { self.ptr.as_ref() }
            }
        }

        impl std::ops::Deref for #name {
            type Target = #elem;

            fn deref(&self) -> &Self::Target {
                unsafe { &*self.ptr }
            }
        }

        impl From<Box<#elem>> for #name {
            fn from(b: Box<#elem>) -> Self {
                #name { ptr: Box::into_raw(b) }
            }
        }

        #[no_mangle]
        pub extern "C" fn #free_name(b: #name) {
            unsafe { drop(Box::from_raw(b.ptr)) };
        }
    }
}
