use super::AsBytes;

use winapi::shared::bcrypt::*;

/// C-compatible dynamic inline structure.
///
/// Can be used to house data with a header structure of a statically known size
/// but with trailing data of size dependent on the header field values.
///
/// # Layout
/// The structure is marked as #[repr(packed)] to be layout-compatible with
/// regular byte slice ([u8]) since it's mostly constructed from Box<[u8]> via
/// C FFI.
///
/// It's worth noting that heap allocation will often align to pointer size, so
/// no unaligned load should happen once the value is constructed from
/// heap-allocated bytes.
#[repr(C, packed)]
pub struct DynStruct<T: DynStructParts>(T::Header, [u8]);

/// Couples both `Header` and `Tail` types used in a `DynStruct`.
pub trait DynStructParts {
    type Header;
}

impl<'a, T: DynStructParts> DynStruct<T> {
    pub fn header(&self) -> &T::Header {
        // SAFETY: The only way to construct this value is via
        // `Self::from_boxed`, which requires that the reference is at least
        // pointer-aligned, and since `DynStruct` is `#[repr(C)]`, so is its
        // first field.
        unsafe { &self.0 }
    }

    #[doc(hidden)]
    pub fn tail(&self) -> &[u8] {
        &self.1
    }

    pub fn as_bytes(&self) -> &[u8] {
        AsBytes::as_bytes(self)
    }
}

impl<T: DynStructParts> AsBytes for DynStruct<T> {
    // TODO: Add T::Header: AsBytes
    fn as_bytes(&self) -> &[u8] {
        let len = std::mem::size_of_val(self);
        // SAFETY: DynStruct is C-compatible - header is assumed to be a
        // POD that's #[repr(C)] and the tail are regular bytes.
        // Therefore, it's safe to view the entire allocation as bytes
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, len) }
    }
}

impl<'a, T: DynStructParts> DynStruct<T> {
    pub fn into_bytes(self: Box<Self>) -> Box<[u8]> {
        let len = std::mem::size_of_val(self.as_ref());
        let ptr = Box::into_raw(self);
        // SAFETY: DynStruct is C-compatible - header is `#[repr(C)]` and the
        // tail are regular bytes. Moreover, it's `#[repr(packed)]` so it's
        // layout-compatible with Box<[u8]>.
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr as *mut u8, len);
            Box::from_raw(slice as *mut [u8])
        }
    }
}

impl<'a, T: DynStructParts> DynStruct<T> {
    pub fn from_boxed(boxed: Box<[u8]>) -> Box<Self>
    where
        T::Header: 'static,
    {
        dbg!(&boxed);
        let hehe: &BCRYPT_ECCKEY_BLOB = unsafe { std::mem::transmute(boxed.as_ref().as_ptr()) };
        dbg!(hehe.dwMagic);
        dbg!(hehe.cbKey);
        eprintln!("Boxed len is {}", boxed.len());
        eprintln!(
            "Align of header {:?} is: {}",
            std::any::TypeId::of::<T::Header>(),
            std::mem::align_of::<T::Header>()
        );

        // TODO:
        dbg!(std::mem::size_of_val(boxed.as_ref()));
        // assert_eq!(boxed.len() % std::mem::align_of::<$header>(), 0);

        // SAFETY: Require that the pointer is at least as aligned as the header
        // to safely reference its first field (header) with aligned load.
        // NOTE: That's despite `DynStruct` being `#[repr(packed)]`, to
        // guarantee layout-compatibility with [u8].
        assert_eq!(
            boxed.as_ptr() as usize % std::mem::align_of::<T::Header>(),
            0
        );
        assert!(boxed.len() >= std::mem::size_of::<T::Header>());

        let tail_len = boxed.len() - std::mem::size_of::<T::Header>();
        // Construct a custom slice-based DST
        let ptr = Box::leak(boxed);
        unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr.as_mut_ptr(), tail_len);

            Box::from_raw(slice as *mut [u8] as *mut [()] as *mut Self)
        }
    }
}

/// Defines a trait for accessing dynamic fields (byte slices) for structs that
/// have a header of a known size which also defines the rest of the struct
/// layout.
/// Assumes a contiguous byte buffer.
#[macro_export]
macro_rules! dyn_struct {
    (
        $(#[$wrapper_meta:meta])*
        enum $wrapper_ident: ident {},
        header: $header: ty,
        $(#[$outer:meta])*
        view: struct ref $tail_ident: ident {
            $(
                $(#[$meta:meta])*
                $field: ident [$($len: tt)*],
            )*
        }
    ) => {
        $(#[$wrapper_meta])*
        pub enum $wrapper_ident {}

        $(#[$outer])*
        pub struct $tail_ident<'a> {
            $(
                $(#[$meta])*
                pub $field: &'a [u8],
            )*
        }

        impl<'a> $crate::helpers::dyn_struct::DynStructParts for $wrapper_ident {
            type Header = $header;
        }

        impl $crate::helpers::dyn_struct::DynStruct<$wrapper_ident> {
            #[allow(unused_assignments)]
            pub fn clone_from_parts(header: &$header, tail: &$tail_ident) -> Box<Self> {
                let header_len = std::mem::size_of_val(header);
                let tail_len: usize = 0 $( + dyn_struct! { size: header, $($len)*} )*;

                // To err on the safe side, despite `DynStruct` being
                // `#[repr(packed)]`, we pad the tail allocation as if it was
                // a regular struct.
                // We assume that header is #[repr(C)] and that its alignment is
                // the largest required alignment for its field.
                let align = std::mem::align_of_val(header);
                let tail_padding = (align - (tail_len % align)) % align;

                let mut boxed = vec![0u8; header_len + tail_len + tail_padding].into_boxed_slice();

                let header_as_bytes = unsafe {
                    std::slice::from_raw_parts(
                        header as *const _ as *const u8,
                        header_len
                    )
                };
                &mut boxed[..header_len].copy_from_slice(header_as_bytes);
                let mut offset = header_len;
                $(
                    let field_len = dyn_struct! { size: header, $($len)*};
                    dbg!(tail.$field, field_len);
                    &mut boxed[offset..offset + field_len].copy_from_slice(tail.$field);
                    offset += field_len;
                )*

                Self::from_boxed(boxed)
            }
        }

        impl $crate::helpers::dyn_struct::DynStruct<$wrapper_ident> {
            dyn_struct! { fields: ;
                $(
                    $(#[$meta])*
                    $field [$($len)*],
                )*
            }
        }
    };

    // Expand fields. Recursively expand each field, pushing the processed field
    //  identifier to a queue which is later used to calculate field offset for
    // subsequent fields
    (
        fields: $($prev: ident,)* ;
        $(#[$curr_meta:meta])*
        $curr: ident [$($curr_len: tt)*],
        $(
            $(#[$field_meta:meta])*
            $field: ident [$($field_len: tt)*],
        )*
    ) => {
        $(#[$curr_meta])*
        #[inline(always)]
        pub fn $curr(&self) -> &[u8] {
            let size: usize = dyn_struct! { size: self.header(), $($curr_len)* };
            let offset = 0 $(+ self.$prev().len())*;

            &self.tail()[offset..offset + size]
        }

        // Once expanded, push the processed ident and recursively expand other
        // fields
        dyn_struct! {
            fields: $($prev,)* $curr, ;
            $(
                $(#[$field_meta])*
                $field [$($field_len)*],
            )*
        }
    };
    // Stop after expanding every field
    (fields: $($prev: ident,)* ; ) => {};


    // Accept either header member values or arbitrary expressions (e.g. numeric
    // constants)
    (size: $this: expr, $ident: ident) => { $this.$ident as usize };
    (size: $this: expr, $expr: expr) => { $expr };

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        #[repr(C)]
        pub struct Header {
            count: u16,
        }
        dyn_struct! {
            enum MyDynStruct {},
            header: Header,
            view: struct ref TailView {
                some_member[count], // Refers to run-time value of `count` field
            }
        }

        let inline = DynStruct::<MyDynStruct>::clone_from_parts(
            &Header { count: 4 },
            &TailView {
                some_member: &[1u8, 2, 3, 4],
            },
        );
        assert_eq!(6, std::mem::size_of_val(&*inline));

        let inline = DynStruct::<MyDynStruct>::clone_from_parts(
            &Header { count: 5 },
            &TailView {
                some_member: &[1u8, 2, 3, 4, 5],
            },
        );
        // Account for trailing padding
        assert_eq!(8, std::mem::size_of_val(&*inline));
    }
}
