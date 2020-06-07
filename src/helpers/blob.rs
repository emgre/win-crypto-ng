use crate::helpers::bytes::{AsBytes, FromBytes};

/// C-compatible dynamic inline structure.
///
/// Can be used to house data with a header structure of a statically known size
/// but with trailing data of size dependent on the header field values.
///
/// # Layout
/// The structure is marked as `#[repr(packed)]` to be layout-compatible with
/// regular byte slice (`[u8]`) since it's mostly constructed from `Box<[u8]>`
/// via C FFI.
///
/// It's worth noting that heap allocation will often align to pointer size, so
/// no unaligned load should happen once the value is constructed from
/// heap-allocated bytes.
#[repr(C, packed)]
pub struct Blob<T: BlobLayout>(T::Header, [u8]);

/// Marker trait for dynamic struct layouts prefixed with `Self::Header` type
/// of a statically-known size. Used in tandem with `Blob`.
pub trait BlobLayout {
    type Header: AsBytes + FromBytes;
}

impl<'a, T: BlobLayout> Blob<T> {
    pub fn header(&self) -> &T::Header {
        // SAFETY: The only way to construct `Blob` is via
        // `Self::from_boxed`, which requires that the source reference is
        // aligned at least as `T::Header` and since `Blob` is
        // `#[repr(C)]` (and so is `T::Header`, because it  implements `AsBytes`
        // which requires which requires being `#[repr(C)]`), so the reference
        // to its first field will be aligned at least as `T::Header`.
        unsafe { &self.0 }
    }

    pub(crate) fn tail(&self) -> &[u8] {
        &self.1
    }

    pub fn as_bytes(&self) -> &[u8] {
        AsBytes::as_bytes(self)
    }

    pub fn into_bytes(self: Box<Self>) -> Box<[u8]> {
        AsBytes::into_bytes(self)
    }

    pub fn from_boxed(boxed: Box<[u8]>) -> Box<Self> {
        FromBytes::from_boxed(boxed)
    }

    pub(crate) unsafe fn ref_cast<U: BlobLayout>(&self) -> &Blob<U> {
        Blob::<U>::from_bytes(self.as_bytes())
    }
}

// SAFETY: The entire struct is `#[repr(C)]` and so is the header (because it
// implements `AsBytes` as well)
unsafe impl<T: BlobLayout> AsBytes for Blob<T> {}

unsafe impl<T: BlobLayout> FromBytes for Blob<T> {
    // Require that the allocation is at least as aligned as its header to
    // safely reference it as the first field. (despite
    // `Blob` being technically `#[repr(packed)]`)
    const MIN_LAYOUT: std::alloc::Layout = std::alloc::Layout::new::<T::Header>();

    unsafe fn ptr_cast(source: *const [u8]) -> *const Self {
        assert_ne!(source as *const (), std::ptr::null());
        // SAFETY: [u8] is 1-byte aligned so no need to check before deref
        let len = (&*source).len();
        let tail_len = len - std::mem::size_of::<T::Header>();

        // SAFETY: This assumes that the pointer to slices and slice-based DSTs
        // have the same metadata (verified by the compiler at compile-time)
        let slice = std::slice::from_raw_parts(source as *const T::Header, tail_len);
        slice as *const [T::Header] as *const _
    }
}

/// Defines a trait for accessing dynamic fields (byte slices) for structs that
/// have a header of a known size which also defines the rest of the struct
/// layout.
/// Assumes a contiguous byte buffer.
#[macro_export]
macro_rules! blob {
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

        impl<'a> $crate::helpers::blob::BlobLayout for $wrapper_ident {
            type Header = $header;
        }

        impl $crate::helpers::blob::Blob<$wrapper_ident> {
            #[allow(unused_assignments)]
            pub fn clone_from_parts(header: &$header, tail: &$tail_ident) -> Box<Self> {
                let header_len = std::mem::size_of_val(header);
                let tail_len: usize = 0 $( + blob! { size: header, $($len)*} )*;

                // To err on the safe side, despite `Blob` being
                // `#[repr(packed)]`, we pad the tail allocation as if it was
                // a regular, padded struct.
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
                    let field_len = blob! { size: header, $($len)*};
                    &mut boxed[offset..offset + field_len].copy_from_slice(tail.$field);
                    offset += field_len;
                )*

                Self::from_boxed(boxed)
            }
        }

        impl $crate::helpers::blob::Blob<$wrapper_ident> {
            blob! { fields: ;
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
            let size: usize = blob! { size: self.header(), $($curr_len)* };
            let offset = 0 $(+ self.$prev().len())*;

            &self.tail()[offset..offset + size]
        }

        // Once expanded, push the processed ident and recursively expand other
        // fields
        blob! {
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
    use crate::helpers::bytes::Pod;

    #[test]
    fn test() {
        #[repr(C)]
        pub struct Header {
            count: u16,
        }
        blob! {
            enum MyDynStruct {},
            header: Header,
            view: struct ref TailView {
                some_member[count], // Refers to run-time value of `count` field
            }
        }

        unsafe impl Pod for Header {}

        let inline = Blob::<MyDynStruct>::clone_from_parts(
            &Header { count: 4 },
            &TailView {
                some_member: &[1u8, 2, 3, 4],
            },
        );
        assert_eq!(6, std::mem::size_of_val(&*inline));

        let inline = Blob::<MyDynStruct>::clone_from_parts(
            &Header { count: 5 },
            &TailView {
                some_member: &[1u8, 2, 3, 4, 5],
            },
        );
        // Account for trailing padding
        assert_eq!(8, std::mem::size_of_val(&*inline));
    }
}
