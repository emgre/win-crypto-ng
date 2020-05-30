use std::marker::PhantomData;
use std::ops::Deref;

/// A typed view into an opaque blob of heap-allocated bytes.
pub struct TypedBlob<T: ?Sized> {
    allocation: Box<[u8]>,
    marker: PhantomData<T>,
}

impl<T: ?Sized> std::fmt::Debug for TypedBlob<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TypedBlob({}, {:?})",
            std::any::type_name::<T>(),
            self.allocation
        )
    }
}

impl<T: ?Sized> Into<Box<[u8]>> for TypedBlob<T> {
    fn into(self) -> Box<[u8]> {
        self.allocation
    }
}

#[allow(dead_code)]
impl<T: ?Sized> TypedBlob<T> {
    pub fn into_inner(self) -> Box<[u8]> {
        self.into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.allocation
    }
}

impl<T: Sized> Deref for TypedBlob<T> {
    type Target = T;

    /// Creates a typed reference to the underlying data structure backed by the
    /// source bytes.
    fn deref(&self) -> &T {
        // SAFETY: The only way to create this struct with sized `T` is via
        // `TypedBlob::from_box`, where:
        // 1. the caller has to prove that the data is of correct format,
        // 2. we check that the resulting reference will be well-aligned, and
        // 3. the allocation is big enough to hold a value of type `T`.
        unsafe { &*(self.allocation.as_ptr() as *const T) }
    }
}

impl<T, U: AsRef<T>> AsRef<T> for TypedBlob<U> {
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

#[allow(dead_code)]
impl<T: Sized> TypedBlob<T> {
    /// Converts an opaque blob of bytes into a typed blob asserting that the
    /// raw bytes correspond in shape to value of type `T`.
    ///
    /// # Panics
    /// This function panicks if the allocation is not big enough to hold a
    /// value of type `T` or if the backing pointee alignment is not compatible
    /// with that of `T`.
    pub unsafe fn from_box(allocation: Box<[u8]>) -> Self {
        assert!(allocation.len() >= std::mem::size_of::<T>());
        // Verify that we can produce a valid reference (which are required to
        // always be well-aligned).
        assert_eq!(allocation.as_ptr() as usize % std::mem::align_of::<T>(), 0);

        TypedBlob {
            allocation,
            marker: PhantomData,
        }
    }
}

impl<T> AsRef<[T]> for TypedBlob<[T]> {
    /// Creates a typed reference to the underlying data structure backed by the
    /// source bytes.
    ///
    /// # Panics
    /// This function panicks if the allocation does not fit exactly a certain
    /// count of `T`-sized values.
    fn as_ref(&self) -> &[T] {
        // SAFETY: The only way to create this struct with *unsized* `T` is via
        // `TypedBlob::from_box_unsized`, where:
        // 1. the caller has to prove that the data is of correct format,
        // 2. we check that the resulting reference will be well-aligned.

        // Ensure that allocation can hold exactly N elements of type T - we
        // disallow any trailing bytes outside of the resulting `[T]` slice.
        assert_eq!(self.allocation.len() % std::mem::size_of::<T>(), 0);

        unsafe {
            std::slice::from_raw_parts(
                self.allocation.as_ptr() as *const T,
                // Account for possibly fewer slice elements, e.g. [u16] will
                // have 2 times fewer elements than [u8] for the same bytes.
                self.allocation.len() * std::mem::size_of::<u8>() / std::mem::size_of::<T>(),
            )
        }
    }
}

#[allow(dead_code)]
impl<T: ?Sized> TypedBlob<T> {
    /// Converts an opaque blob of bytes into a typed blob asserting that the
    /// raw bytes correspond in shape to value of type `T`.
    ///
    /// **NOTE: Only slices are supported at the moment.** To uphold safety
    /// invariants, this type can only be safely dereferenced for slice types,
    /// as long as the allocation size matches the slice layout.
    ///
    /// # Panics
    /// This function panicks if the backing pointee alignment is not compatible
    /// with that of `&T`.
    ///
    /// # Safety
    /// The caller has to guarantee that the type of is of correct layout.
    /// For slices (`[T]`), the memory allocation should contain *exactly* given
    /// N elements of type T.
    pub unsafe fn from_box_unsized(allocation: Box<[u8]>) -> Self {
        // Verify that we can produce a valid reference (which are required to
        // always be well-aligned).
        assert_eq!(allocation.as_ptr() as usize % std::mem::align_of::<&T>(), 0);

        TypedBlob {
            allocation,
            marker: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_blob() {
        #[repr(C)]
        #[derive(Debug)]
        struct Inner {
            first: u16,
            second: u32,
        }

        let bytes = vec![0x1, 0x1, 0xFF, 0xFF, 0x2, 0x2, 0x2, 0x2, 0xDE, 0xDE].into_boxed_slice();
        let typed = unsafe { TypedBlob::<Inner>::from_box(bytes.clone()) };
        assert_eq!(typed.first, 0x0101);
        assert_eq!(typed.second, 0x02020202);
        let typed = unsafe { TypedBlob::<[u8; 10]>::from_box(bytes.clone()) };
        assert_eq!(&*typed, bytes.as_ref());

        let typed = unsafe { TypedBlob::<[u8]>::from_box_unsized(bytes.clone()) };
        assert_eq!(typed.as_ref(), bytes.as_ref());
        let typed = unsafe { TypedBlob::<[u16]>::from_box_unsized(bytes.clone()) };
        assert_eq!(typed.as_ref(), &[0x0101, 0xFFFF, 0x0202, 0x0202, 0xDEDE]);

        assert!(std::panic::catch_unwind(|| {
            // Allocation is too small
            unsafe { TypedBlob::<[[u8; 1000]; 1]>::from_box(bytes.clone()) }
        })
        .is_err());
    }
}
