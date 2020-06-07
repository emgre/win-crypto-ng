pub mod bytes;
pub use bytes::{AsBytes, FromBytes};
pub mod blob;
pub use blob::{Blob, BlobLayout};
pub mod string;
pub use string::WideCString;

/*pub fn list_algorithms() {
    let mut alg_count = MaybeUninit::<ULONG>::uninit();
    let mut alg_list = MaybeUninit::<*mut BCRYPT_ALGORITHM_IDENTIFIER>::uninit();
    unsafe {
        BCryptEnumAlgorithms(
            BCRYPT_HASH_OPERATION,
            alg_count.as_mut_ptr(),
            alg_list.as_mut_ptr(),
            0
        );

        for i in 0..alg_count.assume_init() {
            let name = WideCString::from_ptr((*alg_list.assume_init().offset(i as isize)).pszName);
            println!("{}", name.to_str());
        }
    }
}*/
