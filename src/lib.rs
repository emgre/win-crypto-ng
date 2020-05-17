use doc_comment::doctest;

pub mod buffer;
pub mod error;
pub use error::{Error, Result};
pub mod hash;
pub mod property;
pub mod random;
pub mod symmetric;

mod helpers;

// Compile and test the README
doctest!("../README.md");
