# win-crypto-ng

[![crates.io](https://img.shields.io/crates/v/win-crypto-ng.svg)](https://crates.io/crates/win-crypto-ng)
[![docs.rs](https://docs.rs/win-crypto-ng/badge.svg)](https://docs.rs/crate/win-crypto-ng)
![MSRV](https://img.shields.io/badge/rustc-1.37+-blue.svg)
[![Build status](https://github.com/emgre/win-crypto-ng/workflows/CI/badge.svg)](https://github.com/emgre/win-crypto-ng/actions)
[![License](https://img.shields.io/github/license/emgre/win-crypto-ng)](https://github.com/emgre/win-crypto-ng/blob/master/LICENSE.md)

Safe Rust bindings to Microsoft Windows
[Cryptography API : Next Generation (CNG)](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal)

CNG are cryptographic primitives and utilities provided by the operating system and/or hardware. It is available since
Windows Vista and replaces the now deprecated
[CryptoAPI](https://docs.microsoft.com/fr-fr/windows/win32/seccrypto/cryptography-portal).

The primitives do **not** depend on OpenSSL or other libraries of the sort, they are provided by Microsoft and/or by
the hardware manufacturer. They are the primitives used in kernel space programs. Therefore, if you are using Microsoft
Windows, you already accepted to trust these primitives.

## CNG Features

- Validated by FIPS 140-2 and part of the Target of Evaluation for the Windows Common Criteria certification
- Full support for NSA Suite B algorithms
- Kernel support (not through the Rust bindings)
- Auditing in the key storage provider (KSP)
- Thread safe

## Supported features in Rust
- Symmetric encryption
  - Supported algorithms: AES, DES, DES-X, RC2, 3DES, 3DES-112.
  - Supported chaining modes: ECB, CBC, CFB.
- Hash functions
  - Supported algorithms: SHA-1, SHA-256, SHA-384, SHA-512, SHA-512, MD2, MD4, MD5.

*More to come*

## Examples

### Symmetric encryption

```rust
use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId};

const KEY: &'static str = "0123456789ABCDEF";
const IV: &'static str = "asdfqwerasdfqwer";
const DATA: &'static str = "This is a test.";

let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
let key = algo.new_key(KEY.as_bytes()).unwrap();
let ciphertext = key.encrypt(Some(IV.as_bytes()), DATA.as_bytes()).unwrap();
let plaintext = key.decrypt(Some(IV.as_bytes()), ciphertext.as_slice()).unwrap();

assert_eq!(std::str::from_utf8(&plaintext.as_slice()[..DATA.len()]).unwrap(), DATA);
```

### Hash functions

```rust
use win_crypto_ng::hash::{HashAlgorithm, HashAlgorithmId};

const DATA: &'static str = "This is a test.";

let algo = HashAlgorithm::open(HashAlgorithmId::Sha256).unwrap();
let mut hash = algo.new_hash().unwrap();
hash.hash(DATA.as_bytes()).unwrap();
let result = hash.finish().unwrap();

assert_eq!(result.as_slice(), &[
    0xA8, 0xA2, 0xF6, 0xEB, 0xE2, 0x86, 0x69, 0x7C,
    0x52, 0x7E, 0xB3, 0x5A, 0x58, 0xB5, 0x53, 0x95,
    0x32, 0xE9, 0xB3, 0xAE, 0x3B, 0x64, 0xD4, 0xEB,
    0x0A, 0x46, 0xFB, 0x65, 0x7B, 0x41, 0x56, 0x2C,
]);
```

## License

Licensed under the 3-Clause BSD License. See [LICENSE.md](LICENSE.md) for more details.

Copyright (c) 2019 Émile Grégoire. All rights reserved.
