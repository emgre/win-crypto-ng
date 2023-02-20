# win-crypto-ng

[![crates.io](https://img.shields.io/crates/v/win-crypto-ng.svg)](https://crates.io/crates/win-crypto-ng)
[![docs.rs](https://docs.rs/win-crypto-ng/badge.svg)](https://docs.rs/crate/win-crypto-ng)
![MSRV](https://img.shields.io/badge/rustc-1.60+-blue.svg)
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
- Asymmetric encryption (RSA)
- Digital signatures
  - Supported algorithms: RSA, DSA, ECDSA.
- Key exchange
  - Supported algorithms: DH, ECDH.
- Symmetric encryption
  - Supported algorithms: AES, DES, DES-X, RC2, 3DES, 3DES-112.
  - Supported chaining modes: ECB, CBC, CFB.
- Hash functions
  - Supported algorithms: SHA-1, SHA-256, SHA-384, SHA-512, MD2, MD4, MD5.
- Cryptographically secure random number generation

*More to come*

## Cargo features

- `zeroize` - Uses `zeroize` crate to zero intermediate buffers on destruction
- `rand` - Implements `rand` crate traits for the CNG-provided CSPRNG
  (cryptographically secure pseudorandom number generator)
- `block-cipher` - Implements `block-cipher` traits for CNG block ciphers.

By default, only the `zeroize` feature is enabled.

## Examples

### Asymmetric encryption (RSA)

```rust
use win_crypto_ng::asymmetric::{AsymmetricKey, EncryptionPadding, Rsa};
let key = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();

let plaintext = b"This is an important message.";

let padding = Some(EncryptionPadding::Pkcs1);
let ciphertext = key.encrypt(padding.clone(), &*plaintext).unwrap();
assert_eq!(ciphertext.len(), 1024 / 8);
let decoded = key.decrypt(padding, ciphertext.as_ref()).unwrap();
assert_eq!(plaintext, decoded.as_ref());
```

### Digital signatures
```rust
use win_crypto_ng::asymmetric::signature::{Signer, Verifier, SignaturePadding};
use win_crypto_ng::asymmetric::{AsymmetricKey, Rsa};
use win_crypto_ng::hash::HashAlgorithmId;

let key = AsymmetricKey::builder(Rsa).key_bits(1024).build().unwrap();

let data: Vec<u8> = (0..32).collect();
let padding = SignaturePadding::pkcs1(HashAlgorithmId::Sha256);
let signature = key.sign(&*data, Some(padding)).expect("Signing to succeed");

key.verify(&data, &signature, Some(padding)).expect("Signature to be valid");

key.verify(&[0xDE, 0xAD], &signature, Some(padding)).expect_err("Bad digest");
key.verify(&data, &[0xDE, 0xAD], Some(padding)).expect_err("Bad signature");
```

### Symmetric encryption

```rust
use win_crypto_ng::symmetric::{ChainingMode, SymmetricAlgorithm, SymmetricAlgorithmId, Padding};

const KEY: &'static str = "0123456789ABCDEF";
const IV: &'static str = "asdfqwerasdfqwer";
const DATA: &'static str = "This is a test.";

let iv = IV.as_bytes().to_vec();

let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
let key = algo.new_key(KEY.as_bytes()).unwrap();
let ciphertext = key.encrypt(Some(&mut iv.clone()), DATA.as_bytes(), Some(Padding::Block)).unwrap();
let plaintext = key.decrypt(Some(&mut iv.clone()), ciphertext.as_slice(), Some(Padding::Block)).unwrap();

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

### Cryptographically secure random number generator

```rust
use win_crypto_ng::random::{RandomAlgorithmId, RandomNumberGenerator};

let mut buffer = [0u8; 32];
let rng = RandomNumberGenerator::system_preferred();
rng.gen_random(&mut buffer).unwrap();

assert_ne!(&buffer, &[0u8; 32]);
```

## License

Licensed under the 3-Clause BSD License. See [LICENSE.md](LICENSE.md) for more details.

Copyright (c) 2019-2020 Émile Grégoire. All rights reserved.
