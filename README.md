# win-crypto-ng

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
  - Supported algorithms: AES, DES, DES-X, RC2, 3DES, 3DES 112.
  - Supported chaining modes: ECB, CBC, CFB.

*More to come*

## Examples

### Symmetric encryption

```rust
use win_crypto_ng::symmetric::*;

fn main() {
    const KEY: &'static str = "0123456789ABCDEF";
    const IV: &'static str = "asdfqwerasdfqwer";
    const DATA: &'static str = "This is a test.";
    
    let algo = SymmetricAlgorithm::open(SymmetricAlgorithmId::Aes, ChainingMode::Cbc).unwrap();
    println!("Valid key sizes: {:?}", algo.valid_key_sizes().unwrap());
    
    let key = algo.new_key(KEY.as_bytes()).unwrap();
    println!("Key size: {}", key.key_size().unwrap());
    
    let result = key.encrypt(Some(IV.as_bytes()), DATA.as_bytes()).unwrap();
    println!("Encrypted data: {:?}", result);
    
    let result = key.decrypt(Some(IV.as_bytes()), result.as_slice()).unwrap();
    println!("Decrypted data: {:?}", std::str::from_utf8(&result.as_slice()[..DATA.len()]).unwrap());
}
```

## License

Licensed under the 3-Clause BSD License. See [LICENSE.md](LICENSE.md) for more details.

Copyright (c) 2019 Émile Grégoire. All rights reserved.
