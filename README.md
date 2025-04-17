# The AEGIS Family of Authenticated Encryption Algorithms

This is a performant and feature complete pure-rust implementation of AEGIS.

While <https://github.com/jedisct1/rust-aegis/> exists, it only offers good performance
using the C implementation. Its pure-rust implementation only offers Aegis256 and Aegis128l
with ok perforamnce.

Currently this is built using an [unstable version of RustCrypto traits](https://github.com/RustCrypto/traits/tree/3620aba4f1e81e506b46a5f88c47f7ee3a7b87e0).

## Features

### Authenticated Encryption with Additional Data (AEAD)

- `Aegis128L` offers authenticated encryption with 128 bit keys and nonces.
- `Aegis256` offers authenticated encryption with 256 bit keys and nonces.

Both support either 128 bit or 256 bit message tags.

Aside from the core algorithms, there is also

- `Aegis128X2` - Like `Aegis128L` but operates on 2 blocks at a time, offering performance improvements with AVX2.
- `Aegis256X2` - Like `Aegis256` but operates on 2 blocks at a time, offering performance improvements with AVX2.
- `Aegis128X4` - Like `Aegis128L` but operates on 4 blocks at a time, offering performance improvements with AVX512.
- `Aegis256X4` - Like `Aegis256` but operates on 4 blocks at a time, offering performance improvements with AVX512.

### Message Authentication Codes (MAC)

- `AegisMac128:` offers message authentication with 128 bit keys and nonces.
- `AegisMac256` offers message authentication with 256 bit keys and nonces.

Both support either 128 bit or 256 bit authentication codes.

Aside from the core algorithms, there is also

- `AegisMac128X2` - Like `AegisMac128L` but operates on 2 blocks at a time, offering performance improvements with AVX2.
- `AegisMac256X2` - Like `AegisMac256` but operates on 2 blocks at a time, offering performance improvements with AVX2.
- `AegisMac128X4` - Like `AegisMac128L` but operates on 4 blocks at a time, offering performance improvements with AVX512.
- `AegisMac256X4` - Like `AegisMac256` but operates on 4 blocks at a time, offering performance improvements with AVX512.

## Usage

### AEAD

```rust
use aegis_cl::{
    aead::{Aead, AeadCore, KeyInit},
    Aegis128L, Tag128
};

let key = Aegis128L::<Tag128>::generate_key().unwrap();
let cipher = Aegis128L::<Tag128>::new(&key);
let nonce = Aegis128L::<Tag128>::generate_nonce().unwrap();
let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref()).unwrap();
let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
assert_eq!(&plaintext, b"plaintext message");
```

### MAC

```rust
use aegis_cl::{
    digest::{Mac},
    digest::crypto_common::{KeyIvInit},
    AegisMac128L, Tag128
};

let key = AegisMac128L::<Tag128>::generate_key().unwrap();
let iv = AegisMac128L::<Tag128>::generate_iv().unwrap();

let mut mac = AegisMac128L::<Tag128>::new(&key, &iv);
mac.update(b"plaintext message".as_ref());
let tag = mac.finalize().into_bytes();

let mut mac = AegisMac128L::<Tag128>::new(&key, &iv);
mac.update(b"plaintext message".as_ref());
mac.verify(&tag).unwrap();
```

### Stream

```rust
use aegis_cl::{
    cipher::{KeyIvInit, StreamCipher},
    high::AegisStream,
    mid::aegis128::State128X,
    hybrid_array::sizes::U1,
};

let key = AegisStream::<State128X<U1>>::generate_key().unwrap();
let iv = AegisStream::<State128X<U1>>::generate_iv().unwrap();

let mut buffer = *b"plaintext message";

let mut cipher = AegisStream::<State128X<U1>>::new(&key, &iv);
cipher.apply_keystream(&mut buffer);

let mut cipher = AegisStream::<State128X<U1>>::new(&key, &iv);
cipher.apply_keystream(&mut buffer);

assert_eq!(&buffer, b"plaintext message");
```
