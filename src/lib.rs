#![doc = include_str!("../README.md")]
#![cfg_attr(all(target_arch = "x86_64"), feature(stdarch_x86_avx512))]
#![deny(unsafe_code)]
#![deny(clippy::multiple_unsafe_ops_per_block)]

pub use aead;
pub use cipher;
pub use digest;
pub use hybrid_array;

/// 1x [parallism](`mid::AegisParallel`) marker for AEGIS.
pub struct X1;
/// 2x [parallism](`mid::AegisParallel`) marker for AEGIS.
pub struct X2;
/// 4x [parallism](`mid::AegisParallel`) marker for AEGIS.
pub struct X4;

/// 128-bit [tag](`high::AegisTag`) marker for AEGIS.
pub struct Tag128;
/// 256-bit [tag](`high::AegisTag`) marker for AEGIS.
pub struct Tag256;

/// high level internals
pub mod high;
/// middle level internals, including the core AEGIS functions
pub mod low;
/// low level internals, including AES hardware optimisations.
pub mod mid;

/// AEGIS-128L Authenticated Encryption
///
/// This is an [AEAD](`aead`) with 16 byte keys and 16 byte IVs.
pub type Aegis128L<T> = high::Aegis128X<X1, T>;
/// AEGIS-128X2 Authenticated Encryption
///
/// This is an [AEAD](`aead`) with 16 byte keys and 16 byte IVs.
///
/// It's much like [`Aegis128L`] but operates on 2 blocks in parallel,
/// which can be faster when running on AVX2 with VAES.
pub type Aegis128X2<T> = high::Aegis128X<X2, T>;
/// AEGIS-128X4 Authenticated Encryption
///
/// This is an [AEAD](`aead`) with 16 byte keys and 16 byte IVs.
///
/// It's much like [`Aegis128L`] but operates on 4 blocks in parallel,
/// which can be faster when running on AVX-512.
pub type Aegis128X4<T> = high::Aegis128X<X4, T>;

/// AEGISMAC-128L - Message Authentication
///
/// This is an [MAC](`digest::mac`) with 16 byte keys and 16 byte IVs.
pub type AegisMac128L<T> = high::AegisMac128X<X1, T>;
/// AEGISMAC-128L - Message Authentication
///
/// This is an [MAC](`digest::mac`) with 16 byte keys and 16 byte IVs.
///
/// It's much like [`AegisMac128L`] but operates on 2 blocks in parallel,
/// which can be faster when running on AVX2 with VAES.
pub type AegisMac128X2<T> = high::AegisMac128X<X2, T>;
/// AEGISMAC-128L - Message Authentication
///
/// This is an [MAC](`digest::mac`) with 16 byte keys and 16 byte IVs.
///
/// It's much like [`AegisMac128L`] but operates on 4 blocks in parallel,
/// which can be faster when running on AVX-512.
pub type AegisMac128X4<T> = high::AegisMac128X<X4, T>;

/// AEGIS-256 Authenticated Encryption
///
/// This is an [AEAD](`aead`) with 32 byte keys and 32 byte IVs.
pub type Aegis256<T> = high::Aegis256X<X1, T>;
/// AEGIS-256X2 Authenticated Encryption
///
/// This is an [AEAD](`aead`) with 32 byte keys and 32 byte IVs.
///
/// It's much like [`Aegis256`] but operates on 2 blocks in parallel,
/// which can be faster when running on AVX2 with VAES.
pub type Aegis256X2<T> = high::Aegis256X<X2, T>;
/// AEGIS-256X4 Authenticated Encryption
///
/// This is an [AEAD](`aead`) with 32 byte keys and 32 byte IVs.
///
/// It's much like [`Aegis256`] but operates on 4 blocks in parallel,
/// which can be faster when running on AVX-512.
pub type Aegis256X4<T> = high::Aegis256X<X4, T>;

/// AEGISMAC-256 - Message Authentication
///
/// This is an [MAC](`digest::mac`) with 32 byte keys and 32 byte IVs.
pub type AegisMac256<T> = high::AegisMac256X<X1, T>;
/// AEGISMAC-128L - Message Authentication
///
/// This is an [MAC](`digest::mac`) with 32 byte keys and 32 byte IVs.
///
/// It's much like [`AegisMac256`] but operates on 2 blocks in parallel,
/// which can be faster when running on AVX2 with VAES.
pub type AegisMac256X2<T> = high::AegisMac256X<X2, T>;
/// AEGISMAC-128L - Message Authentication
///
/// This is an [MAC](`digest::mac`) with 32 byte keys and 32 byte IVs.
///
/// It's much like [`AegisMac256`] but operates on 4 blocks in parallel,
/// which can be faster when running on AVX-512.
pub type AegisMac256X4<T> = high::AegisMac256X<X4, T>;
