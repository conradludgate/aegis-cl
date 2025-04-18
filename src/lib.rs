#![doc = include_str!("../README.md")]
#![cfg_attr(all(target_arch = "x86_64"), feature(stdarch_x86_avx512))]
#![deny(unsafe_code)]
#![deny(clippy::multiple_unsafe_ops_per_block)]

pub use aead;
pub use digest;
pub use hybrid_array;

pub struct X1;
pub struct X2;
pub struct X4;

pub struct Tag128;
pub struct Tag256;

// *  C0: an AES block built from the following bytes in hexadecimal
// format: { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,
// 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }.
const C0: Array<u8, hybrid_array::sizes::U16> = Array([
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
]);

// *  C1: an AES block built from the following bytes in hexadecimal
// format: { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20,
// 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }.
const C1: Array<u8, hybrid_array::sizes::U16> = Array([
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
]);

use hybrid_array::Array;

pub mod high;
pub mod low;
pub mod mid;

pub use mid::AegisCore;
pub use mid::AegisParallel;

pub use high::aegis128::{
    Aegis128L, Aegis128X, Aegis128X2, Aegis128X4, AegisMac128L, AegisMac128X, AegisMac128X2,
    AegisMac128X4,
};

pub use high::aegis256::{
    Aegis256, Aegis256X, Aegis256X2, Aegis256X4, AegisMac256, AegisMac256X, AegisMac256X2,
    AegisMac256X4,
};
