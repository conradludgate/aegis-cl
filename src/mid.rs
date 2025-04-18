use aead::inout::InOut;
use cipher::crypto_common::BlockSizes;
use hybrid_array::{Array, ArraySize};

use crate::low::{AesBlock, AesBlock2, AesBlock4, AesBlockArray};

mod aegis128;
mod aegis256;
mod util;

mod sealed {
    pub trait Sealed {}
}

pub use aegis128::State128X;
pub use aegis256::State256X;

/// The parallelism used by the AEGIS state.
pub trait AegisParallel: sealed::Sealed {
    /// The number of AES blocks to update in parallel.
    type Blocks: ArraySize;

    #[doc(hidden)]
    type AesBlock: AesBlockArray + Into<Array<AesBlock, Self::Blocks>>;

    #[doc(hidden)]
    fn ctx() -> Self::AesBlock;
}

impl sealed::Sealed for crate::X1 {}
impl AegisParallel for crate::X1 {
    type Blocks = hybrid_array::sizes::U1;
    type AesBlock = AesBlock;

    fn ctx() -> Self::AesBlock {
        AesBlock::from_block(&Array([0; 16]))
    }
}

impl sealed::Sealed for crate::X2 {}
impl AegisParallel for crate::X2 {
    type Blocks = hybrid_array::sizes::U2;
    type AesBlock = AesBlock2;

    fn ctx() -> Self::AesBlock {
        let mut a = Array([0; 32]);
        a[16] = 1;
        a[1] = 1;
        a[17] = 1;

        AesBlock2::from_block(&a)
    }
}

impl sealed::Sealed for crate::X4 {}
impl AegisParallel for crate::X4 {
    type Blocks = hybrid_array::sizes::U4;
    type AesBlock = AesBlock4;

    fn ctx() -> Self::AesBlock {
        let mut a = Array([0; 64]);
        a[16] = 1;
        a[32] = 2;
        a[48] = 3;
        a[1] = 3;
        a[17] = 3;
        a[33] = 3;
        a[49] = 3;

        AesBlock4::from_block(&a)
    }
}

/// The core AEGIS state and functions.
pub trait AegisCore: Copy {
    /// The size of the key/iv used to initialise this AEGIS state.
    type Key: ArraySize;
    /// The size of the blocks processed by this AEGIS state.
    type Block: BlockSizes;

    fn new(key: &Array<u8, Self::Key>, iv: &Array<u8, Self::Key>) -> Self;

    fn encrypt_emtpy_block(&mut self, block: &mut Array<u8, Self::Block>);

    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);
    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);

    fn decrypt_partial_block(
        &mut self,
        padded_block: InOut<'_, '_, Array<u8, Self::Block>>,
        len: usize,
    );

    fn finalize128(self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 16];
    fn finalize_mac128(self, data_len_bits: u64) -> [u8; 16];
    fn finalize256(self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 32];
    fn finalize_mac256(self, data_len_bits: u64) -> [u8; 32];

    fn absorb(&mut self, ad: &Array<u8, Self::Block>);
}

// *  C0: an AES block built from the following bytes in hexadecimal
// format: { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,
// 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }.
const C0: hybrid_array::Array<u8, hybrid_array::sizes::U16> = hybrid_array::Array([
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
]);

// *  C1: an AES block built from the following bytes in hexadecimal
// format: { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20,
// 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }.
const C1: hybrid_array::Array<u8, hybrid_array::sizes::U16> = hybrid_array::Array([
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
]);
