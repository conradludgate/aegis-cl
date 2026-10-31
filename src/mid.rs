use crate::low::{
    AesBlock, AesBlockArray,
    backend::{Backend, Static},
};
use aead::inout::InOut;
use cipher::crypto_common::BlockSizes;
use hybrid_array::{Array, ArraySize};
mod aegis128;
mod aegis256;
mod util;
mod sealed {
    use crate::{low::backend::Backend, runtime::Algorithm};
    use hybrid_array::sizes::{U16, U32};

    // These mappings let generic lane types reach the closed runtime algorithm
    // implementations without sealing the public, customizable AegisCore trait.
    pub trait Sealed {
        type State128<B: Backend>: Algorithm<Key = U16>;
        type State256<B: Backend>: Algorithm<Key = U32>;
    }
}
pub use aegis128::State128X;
pub use aegis256::State256X;

/// Internal mapping from algorithm lanes to a backend's block representation.
#[doc(hidden)]
pub trait BackendParallel<B: Backend>: sealed::Sealed {
    type Storage: AesBlockArray<B::Scalar>;
    #[inline(always)]
    fn backend_ctx() -> Self::Storage {
        let mut ctx = Array::<u8, <Self::Storage as AesBlockArray<B::Scalar>>::Block>::default();
        let lanes = ctx.len() / 16;
        // Each AES lane is domain-separated by (lane index, lane count - 1).
        for (i, lane) in ctx.as_chunks_mut::<16>().0.iter_mut().enumerate() {
            lane[0] = i as u8;
            lane[1] = (lanes - 1) as u8;
        }
        Self::Storage::from_block(&ctx)
    }
}
type Repr<D, B> = <D as BackendParallel<B>>::Storage;

/// The parallelism used by the AEGIS state.
pub trait AegisParallel:
    sealed::Sealed + BackendParallel<Static, Storage = Self::AesBlock>
{
    /// The number of AES blocks to update in parallel.
    type Blocks: ArraySize;
    #[doc(hidden)]
    type AesBlock: AesBlockArray + Into<Array<AesBlock, Self::Blocks>>;
    #[doc(hidden)]
    fn ctx() -> Self::AesBlock;
}
macro_rules! parallel {
    ($name:ident, $count:ident, $repr:ident) => {
        impl<B: Backend> BackendParallel<B> for crate::$name {
            type Storage = <B as Backend>::$repr;
        }
        impl sealed::Sealed for crate::$name {
            type State128<B: Backend> = State128X<Self, B>;
            type State256<B: Backend> = State256X<Self, B>;
        }
        impl AegisParallel for crate::$name {
            type Blocks = hybrid_array::sizes::$count;
            type AesBlock = <Static as Backend>::$repr;
            fn ctx() -> Self::AesBlock {
                <Self as BackendParallel<Static>>::backend_ctx()
            }
        }
    };
}
parallel!(X1, U1, Scalar);
parallel!(X2, U2, Pair);
parallel!(X4, U4, Quad);

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

    /// Complete AEAD operation. Built-in cores may select a CPU backend here.
    #[doc(hidden)]
    #[inline(always)]
    fn encrypt_aead<T: crate::high::AegisTag>(
        key: &Array<u8, Self::Key>,
        nonce: &Array<u8, Self::Key>,
        ad: &[u8],
        data: aead::inout::InOutBuf<'_, '_, u8>,
    ) -> aead::Result<Array<u8, T::Size>> {
        crate::high::encrypt::<Self, T>(key, nonce, ad, data)
    }

    /// Complete AEAD operation; custom cores retain the static default engine.
    #[doc(hidden)]
    #[inline(always)]
    fn decrypt_aead<T: crate::high::AegisTag>(
        key: &Array<u8, Self::Key>,
        nonce: &Array<u8, Self::Key>,
        ad: &[u8],
        data: aead::inout::InOutBuf<'_, '_, u8>,
        tag: &Array<u8, T::Size>,
    ) -> aead::Result<()> {
        crate::high::decrypt::<Self, T>(key, nonce, ad, data, tag)
    }
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
