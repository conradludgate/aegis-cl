use aead::inout::InOut;
use hybrid_array::sizes::{U16, U32};
use hybrid_array::{Array, ArraySize};

pub mod aegis128;
pub mod aegis256;
mod util;

pub trait AegisCore {
    type Key: ArraySize;
    type Block: ArraySize;

    fn new(key: &Array<u8, Self::Key>, iv: &Array<u8, Self::Key>) -> Self;

    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);
    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);

    fn decrypt_partial_block(
        &mut self,
        padded_block: InOut<'_, '_, Array<u8, Self::Block>>,
        len: usize,
    );

    fn finalize128(self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, U16>;
    fn finalize_mac128(self, data_len_bits: u64) -> Array<u8, U16>;
    fn finalize256(self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, U32>;
    fn finalize_mac256(self, data_len_bits: u64) -> Array<u8, U32>;

    fn absorb(&mut self, ad: &Array<u8, Self::Block>);
}
