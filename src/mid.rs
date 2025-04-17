use aead::inout::{InOut, InOutBuf};
use hybrid_array::sizes::{U16, U32};
use hybrid_array::{Array, ArraySize};

use crate::AegisParallel;

pub mod aegis128;
pub mod aegis256;
pub mod util;

pub trait AegisCore<D: AegisParallel> {
    type Key: ArraySize;
    type Block: ArraySize;

    fn new(key: &Array<u8, Self::Key>, iv: &Array<u8, Self::Key>) -> Self;

    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);
    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Self::Block>>);

    fn decrypt_partial(&mut self, mut tail: InOutBuf<'_, '_, u8>) {
        let len = tail.len();
        let mut msg_chunk = Array::default();
        msg_chunk[..len].copy_from_slice(tail.get_in());
        self.decrypt_partial_block(InOut::from(&mut msg_chunk), len);
        tail.get_out().copy_from_slice(&msg_chunk[..len]);
    }

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
