pub mod aegis128;
pub mod aegis256;

use std::marker::PhantomData;

use aead::{
    AeadCore, AeadInOut, Key, KeyInit, KeySizeUser, Nonce,
    inout::{InOut, InOutBuf},
};
use digest::{
    FixedOutput, MacMarker, OutputSizeUser, Update,
    block_buffer::{BlockBuffer, Eager},
    crypto_common::{Iv, IvSizeUser, KeyIvInit},
};
use hybrid_array::sizes::{U16, U32};
use hybrid_array::{Array, ArraySize};
use subtle::ConstantTimeEq;

use crate::mid::AegisCore;

pub struct Aegis<C: AegisCore, T>(Array<u8, C::Key>, PhantomData<T>);

impl<C: AegisCore, T> KeySizeUser for Aegis<C, T> {
    type KeySize = C::Key;
}

impl<C: AegisCore, T> KeyInit for Aegis<C, T> {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self(key.clone(), PhantomData)
    }
}

impl<C: AegisCore> AeadCore for Aegis<C, U16> {
    type NonceSize = C::Key;
    type TagSize = U16;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<C: AegisCore> AeadCore for Aegis<C, U32> {
    type NonceSize = C::Key;
    type TagSize = U32;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<C: AegisCore> AeadInOut for Aegis<C, U16> {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = C::new(&self.0, nonce);

        core_encrypt_inout_detached(&mut state, associated_data, buffer);

        // tag = Finalize(|ad|, |msg|)
        // ct = Truncate(ct, |msg|)

        // return ct and tag
        Ok(state.finalize128(ad_len_bits, msg_len_bits))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = C::new(&self.0, nonce);

        core_decrypt_inout_detached(&mut state, associated_data, buffer.reborrow());

        // expected_tag = Finalize(|ad|, |msg|)
        let expected_tag = state.finalize128(ad_len_bits, msg_len_bits);

        // if CtEq(tag, expected_tag) is False:
        //     erase msg
        //     erase expected_tag
        //     return "verification failed" error
        // else:
        //     return msg

        if expected_tag.ct_ne(tag).into() {
            // re-encrypt the buffer to prevent revealing the plaintext.
            self.encrypt_inout_detached(nonce, associated_data, InOutBuf::from(buffer.get_out()))
                .unwrap();
            Err(aead::Error)
        } else {
            Ok(())
        }
    }
}

impl<C: AegisCore> AeadInOut for Aegis<C, U32> {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = C::new(&self.0, nonce);

        core_encrypt_inout_detached(&mut state, associated_data, buffer);

        // tag = Finalize(|ad|, |msg|)
        // ct = Truncate(ct, |msg|)

        // return ct and tag
        Ok(state.finalize256(ad_len_bits, msg_len_bits))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        mut buffer: InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = C::new(&self.0, nonce);

        core_decrypt_inout_detached(&mut state, associated_data, buffer.reborrow());

        // expected_tag = Finalize(|ad|, |msg|)
        let expected_tag = state.finalize256(ad_len_bits, msg_len_bits);

        // if CtEq(tag, expected_tag) is False:
        //     erase msg
        //     erase expected_tag
        //     return "verification failed" error
        // else:
        //     return msg

        if expected_tag.ct_ne(tag).into() {
            // re-encrypt the buffer to prevent revealing the plaintext.
            self.encrypt_inout_detached(nonce, associated_data, InOutBuf::from(buffer.get_out()))
                .unwrap();
            Err(aead::Error)
        } else {
            Ok(())
        }
    }
}

fn core_encrypt_inout_detached<C: AegisCore>(
    state: &mut C,
    associated_data: &[u8],
    buffer: InOutBuf<'_, '_, u8>,
) {
    // ad_blocks = Split(ZeroPad(ad, R), R)
    // for ai in ad_blocks:
    //     Absorb(ai)
    process_chunks_padded(associated_data, |ad_chunk| {
        state.absorb(ad_chunk);
    });

    // msg_blocks = Split(ZeroPad(msg, R), R)
    // for xi in msg_blocks:
    //     ct = ct || Enc(xi)
    process_inout_chunks_padded(buffer, |msg_chunk| {
        state.encrypt_block(msg_chunk);
    });
}

fn core_decrypt_inout_detached<C: AegisCore>(
    state: &mut C,
    associated_data: &[u8],
    mut buffer: InOutBuf<'_, '_, u8>,
) {
    // ad_blocks = Split(ZeroPad(ad, R), R)
    // for ai in ad_blocks:
    //     Absorb(ai)
    process_chunks_padded(associated_data, |ad_chunk| {
        state.absorb(ad_chunk);
    });

    // ct_blocks = Split(ct, R)
    // cn = Tail(ct, |ct| mod R)
    let (ct_blocks, cn) = buffer.reborrow().into_chunks();

    // for ci in ct_blocks:
    //     msg = msg || Dec(ci)
    for ci in ct_blocks {
        state.decrypt_block(ci);
    }

    // if cn is not empty:
    //     msg = msg || DecPartial(cn)
    if !cn.is_empty() {
        decrypt_partial(state, cn);
    }
}

fn decrypt_partial<C: AegisCore>(state: &mut C, mut tail: InOutBuf<'_, '_, u8>) {
    let len = tail.len();
    let mut msg_chunk = Array::default();
    msg_chunk[..len].copy_from_slice(tail.get_in());
    state.decrypt_partial_block(InOut::from(&mut msg_chunk), len);
    tail.get_out().copy_from_slice(&msg_chunk[..len]);
}

fn process_inout_chunks_padded<'in_, 'out, T: ArraySize>(
    buffer: InOutBuf<'in_, 'out, u8>,
    mut f: impl for<'in2, 'out2> FnMut(InOut<'in2, 'out2, Array<u8, T>>),
) {
    let (msg_chunks, mut msg_tail) = buffer.into_chunks();
    for msg_chunk in msg_chunks {
        f(msg_chunk);
    }
    if !msg_tail.is_empty() {
        let len = msg_tail.len();
        let mut msg_chunk = Array::default();
        msg_chunk[..len].copy_from_slice(msg_tail.get_in());
        f(InOut::from(&mut msg_chunk));
        msg_tail.get_out().copy_from_slice(&msg_chunk[..len]);
    }
}

fn process_chunks_padded<T: ArraySize>(data: &[u8], mut f: impl FnMut(&Array<u8, T>)) {
    let (chunks, tail) = Array::slice_as_chunks(data);
    for ad_chunk in chunks {
        f(ad_chunk);
    }
    if !tail.is_empty() {
        let mut chunk = Array::default();
        chunk[..tail.len()].copy_from_slice(tail);
        f(&chunk);
    }
}

#[inline]
fn bits(bytes: usize) -> aead::Result<u64> {
    u64::try_from(bytes)
        .ok()
        .and_then(|b| b.checked_mul(8))
        .ok_or(aead::Error)
}

#[derive(Clone)]
pub struct AegisMac<C: AegisCore, T> {
    state: C,
    blocks: BlockBuffer<C::Block, Eager>,
    data_len_bits: u64,
    _parallel: PhantomData<T>,
}

impl<C: AegisCore, T> KeySizeUser for AegisMac<C, T> {
    type KeySize = C::Key;
}

impl<C: AegisCore, T> IvSizeUser for AegisMac<C, T> {
    type IvSize = C::Key;
}

impl<C: AegisCore, T> KeyIvInit for AegisMac<C, T> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            state: C::new(key, iv),
            blocks: BlockBuffer::new(&[]),
            data_len_bits: 0,
            _parallel: PhantomData,
        }
    }
}

// Update + FixedOutput + MacMarker
impl<C: AegisCore, T> MacMarker for AegisMac<C, T> {}
impl<C: AegisCore, T> Update for AegisMac<C, T> {
    fn update(&mut self, data: &[u8]) {
        self.data_len_bits = bits(data.len())
            .ok()
            .and_then(|b| self.data_len_bits.checked_add(b))
            .expect("data length in bits should not overflow u64");

        self.blocks.digest_blocks(data, |blocks| {
            blocks.iter().for_each(|block| self.state.absorb(block));
        });
    }
}

impl<C: AegisCore> OutputSizeUser for AegisMac<C, U16> {
    type OutputSize = U16;
}

impl<C: AegisCore> OutputSizeUser for AegisMac<C, U32> {
    type OutputSize = U32;
}

impl<C: AegisCore> FixedOutput for AegisMac<C, U16> {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        self.state.absorb(&self.blocks.pad_with_zeros());
        *out = self.state.finalize_mac128(self.data_len_bits)
    }
}

impl<C: AegisCore> FixedOutput for AegisMac<C, U32> {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        self.state.absorb(&self.blocks.pad_with_zeros());
        *out = self.state.finalize_mac256(self.data_len_bits)
    }
}
