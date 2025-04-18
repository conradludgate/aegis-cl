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

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for crate::Tag128 {}
impl sealed::Sealed for crate::Tag256 {}

pub trait AegisTag: sealed::Sealed {
    type Size: ArraySize;
    #[doc(hidden)]
    fn finalize<C: AegisCore>(s: C, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, Self::Size>;
    #[doc(hidden)]
    fn finalize_mac<C: AegisCore>(s: C, data_len_bits: u64) -> Array<u8, Self::Size>;
}

impl AegisTag for crate::Tag128 {
    type Size = U16;

    #[doc(hidden)]
    #[inline(always)]
    fn finalize<C: AegisCore>(s: C, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, Self::Size> {
        Array(s.finalize128(ad_len_bits, msg_len_bits))
    }
    #[doc(hidden)]
    #[inline(always)]
    fn finalize_mac<C: AegisCore>(s: C, data_len_bits: u64) -> Array<u8, Self::Size> {
        Array(s.finalize_mac128(data_len_bits))
    }
}

impl AegisTag for crate::Tag256 {
    type Size = U32;

    #[doc(hidden)]
    #[inline(always)]
    fn finalize<C: AegisCore>(s: C, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, Self::Size> {
        Array(s.finalize256(ad_len_bits, msg_len_bits))
    }
    #[doc(hidden)]
    #[inline(always)]
    fn finalize_mac<C: AegisCore>(s: C, data_len_bits: u64) -> Array<u8, Self::Size> {
        Array(s.finalize_mac256(data_len_bits))
    }
}

pub struct Aegis<C: AegisCore, T: AegisTag>(Array<u8, C::Key>, PhantomData<T>);

impl<C: AegisCore, T: AegisTag> KeySizeUser for Aegis<C, T> {
    type KeySize = C::Key;
}

impl<C: AegisCore, T: AegisTag> KeyInit for Aegis<C, T> {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self(key.clone(), PhantomData)
    }
}

impl<C: AegisCore, T: AegisTag> AeadCore for Aegis<C, T> {
    type NonceSize = C::Key;
    type TagSize = T::Size;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<C: AegisCore, T: AegisTag> AeadInOut for Aegis<C, T> {
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

        // ad_blocks = Split(ZeroPad(ad, R), R)
        // for ai in ad_blocks:
        //     Absorb(ai)
        process_chunks_padded(associated_data, |ad_chunk| {
            state.absorb(ad_chunk);
        });

        // msg_blocks = Split(ZeroPad(msg, R), R)
        // for xi in msg_blocks:
        //     ct = ct || Enc(xi)
        let (xt_blocks, mut xn) = buffer.into_chunks();
        for xi in xt_blocks {
            state.encrypt_block(xi);
        }
        if !xn.is_empty() {
            let len = xn.len();
            let mut msg_chunk = Array::default();
            msg_chunk[..len].copy_from_slice(xn.get_in());
            state.encrypt_block(InOut::from(&mut msg_chunk));
            xn.get_out().copy_from_slice(&msg_chunk[..len]);
        }

        // tag = Finalize(|ad|, |msg|)
        // ct = Truncate(ct, |msg|)

        // return ct and tag
        Ok(T::finalize(state, ad_len_bits, msg_len_bits))
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
            decrypt_partial(&mut state, cn);
        }

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

fn decrypt_partial<C: AegisCore>(state: &mut C, mut tail: InOutBuf<'_, '_, u8>) {
    let len = tail.len();
    let mut msg_chunk = Array::default();
    msg_chunk[..len].copy_from_slice(tail.get_in());
    state.decrypt_partial_block(InOut::from(&mut msg_chunk), len);
    tail.get_out().copy_from_slice(&msg_chunk[..len]);
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
pub struct AegisMac<C: AegisCore, T: AegisTag> {
    state: C,
    blocks: BlockBuffer<C::Block, Eager>,
    data_len_bits: u64,
    _parallel: PhantomData<T>,
}

impl<C: AegisCore, T: AegisTag> KeySizeUser for AegisMac<C, T> {
    type KeySize = C::Key;
}

impl<C: AegisCore, T: AegisTag> IvSizeUser for AegisMac<C, T> {
    type IvSize = C::Key;
}

impl<C: AegisCore, T: AegisTag> KeyIvInit for AegisMac<C, T> {
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
impl<C: AegisCore, T: AegisTag> MacMarker for AegisMac<C, T> {}
impl<C: AegisCore, T: AegisTag> Update for AegisMac<C, T> {
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

impl<C: AegisCore, T: AegisTag> OutputSizeUser for AegisMac<C, T> {
    type OutputSize = T::Size;
}

impl<C: AegisCore, T: AegisTag> FixedOutput for AegisMac<C, T> {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        self.state.absorb(&self.blocks.pad_with_zeros());
        *out = T::finalize_mac(self.state, self.data_len_bits)
    }
}
