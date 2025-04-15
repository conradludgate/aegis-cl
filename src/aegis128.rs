use std::marker::PhantomData;

use aead::{
    AeadCore, AeadInOut, Key, KeyInit, KeySizeUser, Nonce,
    inout::{InOut, InOutBuf},
};
use digest::{
    FixedOutput, Mac, MacMarker, OutputSizeUser, Update,
    block_buffer::{BlockBuffer, Eager},
    crypto_common::{Iv, IvSizeUser, KeyIvInit},
};
use hybrid_array::{
    Array,
    sizes::{U1, U16},
};
use subtle::ConstantTimeEq;

use crate::{
    AegisParallel, C0, C1,
    aarch64::AesBlock,
    util::{self, ctx},
};

pub type Aegis128L = Aegis128X<U1>;
pub struct Aegis128X<D>(Array<u8, U16>, PhantomData<D>);

type TagSize = U16;

impl<D> KeySizeUser for Aegis128X<D> {
    type KeySize = U16;
}

impl<D> KeyInit for Aegis128X<D> {
    fn new(key: &Key<Self>) -> Self {
        Self(*key, PhantomData)
    }
}

impl<D> AeadCore for Aegis128X<D> {
    type NonceSize = U16;
    type TagSize = TagSize;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<D: AegisParallel> AeadInOut for Aegis128X<D> {
    fn encrypt_inout_detached(
        &self,
        nonce: &Nonce<Self>,
        associated_data: &[u8],
        buffer: InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = util::bits(buffer.len())?;
        let ad_len_bits = util::bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = State128X::<D>::new(&self.0, nonce);

        // ad_blocks = Split(ZeroPad(ad, R), R)
        // for ai in ad_blocks:
        //     Absorb(ai)
        util::process_chunks_padded(associated_data, |ad_chunk| {
            state.absorb(ad_chunk);
        });

        // msg_blocks = Split(ZeroPad(msg, R), R)
        // for xi in msg_blocks:
        //     ct = ct || Enc(xi)
        util::process_inout_chunks_padded(buffer, |msg_chunk| {
            state.encrypt_block(msg_chunk);
        });

        // tag = Finalize(|ad|, |msg|)
        // ct = Truncate(ct, |msg|)

        // return ct and tag
        Ok(state.finalize(ad_len_bits, msg_len_bits))
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
        let msg_len_bits = util::bits(buffer.len())?;
        let ad_len_bits = util::bits(associated_data.len())?;

        // Init(key, nonce)
        let mut state = State128X::<D>::new(&self.0, nonce);

        // ad_blocks = Split(ZeroPad(ad, R), R)
        // for ai in ad_blocks:
        //     Absorb(ai)
        util::process_chunks_padded(associated_data, |ad_chunk| {
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
            state.decrypt_partial(cn);
        }

        // expected_tag = Finalize(|ad|, |msg|)
        let expected_tag = state.finalize(ad_len_bits, msg_len_bits);

        // if CtEq(tag, expected_tag) is False:
        //     erase msg
        //     erase expected_tag
        //     return "verification failed" error
        // else:
        //     return msg

        if expected_tag.ct_ne(tag).into() {
            // re-encrypt the buffer to prevent revealing the plaintext.
            self.encrypt_inout_detached(nonce, associated_data, buffer)
                .unwrap();
            Err(aead::Error)
        } else {
            Ok(())
        }
    }
}

pub type AegisMac128L = AegisMac128X<U1>;
pub struct AegisMac128X<D: AegisParallel> {
    state: State128X<D>,
    blocks: BlockBuffer<D::Aegis128BlockSize, Eager>,
    data_len_bits: u64,
    _parallel: PhantomData<D>,
}

impl<D: AegisParallel> KeySizeUser for AegisMac128X<D> {
    type KeySize = U16;
}

impl<D: AegisParallel> IvSizeUser for AegisMac128X<D> {
    type IvSize = U16;
}

impl<D: AegisParallel> KeyIvInit for AegisMac128X<D> {
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        Self {
            state: State128X::new(key, iv),
            blocks: BlockBuffer::new(&[]),
            data_len_bits: 0,
            _parallel: PhantomData,
        }
    }
}

// Update + FixedOutput + MacMarker
impl<D: AegisParallel> MacMarker for AegisMac128X<D> {}
impl<D: AegisParallel> Update for AegisMac128X<D> {
    fn update(&mut self, data: &[u8]) {
        self.data_len_bits = util::bits(data.len())
            .ok()
            .and_then(|b| self.data_len_bits.checked_add(b))
            .expect("data length in bits should not overflow u64");

        self.blocks.digest_blocks(data, |blocks| {
            blocks.iter().for_each(|block| self.state.absorb(block));
        });
    }
}

impl<D: AegisParallel> OutputSizeUser for AegisMac128X<D> {
    type OutputSize = TagSize;
}

impl<D: AegisParallel> FixedOutput for AegisMac128X<D> {
    fn finalize_into(mut self, out: &mut digest::Output<Self>) {
        self.state.absorb(&self.blocks.pad_with_zeros());
        *out = self.state.finalize_mac(self.data_len_bits, 128)
    }
}

#[derive(Clone)]
pub struct State128X<D: AegisParallel>(Array<State128L, D>);

impl<D: AegisParallel> State128X<D> {
    fn new(key: &Key<Aegis128X<D>>, iv: &Nonce<Aegis128X<D>>) -> Self {
        let key = AesBlock::from_bytes(&key.0);
        let nonce = AesBlock::from_bytes(&iv.0);
        let c0 = AesBlock::from_bytes(&C0);
        let c1 = AesBlock::from_bytes(&C1);

        // for i in 0..D:
        //     V[0,i] = key ^ nonce
        //     V[1,i] = C1
        //     V[2,i] = C0
        //     V[3,i] = C1
        //     V[4,i] = key ^ nonce
        //     V[5,i] = key ^ C0
        //     V[6,i] = key ^ C1
        //     V[7,i] = key ^ C0
        let mut v = Self(Array::from_fn(|_| {
            State128L(
                key ^ nonce,
                c1,
                c0,
                c1,
                key ^ nonce,
                key ^ c0,
                key ^ c1,
                key ^ c0,
            )
        }));

        // nonce_v = {}
        // key_v = {}
        // for i in 0..D:
        //     nonce_v = nonce_v || nonce
        //     key_v = key_v || key
        let nonce_v = Array::from_fn(|_| nonce);
        let key_v = Array::from_fn(|_| key);

        // for i in 0..D:
        //     ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128)
        let ctx = ctx::<D>();

        // Repeat(10,
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[7,i] = V[7,i] ^ ctx[i]

        //     Update(nonce_v, key_v)
        // )
        for _ in 0..10 {
            for i in 0..D::USIZE {
                v.0[i].3 ^= ctx[i];
                v.0[i].7 ^= ctx[i];
            }
            v.update(nonce_v.clone(), key_v.clone());
        }

        v
    }

    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, D::Aegis128BlockSize>>) {
        // z0 = {}
        // z1 = {}
        // for i in 0..D:
        //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
        //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))
        //
        // t0, t1 = Split(xi, R)
        // out0 = t0 ^ z0
        // out1 = t1 ^ z1
        //
        // Update(t0, t1)
        // ci = out0 || out1

        let blockbuf = block.into_buf();

        let (mut chunks, _) = blockbuf.into_chunks::<U16>();

        let t0 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i).get_in().0));
        let t1 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i + D::USIZE).get_in().0));

        for i in 0..D::USIZE {
            let s = &self.0[i];

            let z0 = s.6 ^ s.1 ^ (s.2 & s.3);
            let z1 = s.2 ^ s.5 ^ (s.6 & s.7);

            // hopefully this auto-vectorises and doesn't have to move z0 and z1 out
            // of the simd registers.
            chunks.get(i).xor_in2out(&Array(z0.into_bytes()));
            chunks.get(i + D::USIZE).xor_in2out(&Array(z1.into_bytes()));
        }

        self.update(t0, t1);
    }

    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, D::Aegis128BlockSize>>) {
        // z0 = {}
        // z1 = {}
        // for i in 0..D:
        //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
        //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))

        // t0, t1 = Split(ci, R)
        // out0 = t0 ^ z0
        // out1 = t1 ^ z1

        // Update(out0, out1)
        // xi = out0 || out1

        let blockbuf = block.into_buf();

        let (mut chunks, _) = blockbuf.into_chunks::<U16>();

        for i in 0..D::USIZE {
            let s = &self.0[i];

            let z0 = s.6 ^ s.1 ^ (s.2 & s.3);
            let z1 = s.2 ^ s.5 ^ (s.6 & s.7);

            // hopefully this auto-vectorises and doesn't have to move z0 and z1 out
            // of the simd registers.
            chunks.get(i).xor_in2out(&Array(z0.into_bytes()));
            chunks.get(i + D::USIZE).xor_in2out(&Array(z1.into_bytes()));
        }

        let t0 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i).get_out().0));
        let t1 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i + D::USIZE).get_out().0));
        self.update(t0, t1);
    }

    fn decrypt_partial(&mut self, mut tail: InOutBuf<'_, '_, u8>) {
        let len = tail.len();
        let mut msg_chunk = Array::default();
        msg_chunk[..len].copy_from_slice(tail.get_in());
        self.decrypt_partial_block(InOut::from(&mut msg_chunk), len);
        tail.get_out().copy_from_slice(&msg_chunk[..len]);
    }

    fn decrypt_partial_block(
        &mut self,
        block: InOut<'_, '_, Array<u8, D::Aegis128BlockSize>>,
        len: usize,
    ) {
        // z0 = {}
        // z1 = {}
        // for i in 0..D:
        //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
        //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))

        // t0, t1 = Split(ci, R)
        // out0 = t0 ^ z0
        // out1 = t1 ^ z1

        // Update(out0, out1)
        // xi = out0 || out1

        let mut blockbuf = block.into_buf();
        let (mut chunks, _) = blockbuf.reborrow().into_chunks::<U16>();

        for i in 0..D::USIZE {
            let s = &self.0[i];

            let z0 = s.6 ^ s.1 ^ (s.2 & s.3);
            let z1 = s.2 ^ s.5 ^ (s.6 & s.7);

            // hopefully this auto-vectorises and doesn't have to move z0 and z1 out
            // of the simd registers.
            chunks.get(i).xor_in2out(&Array(z0.into_bytes()));
            chunks.get(i + D::USIZE).xor_in2out(&Array(z1.into_bytes()));
        }

        blockbuf.get_out()[len..].fill(0);
        let (mut chunks, _) = blockbuf.reborrow().into_chunks::<U16>();

        let t0 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i).get_out().0));
        let t1 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i + D::USIZE).get_out().0));
        self.update(t0, t1);
    }

    fn finalize(mut self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, TagSize> {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let u = concatu64(ad_len_bits, msg_len_bits);

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = Array::from_fn(|i| self.0[i].2 ^ u);

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update(t.clone(), t.clone());
        }

        // if tag_len_bits == 128:
        //     tag = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]
        //         tag = tag ^ ti
        let tag = self
            .0
            .into_iter()
            .fold(AesBlock::default(), |tag, s| tag ^ s.fold_tag());

        Array(tag.into_bytes())

        // else:            # 256 bits
        //     ti0 = ZeroPad({}, 128)
        //     ti1 = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
        //         ti1 = ti1 ^ V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
        //     tag = ti0 || ti1
    }

    fn finalize_mac(mut self, data_len_bits: u64, tag_len_bits: u64) -> Array<u8, TagSize> {
        // t = {}
        // u = LE64(data_len_bits) || LE64(tag_len_bits)
        let u = concatu64(data_len_bits, tag_len_bits);

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = Array::from_fn(|i| self.0[i].2 ^ u);

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update(t.clone(), t.clone());
        }

        if D::USIZE > 1 {
            fn zeropad<D: AegisParallel>(x: AesBlock) -> Array<AesBlock, D> {
                let mut t = Array::default();
                t[0] = x;
                t
            }

            // if tag_len_bits == 128:
            //     for i in 0..D: # tag from state 0 is included
            //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]
            //         tags = tags || ti
            // else:              # 256 bits
            //     for i in 1..D: # tag from state 0 is skipped
            //         ti0 = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
            //         ti1 = V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
            //         tags = tags || (ti0 || ti1)
            // TODO: support 256 bit tags
            let tags = self.0.clone().map(|s| s.fold_tag());

            // # Absorb tags into state 0; other states are not used anymore
            // for v in Split(tags, 256):
            //     x0, x1 = Split(v, 128)
            //     Absorb(ZeroPad(x0, R / 2) || ZeroPad(x1, R / 2))
            let mut tags = &*tags;
            loop {
                let Some(([x0, x1], rest)) = tags.split_first_chunk() else {
                    break;
                };
                tags = rest;

                self.update(zeropad(*x0), zeropad(*x1));
            }

            // u = LE64(D) || LE64(tag_len_bits)
            let u = concatu64(D::U64, tag_len_bits);

            // t = ZeroPad(V[2,0] ^ u, R)
            let t = zeropad(self.0[0].2 ^ u);

            // Repeat(7, Update(t, t))
            for _ in 0..7 {
                self.update(t.clone(), t.clone());
            }
        }

        // if tag_len_bits == 128:
        //     tag = V[0,0] ^ V[1,0] ^ V[2,0] ^ V[3,0] ^ V[4,0] ^ V[5,0] ^ V[6,0]
        // else:            # 256 bits
        //     t0 = V[0,0] ^ V[1,0] ^ V[2,0] ^ V[3,0]
        //     t1 = V[4,0] ^ V[5,0] ^ V[6,0] ^ V[7,0]
        //     tag = t0 || t1
        // TODO: support 256 bit tags
        let tag = self.0[0].fold_tag();

        Array(tag.into_bytes())
    }

    fn absorb(&mut self, ad: &Array<u8, D::Aegis128BlockSize>) {
        let (t0, t1) = split(ad);
        self.update(t0, t1);
    }

    fn update(&mut self, m0: Array<AesBlock, D>, m1: Array<AesBlock, D>) {
        let mut out = self.clone();

        macro_rules! d {
            ($s:ident, $m:pat, $o:ident => $e:expr) => {
                for i in 0..D::USIZE {
                    let $m = &(m0[i], m1[i]);
                    let $s = &self.0[i];
                    let $o = &mut out.0[i];
                    { $e }
                }
            };
        }

        // for i in 0..D:
        //     V'[0,i] = AESRound(V[7,i], V[0,i] ^ m0[i])
        //     V'[1,i] = AESRound(V[0,i], V[1,i])
        //     V'[2,i] = AESRound(V[1,i], V[2,i])
        //     V'[3,i] = AESRound(V[2,i], V[3,i])
        //     V'[4,i] = AESRound(V[3,i], V[4,i] ^ m1[i])
        //     V'[5,i] = AESRound(V[4,i], V[5,i])
        //     V'[6,i] = AESRound(V[5,i], V[6,i])
        //     V'[7,i] = AESRound(V[6,i], V[7,i])

        d!(s,m,o => o.0 = s.7.aes(s.0 ^ m.0));
        d!(s,_,o => o.1 = s.0.aes(s.1));
        d!(s,_,o => o.2 = s.1.aes(s.2));
        d!(s,_,o => o.3 = s.2.aes(s.3));
        d!(s,m,o => o.4 = s.3.aes(s.4 ^ m.1));
        d!(s,_,o => o.5 = s.4.aes(s.5));
        d!(s,_,o => o.6 = s.5.aes(s.6));
        d!(s,_,o => o.7 = s.6.aes(s.7));

        *self = out;
    }
}

fn concatu64(x: u64, y: u64) -> AesBlock {
    let mut u = [0; 16];
    u[..8].copy_from_slice(&x.to_le_bytes());
    u[8..].copy_from_slice(&y.to_le_bytes());
    AesBlock::from_bytes(&u)
}

fn split<D>(block: &Array<u8, D::Aegis128BlockSize>) -> (Array<AesBlock, D>, Array<AesBlock, D>)
where
    D: AegisParallel,
{
    let (chunks, tail) = Array::<u8, U16>::slice_as_chunks(block);
    assert!(tail.is_empty());

    (
        Array::from_fn(|i| AesBlock::from_bytes(&chunks[i].0)),
        Array::from_fn(|i| AesBlock::from_bytes(&chunks[i + D::USIZE].0)),
    )
}

#[derive(Clone, Copy)]
struct State128L(
    AesBlock,
    AesBlock,
    AesBlock,
    AesBlock,
    AesBlock,
    AesBlock,
    AesBlock,
    AesBlock,
);

impl State128L {
    fn fold_tag(self) -> AesBlock {
        self.0 ^ self.1 ^ self.2 ^ self.3 ^ self.4 ^ self.5 ^ self.6 // not self.7?
    }
}

#[cfg(test)]
mod tests {
    use aead::{Aead, AeadInOut, Key, KeyInit, Nonce, Payload, Tag, consts::U1, inout::InOutBuf};
    use hex_literal::hex;
    use hybrid_array::Array;

    use crate::{Aegis128X, AegisParallel, aarch64::AesBlock};

    use super::{Aegis128L, State128L, State128X};

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.1>
    #[test]
    fn update() {
        let mut s: State128X<U1> = State128X(Array([State128L(
            AesBlock::from_bytes(&hex!("9b7e60b24cc873ea894ecc07911049a3")),
            AesBlock::from_bytes(&hex!("330be08f35300faa2ebf9a7b0d274658")),
            AesBlock::from_bytes(&hex!("7bbd5bd2b049f7b9b515cf26fbe7756c")),
            AesBlock::from_bytes(&hex!("c35a00f55ea86c3886ec5e928f87db18")),
            AesBlock::from_bytes(&hex!("9ebccafce87cab446396c4334592c91f")),
            AesBlock::from_bytes(&hex!("58d83e31f256371e60fc6bb257114601")),
            AesBlock::from_bytes(&hex!("1639b56ea322c88568a176585bc915de")),
            AesBlock::from_bytes(&hex!("640818ffb57dc0fbc2e72ae93457e39a")),
        )]));

        let m0 = Array([AesBlock::from_bytes(&hex!(
            "033e6975b94816879e42917650955aa0"
        ))]);
        let m1 = Array([AesBlock::from_bytes(&hex!(
            "fcc1968a46b7e97861bd6e89af6aa55f"
        ))]);

        s.update(m0, m1);
        let State128X(Array([s])) = s;

        assert_eq!(s.0.into_bytes(), hex!("596ab773e4433ca0127c73f60536769d"));
        assert_eq!(s.1.into_bytes(), hex!("790394041a3d26ab697bde865014652d"));
        assert_eq!(s.2.into_bytes(), hex!("38cf49e4b65248acd533041b64dd0611"));
        assert_eq!(s.3.into_bytes(), hex!("16d8e58748f437bfff1797f780337cee"));
        assert_eq!(s.4.into_bytes(), hex!("9689ecdf08228c74d7e3360cca53d0a5"));
        assert_eq!(s.5.into_bytes(), hex!("a21746bb193a569e331e1aa985d0d729"));
        assert_eq!(s.6.into_bytes(), hex!("09d714e6fcf9177a8ed1cde7e3d259a6"));
        assert_eq!(s.7.into_bytes(), hex!("61279ba73167f0ab76f0a11bf203bdff"));
    }

    fn test_roundtrip<D: AegisParallel>(
        key: Key<Aegis128L>,
        nonce: Nonce<Aegis128L>,
        aad: &[u8],
        msg: &[u8],
        ct: &[u8],
        tag128: Tag<Aegis128L>,
    ) {
        let encrypted = Aegis128X::<D>::new(&key)
            .encrypt(&nonce, Payload { aad, msg })
            .unwrap();

        let (actual_ct, actual_tag) = encrypted.split_last_chunk().unwrap();
        assert_eq!(actual_ct, ct);
        assert_eq!(actual_tag, &tag128.0);

        let decrypted = Aegis128X::<D>::new(&key)
            .decrypt(
                &nonce,
                Payload {
                    aad,
                    msg: &encrypted,
                },
            )
            .unwrap();

        assert_eq!(decrypted, msg);
    }

    fn test_decrypt_fail<D: AegisParallel>(
        key: Key<Aegis128L>,
        nonce: Nonce<Aegis128L>,
        aad: &[u8],
        ct: &[u8],
        tag128: Tag<Aegis128L>,
    ) {
        let mut buf = ct.to_vec();
        Aegis128X::<D>::new(&key)
            .decrypt_inout_detached(&nonce, aad, InOutBuf::from(&mut *buf), &tag128)
            .unwrap_err();

        assert_eq!(buf, ct, "plaintext was cleared");
    }

    mod aegis128l {
        use hex_literal::hex;
        use hybrid_array::Array;
        use hybrid_array::sizes::U1;

        use super::{test_decrypt_fail, test_roundtrip};

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.2>
        fn test_vector_1() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("");
            let msg = hex!("00000000000000000000000000000000");
            let ct = hex!("c1c0e58bd913006feba00f4b3cc3594e");
            let tag128 = Array(hex!("abe0ece80c24868a226a35d16bdae37a"));
            // tag256: 25835bfbb21632176cf03840687cb968
            //         cace4617af1bd0f7d064c639a5c79ee4

            test_roundtrip::<U1>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.3>
        fn test_vector_2() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("");
            let msg = hex!("");
            let ct = hex!("");
            let tag128 = Array(hex!("c2b879a67def9d74e6c14f708bbcc9b4"));
            // tag256: 1360dc9db8ae42455f6e5b6a9d488ea4
            //         f2184c4e12120249335c4ee84bafe25d

            test_roundtrip::<U1>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.4>
        fn test_vector_3() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("0001020304050607");
            let msg = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            );
            let ct = hex!(
                "79d94593d8c2119d7e8fd9b8fc77845c"
                "5c077a05b2528b6ac54b563aed8efe84"
            );
            let tag128 = Array(hex!("cc6f3372f6aa1bb82388d695c3962d9a"));
            // tag256: 022cb796fe7e0ae1197525ff67e30948
            //         4cfbab6528ddef89f17d74ef8ecd82b3

            test_roundtrip::<U1>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.5>
        fn test_vector_4() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("0001020304050607");
            let msg = hex!("000102030405060708090a0b0c0d");
            let ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
            let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac

            test_roundtrip::<U1>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.6>
        fn test_vector_5() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "20212223242526272829"
            );
            let msg = hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "3031323334353637"
            );
            let ct = hex!(
                "b31052ad1cca4e291abcf2df3502e6bd"
                "b1bfd6db36798be3607b1f94d34478aa"
                "7ede7f7a990fec10"
            );
            let tag128 = Array(hex!("7542a745733014f9474417b337399507"));
            // tag256: b91e2947a33da8bee89b6794e647baf0
            //         fc835ff574aca3fc27c33be0db2aff98

            test_roundtrip::<U1>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.7>
        fn test_vector_6() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!("10000200000000000000000000000000"));
            let nonce = Array(hex!("10010000000000000000000000000000"));
            let ad = hex!("0001020304050607");
            let ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
            let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac
            test_decrypt_fail::<U1>(key, nonce, &ad, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.8>
        fn test_vector_7() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("0001020304050607");
            let ct = hex!("79d94593d8c2119d7e8fd9b8fc78");
            let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac

            test_decrypt_fail::<U1>(key, nonce, &ad, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.9>
        fn test_vector_8() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("0001020304050608");
            let ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
            let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac

            test_decrypt_fail::<U1>(key, nonce, &ad, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.10>
        fn test_vector_9() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!("10010000000000000000000000000000"));
            let nonce = Array(hex!("10000200000000000000000000000000"));
            let ad = hex!("0001020304050607");
            let ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
            let tag128 = Array(hex!("6c04b3dba849b2701effbe32c7f0fab8"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ad

            test_decrypt_fail::<U1>(key, nonce, &ad, &ct, tag128);
        }
    }

    mod aegis128x2 {
        use hex_literal::hex;
        use hybrid_array::Array;
        use hybrid_array::sizes::U2;

        use crate::aegis128::State128X;

        use super::test_roundtrip;

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.4.1>
        #[rustfmt::skip]
        fn initialisation() {
            let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
            let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));

            let State128X(Array(v)) = State128X::<U2>::new(&key, &nonce);

            assert_eq!(v[0].0.into_bytes(), hex!("a4fc1ad9a72942fb88bd2cabbba6509a"));
            assert_eq!(v[1].0.into_bytes(), hex!("80a40e392fc71084209b6c3319bdc6cc"));

            assert_eq!(v[0].1.into_bytes(), hex!("380f435cf801763b1f0c2a2f7212052d"));
            assert_eq!(v[1].1.into_bytes(), hex!("73796607b59b1b650ee91c152af1f18a"));
            
            assert_eq!(v[0].2.into_bytes(), hex!("6ee1de433ea877fa33bc0782abff2dcb"));
            assert_eq!(v[1].2.into_bytes(), hex!("b9fab2ab496e16d1facaffd5453cbf14"));
            
            assert_eq!(v[0].3.into_bytes(), hex!("85f94b0d4263bfa86fdf45a603d8b6ac"));
            assert_eq!(v[1].3.into_bytes(), hex!("90356c8cadbaa2c969001da02e3feca0"));

            assert_eq!(v[0].4.into_bytes(), hex!("09bd69ad3730174bcd2ce9a27cd1357e"));
            assert_eq!(v[1].4.into_bytes(), hex!("e610b45125796a4fcf1708cef5c4f718"));
            
            assert_eq!(v[0].5.into_bytes(), hex!("fcdeb0cf0a87bf442fc82383ddb0f6d6"));
            assert_eq!(v[1].5.into_bytes(), hex!("61ad32a4694d6f3cca313a2d3f4687aa"));
            
            assert_eq!(v[0].6.into_bytes(), hex!("571c207988659e2cdfbdaae77f4f37e3"));
            assert_eq!(v[1].6.into_bytes(), hex!("32e6094e217573bf91fb28c145a3efa8"));
            
            assert_eq!(v[0].7.into_bytes(), hex!("ca549badf8faa58222412478598651cf"));
            assert_eq!(v[1].7.into_bytes(), hex!("3407279a54ce76d2e2e8a90ec5d108eb"));
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.4.2>
        fn test_vector_1() {
            let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
            let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));
            let ad = hex!("");
            let msg = hex!("");
            let ct = hex!("");
            let tag128 = Array(hex!("63117dc57756e402819a82e13eca8379"));
            // tag256: b92c71fdbd358b8a4de70b27631ace90
            //         cffd9b9cfba82028412bac41b4f53759

            test_roundtrip::<U2>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.4.3>
        fn test_vector_2() {
            let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
            let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));
            let ad = hex!("0102030401020304");
            let msg = hex!(
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "0405060704050607"
            );
            let ct = hex!(
                "5795544301997f93621b278809d6331b"
                "3bfa6f18e90db12c4aa35965b5e98c5f"
                "c6fb4e54bcb6111842c20637252eff74"
                "7cb3a8f85b37de80919a589fe0f24872"
                "bc926360696739e05520647e390989e1"
                "eb5fd42f99678a0276a498f8c454761c"
                "9d6aacb647ad56be62b29c22cd4b5761"
                "b38f43d5a5ee062f"
            );
            let tag128 = Array(hex!("1aebc200804f405cab637f2adebb6d77"));
            // tag256: c471876f9b4978c44f2ae1ce770cdb11
            //         a094ee3feca64e7afcd48bfe52c60eca

            test_roundtrip::<U2>(key, nonce, &ad, &msg, &ct, tag128);
        }
    }

    mod aegis128x4 {
        use hex_literal::hex;
        use hybrid_array::Array;
        use hybrid_array::sizes::U4;

        use crate::aegis128::State128X;

        use super::test_roundtrip;

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.5.1>
        #[rustfmt::skip]
        fn initialisation() {
            let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
            let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));

            let State128X(Array(v)) = State128X::<U4>::new(&key, &nonce);

            assert_eq!(v[0].0.into_bytes(), hex!("924eb07635003a37e6c6575ba8ce1929"));
            assert_eq!(v[1].0.into_bytes(), hex!("c8b6a5d91475445e936d48e794be0ce2"));
            assert_eq!(v[2].0.into_bytes(), hex!("fcd37d050e24084befe3bbb219d64760"));
            assert_eq!(v[3].0.into_bytes(), hex!("2e9f58cfb893a8800220242c373a8b18"));
            
            assert_eq!(v[0].1.into_bytes(), hex!("1a1f60c4fab64e5471dc72edfcf6fe6b"));
            assert_eq!(v[1].1.into_bytes(), hex!("c1e525ebea2d6375a9edd045dce96381"));
            assert_eq!(v[2].1.into_bytes(), hex!("97a3e25abd228a44d4a14a6d3fe9185c"));
            assert_eq!(v[3].1.into_bytes(), hex!("c2d4cf7f4287a98744645674265d4ca8"));
            
            assert_eq!(v[0].2.into_bytes(), hex!("7bb50c534f6ec4780530ff1cce8a16e8"));
            assert_eq!(v[1].2.into_bytes(), hex!("7b08d57557da0b5ef7b5f7d98b0ba189"));
            assert_eq!(v[2].2.into_bytes(), hex!("6bfcac34ddb68404821a4d665303cb0f"));
            assert_eq!(v[3].2.into_bytes(), hex!("d95626f6dfad1aed7467622c38529932"));
            
            assert_eq!(v[0].3.into_bytes(), hex!("af339fd2d50ee45fc47665c647cf6586"));
            assert_eq!(v[1].3.into_bytes(), hex!("d0669b39d140f0e118a4a511efe2f95a"));
            assert_eq!(v[2].3.into_bytes(), hex!("7a94330f35c194fadda2a87e42cdeccc"));
            assert_eq!(v[3].3.into_bytes(), hex!("233b640d1f4d56e2757e72c1a9d8ecb1"));
            
            assert_eq!(v[0].4.into_bytes(), hex!("9f93737d699ba05c11e94f2b201bef5e"));
            assert_eq!(v[1].4.into_bytes(), hex!("61caf387cf7cfd3f8300ac7680ccfd76"));
            assert_eq!(v[2].4.into_bytes(), hex!("5825a671ecef03b7a9c98a601ae32115"));
            assert_eq!(v[3].4.into_bytes(), hex!("87a1fe4d558161a8f4c38731f3223032"));
            
            assert_eq!(v[0].5.into_bytes(), hex!("7a5aca78d636c05bbc702b2980196ab6"));
            assert_eq!(v[1].5.into_bytes(), hex!("915d868408495d07eb527789f282c575"));
            assert_eq!(v[2].5.into_bytes(), hex!("d0947bfbc1d3309cdffc9be1503aea62"));
            assert_eq!(v[3].5.into_bytes(), hex!("8834ea57a15b9fbdc0245464a4b8cbef"));
            
            assert_eq!(v[0].6.into_bytes(), hex!("e46f4cf71a95ac45b6f0823e3aba1a86"));
            assert_eq!(v[1].6.into_bytes(), hex!("8c4ecef682fc44a8eba911b3fc7d99f9"));
            assert_eq!(v[2].6.into_bytes(), hex!("a4fb61e2c928a2ca760b8772f2ea5f2e"));
            assert_eq!(v[3].6.into_bytes(), hex!("3d34ea89da73caa3016c280500a155a3"));
            
            assert_eq!(v[0].7.into_bytes(), hex!("85075f0080e9d618e7eb40f57c32d9f7"));
            assert_eq!(v[1].7.into_bytes(), hex!("d2ab2b320c6e93b155a3787cb83e5281"));
            assert_eq!(v[2].7.into_bytes(), hex!("0b3af0250ae36831a1b072e499929bcb"));
            assert_eq!(v[3].7.into_bytes(), hex!("5cce4d00329d69f1aae36aa541347512"));
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.5.2>
        fn test_vector_1() {
            let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
            let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));
            let ad = hex!("");
            let msg = hex!("");
            let ct = hex!("");
            let tag128 = Array(hex!("5bef762d0947c00455b97bb3af30dfa3"));
            // tag256: a4b25437f4be93cfa856a2f27e4416b4
            //         2cac79fd4698f2cdbe6af25673e10a68

            test_roundtrip::<U4>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.5.3>
        fn test_vector_2() {
            let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
            let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));
            let ad = hex!("0102030401020304");
            let msg = hex!(
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "04050607040506070405060704050607"
                "0405060704050607"
            );
            let ct = hex!(
                "e836118562f4479c9d35c17356a83311"
                "4c21f9aa39e4dda5e5c87f4152a00fce"
                "9a7c38f832eafe8b1c12f8a7cf12a81a"
                "1ad8a9c24ba9dedfbdaa586ffea67ddc"
                "801ea97d9ab4a872f42d0e352e2713da"
                "cd609f9442c17517c5a29daf3e2a3fac"
                "4ff6b1380c4e46df7b086af6ce6bc1ed"
                "594b8dd64aed2a7e"
            );
            let tag128 = Array(hex!("0e56ab94e2e85db80f9d54010caabfb4"));
            // tag256: 69abf0f64a137dd6e122478d777e98bc
            //         422823006cf57f5ee822dd78397230b2

            test_roundtrip::<U4>(key, nonce, &ad, &msg, &ct, tag128);
        }
    }
}
