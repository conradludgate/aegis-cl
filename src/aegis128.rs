use std::{
    marker::PhantomData,
    ops::{Mul, Sub},
};

use aead::{
    AeadCore, AeadInOut, Key, KeyInit, KeySizeUser, Nonce,
    inout::{InOut, InOutBuf},
};
use hybrid_array::{
    Array, ArraySize,
    sizes::{U1, U16, U32},
    typenum::Prod,
};
use subtle::ConstantTimeEq;

use crate::{
    C0, C1,
    aarch64::AesBlock,
    util::{self, ctx, zero_pad},
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

fn bits(bytes: usize) -> aead::Result<u64> {
    u64::try_from(bytes)
        .ok()
        .and_then(|b| b.checked_mul(8))
        .ok_or(aead::Error)
}

impl<D: ArraySize> AeadInOut for Aegis128X<D>
where
    D: Mul<U32>,
    Prod<D, U32>: ArraySize,
    // D: Mul<U16>,
    // Prod<D, U16>: ArraySize,
{
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
        let msg_len_bits = bits(buffer.len())?;
        let ad_len_bits = bits(associated_data.len())?;

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
            // let len = msg_tail.len();
            // let mut msg_chunk = Array::default();
            // msg_chunk[..len].copy_from_slice(msg_tail.get_in());
            // f(InOut::from(&mut msg_chunk));
            // msg_tail.get_out().copy_from_slice(&msg_chunk[..len]);
        }

        // util::process_inout_chunks_padded(buffer.reborrow(), |msg_chunk| {
        //     // do I need to handle partial decrypt properly :think:
        //     state.decrypt_block(msg_chunk);
        // });

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

#[derive(Clone)]
pub struct State128X<D: ArraySize>(Array<State128L, D>);

impl<D: ArraySize> State128X<D>
where
    D: Mul<U32>,
    Prod<D, U32>: ArraySize,
    // D: Mul<U16>,
    // Prod<D, U16>: ArraySize,
    // Prod<D, U32>: Sub<Prod<D, U16>, Output = Prod<D, U16>>,
{
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

    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Prod<D, U32>>>) {
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

    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, Prod<D, U32>>>) {
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

    fn decrypt_partial_block(&mut self, block: InOut<'_, '_, Array<u8, Prod<D, U32>>>, len: usize) {
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

    // fn decrypt_partial(&mut self, block: InOutBuf<'_, '_, u8>) {
    //     // // z0 = {}
    //     // // z1 = {}
    //     // // for i in 0..D:
    //     // //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
    //     // //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))
    //     // let z0 = self.0.clone().map(|s| s.6 ^ s.1 ^ (s.2 & s.3));
    //     // let z1 = self.0.clone().map(|s| s.2 ^ s.5 ^ (s.6 & s.7));

    //     // // t0, t1 = Split(ZeroPad(cn, R), 128 * D)
    //     // let (t0, t1) = split::<D>(&zero_pad(block.get_in()));

    //     // // out0 = t0 ^ z0
    //     // // out1 = t1 ^ z1
    //     // let out0 = Array::<Array<u8, U16>, D>::from_fn(|i| Array((t0[i] ^ z0[i]).into_bytes()));
    //     // let out1 = Array::<Array<u8, U16>, D>::from_fn(|i| Array((t1[i] ^ z1[i]).into_bytes()));

    //     // // xn = Truncate(out0 || out1, |cn|)
    //     // // v0, v1 = Split(ZeroPad(xn, R), 128 * D)
    //     // let mut xn = Array::default();
    //     // xn[..16].copy_from_slice(&out0);
    //     // xn[16..].copy_from_slice(&out1);
    //     // xn[block.len()..].fill(0);

    //     // // Update(v0, v1)
    //     // let (v0, v1) = split::<D>(xn);
    //     // self.update(v0, v1);

    //     // return xn

    //     let mut block2 = zero_pad::<Prod<D, U32>>(block.get_in());
    //     let blockbuf = InOut::from(&mut block2).into_buf();

    //     let (mut chunks, _) = blockbuf.into_chunks::<U16>();

    //     for i in 0..D::USIZE {
    //         let s = &self.0[i];

    //         let z0 = s.6 ^ s.1 ^ (s.2 & s.3);
    //         let z1 = s.2 ^ s.5 ^ (s.6 & s.7);

    //         // hopefully this auto-vectorises and doesn't have to move z0 and z1 out
    //         // of the simd registers.
    //         chunks.get(i).xor_in2out(&Array(z0.into_bytes()));
    //         chunks.get(i + D::USIZE).xor_in2out(&Array(z1.into_bytes()));
    //     }

    //     let t0 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i).get_out().0));
    //     let t1 = Array::from_fn(|i| AesBlock::from_bytes(&chunks.get(i + D::USIZE).get_out().0));
    //     self.update(t0, t1);
    // }

    fn finalize(mut self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, TagSize> {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let mut u = [0; 16];
        u[..8].copy_from_slice(&ad_len_bits.to_le_bytes());
        u[8..].copy_from_slice(&msg_len_bits.to_le_bytes());
        let u = AesBlock::from_bytes(&u);

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
            .fold(AesBlock::default(), |tag, s| tag ^ s.fold());

        Array(tag.into_bytes())

        // else:            # 256 bits
        //     ti0 = ZeroPad({}, 128)
        //     ti1 = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
        //         ti1 = ti1 ^ V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
        //     tag = ti0 || ti1
    }

    fn absorb(&mut self, ad: &Array<u8, Prod<D, U32>>)
    where
        D: Mul<U32>,
        Prod<D, U32>: ArraySize,
    {
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

fn split<D>(block: &Array<u8, Prod<D, U32>>) -> (Array<AesBlock, D>, Array<AesBlock, D>)
where
    D: ArraySize,
    D: Mul<U32>,
    Prod<D, U32>: ArraySize,
{
    let (chunks, tail) = Array::<u8, U16>::slice_as_chunks(&block);
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
    fn fold(self) -> AesBlock {
        self.0 ^ self.1 ^ self.2 ^ self.3 ^ self.4 ^ self.5 ^ self.6 // not self.7?
    }
}

#[cfg(test)]
mod tests {
    use aead::{Aead, Key, KeyInit, Nonce, Payload, Tag, consts::U1};
    use hex_literal::hex;
    use hybrid_array::Array;

    use crate::aarch64::AesBlock;

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

    fn test_encrypt(
        key: Key<Aegis128L>,
        nonce: Nonce<Aegis128L>,
        aad: &[u8],
        msg: &[u8],
        ct: &[u8],
        tag128: Tag<Aegis128L>,
    ) {
        let encrypted = Aegis128L::new(&key)
            .encrypt(&nonce, Payload { aad, msg })
            .unwrap();

        let (actual_ct, actual_tag) = encrypted.split_last_chunk().unwrap();
        assert_eq!(actual_ct, ct);
        assert_eq!(actual_tag, &tag128.0);

        let decrypted = Aegis128L::new(&key)
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

    #[test]
    fn test_vector_1() {
        let key = Array(hex!("10010000000000000000000000000000"));
        let nonce = Array(hex!("10000200000000000000000000000000"));
        let ad = hex!("");
        let msg = hex!("00000000000000000000000000000000");
        let ct = hex!("c1c0e58bd913006feba00f4b3cc3594e");
        let tag128 = Array(hex!("abe0ece80c24868a226a35d16bdae37a"));
        // tag256: 25835bfbb21632176cf03840687cb968
        //         cace4617af1bd0f7d064c639a5c79ee4

        test_encrypt(key, nonce, &ad, &msg, &ct, tag128);
    }

    #[test]
    fn test_vector_2() {
        let key = Array(hex!("10010000000000000000000000000000"));
        let nonce = Array(hex!("10000200000000000000000000000000"));
        let ad = hex!("");
        let msg = hex!("");
        let ct = hex!("");
        let tag128 = Array(hex!("c2b879a67def9d74e6c14f708bbcc9b4"));
        // tag256: 1360dc9db8ae42455f6e5b6a9d488ea4
        //         f2184c4e12120249335c4ee84bafe25d

        test_encrypt(key, nonce, &ad, &msg, &ct, tag128);
    }

    #[test]
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

        test_encrypt(key, nonce, &ad, &msg, &ct, tag128);
    }

    #[test]
    fn test_vector_4() {
        let key = Array(hex!("10010000000000000000000000000000"));
        let nonce = Array(hex!("10000200000000000000000000000000"));
        let ad = hex!("0001020304050607");
        let msg = hex!("000102030405060708090a0b0c0d");
        let ct = hex!("79d94593d8c2119d7e8fd9b8fc77");
        let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
        // tag256: 86f1b80bfb463aba711d15405d094baf
        //         4a55a15dbfec81a76f35ed0b9c8b04ac

        test_encrypt(key, nonce, &ad, &msg, &ct, tag128);
    }

    #[test]
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

        test_encrypt(key, nonce, &ad, &msg, &ct, tag128);
    }

    // #[test]
    // fn test_vector_6() {
    //     // This test MUST return a “verification failed” error.
    //     let key = Array(hex!("10000200000000000000000000000000"));
    //     let nonce = Array(hex!("10010000000000000000000000000000"));
    //     let ad = hex!("0001020304050607");
    //     // ct    : 79d94593d8c2119d7e8fd9b8fc77
    //     let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
    //     // tag256: 86f1b80bfb463aba711d15405d094baf
    //     //         4a55a15dbfec81a76f35ed0b9c8b04ac

    // Aegis128L::new(&key).encrypt_inout_detached(&nonce, ad, InOutBuf::from_mut(&mut msg));
    // }

    // #[test]
    // fn test_vector_7() {
    //     // This test MUST return a “verification failed” error.
    //     let key = Array(hex!("10010000000000000000000000000000"));
    //     let nonce = Array(hex!("10000200000000000000000000000000"));
    //     let ad = hex!("0001020304050607");
    //     // ct    : 79d94593d8c2119d7e8fd9b8fc78
    //     let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
    //     // tag256: 86f1b80bfb463aba711d15405d094baf
    //     //         4a55a15dbfec81a76f35ed0b9c8b04ac

    // Aegis128L::new(&key).encrypt_inout_detached(&nonce, ad, InOutBuf::from_mut(&mut msg));
    // }

    // #[test]
    // fn test_vector_8() {
    //     // This test MUST return a “verification failed” error.
    //     let key = Array(hex!("10010000000000000000000000000000"));
    //     let nonce = Array(hex!("10000200000000000000000000000000"));
    //     let ad = hex!("0001020304050608");
    //     // ct    : 79d94593d8c2119d7e8fd9b8fc77
    //     let tag128 = Array(hex!("5c04b3dba849b2701effbe32c7f0fab7"));
    //     // tag256: 86f1b80bfb463aba711d15405d094baf
    //     //         4a55a15dbfec81a76f35ed0b9c8b04ac

    // Aegis128L::new(&key).encrypt_inout_detached(&nonce, ad, InOutBuf::from_mut(&mut msg));
    // }

    // #[test]
    // fn test_vector_9() {
    //     // This test MUST return a “verification failed” error.
    //     let key = Array(hex!("10010000000000000000000000000000"));
    //     let nonce = Array(hex!("10000200000000000000000000000000"));
    //     let ad = hex!("0001020304050607");
    //     // ct    : 79d94593d8c2119d7e8fd9b8fc77
    //     let tag128 = Array(hex!("6c04b3dba849b2701effbe32c7f0fab8"));
    //     // tag256: 86f1b80bfb463aba711d15405d094baf
    //     //         4a55a15dbfec81a76f35ed0b9c8b04ad

    // Aegis128L::new(&key).encrypt_inout_detached(&nonce, ad, InOutBuf::from_mut(&mut msg));
    // }
}
