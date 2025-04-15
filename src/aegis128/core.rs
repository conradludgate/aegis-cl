use crate::{AegisParallel, C0, C1, aarch64::AesBlock, util::ctx};
use aead::inout::{InOut, InOutBuf};
use hybrid_array::{Array, sizes::U16};

use super::TagSize;

#[derive(Clone)]
pub struct State128X<D: AegisParallel>(Array<State128L, D>);

impl<D: AegisParallel> State128X<D> {
    pub fn new(key: &Array<u8, U16>, iv: &Array<u8, U16>) -> Self {
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

    pub fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, D::Aegis128BlockSize>>) {
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

    pub fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, D::Aegis128BlockSize>>) {
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

    pub fn decrypt_partial(&mut self, mut tail: InOutBuf<'_, '_, u8>) {
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

    pub fn finalize(mut self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, TagSize> {
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

    pub fn finalize_mac(mut self, data_len_bits: u64, tag_len_bits: u64) -> Array<u8, TagSize> {
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

    pub fn absorb(&mut self, ad: &Array<u8, D::Aegis128BlockSize>) {
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
    use aead::consts::{U1, U2, U4};
    use hex_literal::hex;
    use hybrid_array::Array;

    use crate::aarch64::AesBlock;

    use super::{State128L, State128X};

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

    #[test]
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.4.1>
    #[rustfmt::skip]
    fn init_aegis128x2() {
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
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.5.1>
    #[rustfmt::skip]
    fn init_aegis128x4() {
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
}
