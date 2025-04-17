use std::ops::{Index, IndexMut};

use aead::{
    consts::U32,
    inout::{InOut, InOutBuf},
};
use hybrid_array::{
    Array,
    sizes::{U1, U16},
};

use super::util;
use crate::{
    AegisParallel, C0, C1,
    low::{AesBlock, IAesBlock},
};

#[derive(Clone, Copy)]
pub struct State128X<D: AegisParallel>([D::AesBlock; 8]);

impl<D: AegisParallel> Index<usize> for State128X<D> {
    type Output = D::AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<D: AegisParallel> IndexMut<usize> for State128X<D> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<D: AegisParallel> State128X<D> {
    #[inline(always)]
    pub fn new(key: &Array<u8, U16>, iv: &Array<u8, U16>) -> Self {
        let key = AesBlock::from_block(key);
        let nonce = AesBlock::from_block(iv);
        let c0 = AesBlock::from_block(&C0);
        let c1 = AesBlock::from_block(&C1);

        // for i in 0..D:
        //     V[0,i] = key ^ nonce
        //     V[1,i] = C1
        //     V[2,i] = C0
        //     V[3,i] = C1
        //     V[4,i] = key ^ nonce
        //     V[5,i] = key ^ C0
        //     V[6,i] = key ^ C1
        //     V[7,i] = key ^ C0
        let kn = key ^ nonce;
        let k0 = key ^ c0;
        let k1 = key ^ c1;
        let mut v = Self([
            D::AesBlock::from(kn),
            D::AesBlock::from(c1),
            D::AesBlock::from(c0),
            D::AesBlock::from(c1),
            D::AesBlock::from(kn),
            D::AesBlock::from(k0),
            D::AesBlock::from(k1),
            D::AesBlock::from(k0),
        ]);

        // for i in 0..D:
        //     ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128)
        let ctx = util::ctx::<D>();

        let key = D::AesBlock::from(key);
        let nonce = D::AesBlock::from(nonce);

        // Repeat(10,
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[7,i] = V[7,i] ^ ctx[i]

        //     Update(nonce_v, key_v)
        // )
        for _ in 0..10 {
            v[3] = v[3] ^ ctx;
            v[7] = v[7] ^ ctx;
            v.update(nonce, key);
        }

        v
    }

    #[inline]
    pub fn encrypt_block(&mut self, mut block: InOut<'_, '_, Array<u8, D::Block2>>) {
        let v = self;
        // z0 = {}
        // z1 = {}
        // for i in 0..D:
        //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
        //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))
        let z0 = v[6] ^ v[1] ^ (v[2] & v[3]);
        let z1 = v[2] ^ v[5] ^ (v[6] & v[7]);

        // t0, t1 = Split(xi, R)
        let xi = block.get_in();
        let (t0, t1) = util::split_blocks::<D>(xi);

        // out0 = t0 ^ z0
        // out1 = t1 ^ z1
        let out0 = t0 ^ z0;
        let out1 = t1 ^ z1;

        // Update(t0, t1)
        v.update(t0, t1);

        // ci = out0 || out1
        let ci = block.get_out();
        write::<D>(out0, out1, ci);
    }

    pub fn decrypt_block(&mut self, mut block: InOut<'_, '_, Array<u8, D::Block2>>) {
        let v = self;

        // z0 = {}
        // z1 = {}
        // for i in 0..D:
        //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
        //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))
        let z0 = v[6] ^ v[1] ^ (v[2] & v[3]);
        let z1 = v[2] ^ v[5] ^ (v[6] & v[7]);

        // t0, t1 = Split(ci, R)
        let ci = block.get_in();
        let (t0, t1) = util::split_blocks::<D>(ci);

        // out0 = t0 ^ z0
        // out1 = t1 ^ z1
        let out0 = t0 ^ z0;
        let out1 = t1 ^ z1;

        // Update(out0, out1)
        v.update(out0, out1);

        // xi = out0 || out1
        let xi = block.get_out();
        write::<D>(out0, out1, xi);
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
        mut padded_block: InOut<'_, '_, Array<u8, D::Block2>>,
        len: usize,
    ) {
        let v = self;

        // z0 = {}
        // z1 = {}
        // for i in 0..D:
        //     z0 = z0 || (V[6,i] ^ V[1,i] ^ (V[2,i] & V[3,i]))
        //     z1 = z1 || (V[2,i] ^ V[5,i] ^ (V[6,i] & V[7,i]))
        let z0 = v[6] ^ v[1] ^ (v[2] & v[3]);
        let z1 = v[2] ^ v[5] ^ (v[6] & v[7]);

        // t0, t1 = Split(ZeroPad(cn, R), 128 * D)
        let cn = padded_block.get_in();
        let (t0, t1) = util::split_blocks::<D>(cn);

        // out0 = t0 ^ z0
        // out1 = t1 ^ z1
        let out0 = t0 ^ z0;
        let out1 = t1 ^ z1;

        // xn = Truncate(out0 || out1, |cn|)
        let xn = padded_block.get_out();
        write::<D>(out0, out1, xn);
        xn[len..].fill(0);

        // v0, v1 = Split(ZeroPad(xn, R), 128 * D)
        let (v0, v1) = util::split_blocks::<D>(xn);
        v.update(v0, v1);
    }

    #[inline]
    pub fn finalize128(mut self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, U16> {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let u = concatu64(ad_len_bits, msg_len_bits).into();

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = self[2] ^ u;

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update(t, t);
        }

        //     tag = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]
        //         tag = tag ^ ti
        self.fold_tag128().reduce_xor().into()
    }

    pub fn finalize_mac128(mut self, data_len_bits: u64) -> Array<u8, U16> {
        // t = {}
        // u = LE64(data_len_bits) || LE64(tag_len_bits)
        let u = concatu64(data_len_bits, 128).into();

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = self[2] ^ u;

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update(t, t);
        }

        let v = if D::USIZE > 1 {
            //     for i in 0..D: # tag from state 0 is included
            //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]
            //         tags = tags || ti
            let tags: Array<AesBlock, D> = self.fold_tag128().into();

            // # Absorb tags into state 0; other states are not used anymore
            let mut v = State128X::<U1>(self.0.map(|s| s.first()));

            // for v in Split(tags, 256):
            //     x0, x1 = Split(v, 128)
            //     Absorb(ZeroPad(x0, R / 2) || ZeroPad(x1, R / 2))
            for i in 0..D::USIZE / 2 {
                let x0 = tags[2 * i];
                let x1 = tags[2 * i + 1];
                v.update(x0, x1);
            }

            // u = LE64(D) || LE64(tag_len_bits)
            let u = concatu64(D::U64, 128);

            // t = ZeroPad(V[2,0] ^ u, R)
            let t = v[2].first() ^ u;

            // Repeat(7, Update(t, t))
            for _ in 0..7 {
                v.update(t, t);
            }

            v
        } else {
            // should be a noop.
            State128X::<U1>(self.0.map(|s| s.first()))
        };

        //     tag = V[0,0] ^ V[1,0] ^ V[2,0] ^ V[3,0] ^ V[4,0] ^ V[5,0] ^ V[6,0]
        v.fold_tag128().into()
    }

    pub fn finalize256(mut self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, U32> {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let u = concatu64(ad_len_bits, msg_len_bits).into();

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = self[2] ^ u;

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update(t, t);
        }

        //     ti0 = ZeroPad({}, 128)
        //     ti1 = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
        //         ti1 = ti1 ^ V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
        let [ti0, ti1] = self.fold_tag256();
        let ti0 = ti0.reduce_xor();
        let ti1 = ti1.reduce_xor();

        //     tag = ti0 || ti1
        util::join_blocks::<U1>(ti0, ti1)
    }

    pub fn finalize_mac256(mut self, data_len_bits: u64) -> Array<u8, U32> {
        // t = {}
        // u = LE64(data_len_bits) || LE64(tag_len_bits)
        let u = concatu64(data_len_bits, 256).into();

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = self[2] ^ u;

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update(t, t);
        }

        let v = if D::USIZE > 1 {
            //     for i in 1..D: # tag from state 0 is skipped
            //         ti0 = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
            //         ti1 = V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
            //         tags = tags || (ti0 || ti1)
            let [tags0, tags1] = self.fold_tag256();
            let tags0: Array<AesBlock, D> = tags0.into();
            let tags1: Array<AesBlock, D> = tags1.into();

            // # Absorb tags into state 0; other states are not used anymore
            let mut v = State128X::<U1>(self.0.map(|s| s.first()));

            // for v in Split(tags, 256):
            //     x0, x1 = Split(v, 128)
            //     Absorb(ZeroPad(x0, R / 2) || ZeroPad(x1, R / 2))
            for i in 0..D::USIZE {
                let x0 = tags0[i];
                let x1 = tags1[i];
                v.update(x0, x1);
            }

            // u = LE64(D) || LE64(tag_len_bits)
            let u = concatu64(D::U64, 256);

            // t = ZeroPad(V[2,0] ^ u, R)
            let t = v[2].first() ^ u;

            // Repeat(7, Update(t, t))
            for _ in 0..7 {
                v.update(t, t);
            }

            v
        } else {
            // should be a noop.
            State128X::<U1>(self.0.map(|s| s.first()))
        };

        //     t0 = V[0,0] ^ V[1,0] ^ V[2,0] ^ V[3,0]
        //     t1 = V[4,0] ^ V[5,0] ^ V[6,0] ^ V[7,0]
        //     tag = t0 || t1
        let [t0, t1] = v.fold_tag256();
        util::join_blocks::<U1>(t0, t1)
    }

    pub fn absorb(&mut self, ad: &Array<u8, D::Block2>) {
        let (t0, t1) = util::split_blocks::<D>(ad);
        self.update(t0, t1);
    }

    #[inline]
    fn update(&mut self, m0: D::AesBlock, m1: D::AesBlock) {
        let v = self;

        // for i in 0..D:
        //     V'[0,i] = AESRound(V[7,i], V[0,i] ^ m0[i])
        //     V'[1,i] = AESRound(V[0,i], V[1,i])
        //     V'[2,i] = AESRound(V[1,i], V[2,i])
        //     V'[3,i] = AESRound(V[2,i], V[3,i])
        //     V'[4,i] = AESRound(V[3,i], V[4,i] ^ m1[i])
        //     V'[5,i] = AESRound(V[4,i], V[5,i])
        //     V'[6,i] = AESRound(V[5,i], V[6,i])
        //     V'[7,i] = AESRound(V[6,i], V[7,i])
        let tmp = v[7];
        v[7] = v[6].aes(v[7]);
        v[6] = v[5].aes(v[6]);
        v[5] = v[4].aes(v[5]);
        v[4] = v[3].aes(v[4]);
        v[3] = v[2].aes(v[3]);
        v[2] = v[1].aes(v[2]);
        v[1] = v[0].aes(v[1]);
        v[0] = tmp.aes(v[0]);

        v[4] = v[4] ^ m1;
        v[0] = v[0] ^ m0;
    }

    #[inline]
    fn fold_tag128(self) -> D::AesBlock {
        self[0] ^ self[1] ^ self[2] ^ self[3] ^ self[4] ^ self[5] ^ self[6]
    }

    #[inline]
    fn fold_tag256(self) -> [D::AesBlock; 2] {
        [
            self[0] ^ self[1] ^ self[2] ^ self[3],
            self[4] ^ self[5] ^ self[6] ^ self[7],
        ]
    }
}

#[inline]
fn write<D: AegisParallel>(a: D::AesBlock, b: D::AesBlock, out: &mut Array<u8, D::Block2>) {
    let (p0, p1) = out.split_ref_mut::<D::Block>();
    *p0 = a.into();
    *p1 = b.into();
}

#[inline]
fn concatu64(x: u64, y: u64) -> AesBlock {
    let mut u = Array([0; 16]);
    u[..8].copy_from_slice(&x.to_le_bytes());
    u[8..].copy_from_slice(&y.to_le_bytes());
    AesBlock::from_block(&u)
}

#[cfg(test)]
mod tests {
    use std::mem::transmute;

    use aead::consts::{U1, U2, U4};
    use hex_literal::hex;
    use hybrid_array::Array;

    use crate::{low::AesBlock, low::IAesBlock};

    use super::State128X;

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.2.1>
    #[test]
    #[rustfmt::skip]
    fn update() {
        let mut s: State128X<U1> = State128X([
            AesBlock::from_block(&Array(hex!("9b7e60b24cc873ea894ecc07911049a3"))),
            AesBlock::from_block(&Array(hex!("330be08f35300faa2ebf9a7b0d274658"))),
            AesBlock::from_block(&Array(hex!("7bbd5bd2b049f7b9b515cf26fbe7756c"))),
            AesBlock::from_block(&Array(hex!("c35a00f55ea86c3886ec5e928f87db18"))),
            AesBlock::from_block(&Array(hex!("9ebccafce87cab446396c4334592c91f"))),
            AesBlock::from_block(&Array(hex!("58d83e31f256371e60fc6bb257114601"))),
            AesBlock::from_block(&Array(hex!("1639b56ea322c88568a176585bc915de"))),
            AesBlock::from_block(&Array(hex!("640818ffb57dc0fbc2e72ae93457e39a"))),
        ]);

        let m0 = AesBlock::from_block(&Array(hex!("033e6975b94816879e42917650955aa0")));
        let m1 = AesBlock::from_block(&Array(hex!("fcc1968a46b7e97861bd6e89af6aa55f")));

        s.update(m0, m1);

        let s: [[u8; 16]; 8] = unsafe { transmute(s) };

        assert_eq!(s[0], hex!("596ab773e4433ca0127c73f60536769d"));
        assert_eq!(s[1], hex!("790394041a3d26ab697bde865014652d"));
        assert_eq!(s[2], hex!("38cf49e4b65248acd533041b64dd0611"));
        assert_eq!(s[3], hex!("16d8e58748f437bfff1797f780337cee"));
        assert_eq!(s[4], hex!("9689ecdf08228c74d7e3360cca53d0a5"));
        assert_eq!(s[5], hex!("a21746bb193a569e331e1aa985d0d729"));
        assert_eq!(s[6], hex!("09d714e6fcf9177a8ed1cde7e3d259a6"));
        assert_eq!(s[7], hex!("61279ba73167f0ab76f0a11bf203bdff"));
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.4.1>
    #[rustfmt::skip]
    fn init_aegis128x2() {
        let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
        let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));

        let v = State128X::<U2>::new(&key, &nonce);
        let v: [[[u8; 16]; 2]; 8] = unsafe { transmute(v) };

        assert_eq!(v[0][0], hex!("a4fc1ad9a72942fb88bd2cabbba6509a"));
        assert_eq!(v[0][1], hex!("80a40e392fc71084209b6c3319bdc6cc"));

        assert_eq!(v[1][0], hex!("380f435cf801763b1f0c2a2f7212052d"));
        assert_eq!(v[1][1], hex!("73796607b59b1b650ee91c152af1f18a"));

        assert_eq!(v[2][0], hex!("6ee1de433ea877fa33bc0782abff2dcb"));
        assert_eq!(v[2][1], hex!("b9fab2ab496e16d1facaffd5453cbf14"));

        assert_eq!(v[3][0], hex!("85f94b0d4263bfa86fdf45a603d8b6ac"));
        assert_eq!(v[3][1], hex!("90356c8cadbaa2c969001da02e3feca0"));

        assert_eq!(v[4][0], hex!("09bd69ad3730174bcd2ce9a27cd1357e"));
        assert_eq!(v[4][1], hex!("e610b45125796a4fcf1708cef5c4f718"));

        assert_eq!(v[5][0], hex!("fcdeb0cf0a87bf442fc82383ddb0f6d6"));
        assert_eq!(v[5][1], hex!("61ad32a4694d6f3cca313a2d3f4687aa"));

        assert_eq!(v[6][0], hex!("571c207988659e2cdfbdaae77f4f37e3"));
        assert_eq!(v[6][1], hex!("32e6094e217573bf91fb28c145a3efa8"));

        assert_eq!(v[7][0], hex!("ca549badf8faa58222412478598651cf"));
        assert_eq!(v[7][1], hex!("3407279a54ce76d2e2e8a90ec5d108eb"));
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.5.1>
    #[rustfmt::skip]
    fn init_aegis128x4() {
        let key = Array(hex!("000102030405060708090a0b0c0d0e0f"));
        let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f"));

        let v = State128X::<U4>::new(&key, &nonce);
        let v: [[[u8; 16]; 4]; 8] = unsafe { transmute(v) };

        assert_eq!(v[0][0], hex!("924eb07635003a37e6c6575ba8ce1929"));
        assert_eq!(v[0][1], hex!("c8b6a5d91475445e936d48e794be0ce2"));
        assert_eq!(v[0][2], hex!("fcd37d050e24084befe3bbb219d64760"));
        assert_eq!(v[0][3], hex!("2e9f58cfb893a8800220242c373a8b18"));
        
        assert_eq!(v[1][0], hex!("1a1f60c4fab64e5471dc72edfcf6fe6b"));
        assert_eq!(v[1][1], hex!("c1e525ebea2d6375a9edd045dce96381"));
        assert_eq!(v[1][2], hex!("97a3e25abd228a44d4a14a6d3fe9185c"));
        assert_eq!(v[1][3], hex!("c2d4cf7f4287a98744645674265d4ca8"));
        
        assert_eq!(v[2][0], hex!("7bb50c534f6ec4780530ff1cce8a16e8"));
        assert_eq!(v[2][1], hex!("7b08d57557da0b5ef7b5f7d98b0ba189"));
        assert_eq!(v[2][2], hex!("6bfcac34ddb68404821a4d665303cb0f"));
        assert_eq!(v[2][3], hex!("d95626f6dfad1aed7467622c38529932"));
        
        assert_eq!(v[3][0], hex!("af339fd2d50ee45fc47665c647cf6586"));
        assert_eq!(v[3][1], hex!("d0669b39d140f0e118a4a511efe2f95a"));
        assert_eq!(v[3][2], hex!("7a94330f35c194fadda2a87e42cdeccc"));
        assert_eq!(v[3][3], hex!("233b640d1f4d56e2757e72c1a9d8ecb1"));
        
        assert_eq!(v[4][0], hex!("9f93737d699ba05c11e94f2b201bef5e"));
        assert_eq!(v[4][1], hex!("61caf387cf7cfd3f8300ac7680ccfd76"));
        assert_eq!(v[4][2], hex!("5825a671ecef03b7a9c98a601ae32115"));
        assert_eq!(v[4][3], hex!("87a1fe4d558161a8f4c38731f3223032"));
        
        assert_eq!(v[5][0], hex!("7a5aca78d636c05bbc702b2980196ab6"));
        assert_eq!(v[5][1], hex!("915d868408495d07eb527789f282c575"));
        assert_eq!(v[5][2], hex!("d0947bfbc1d3309cdffc9be1503aea62"));
        assert_eq!(v[5][3], hex!("8834ea57a15b9fbdc0245464a4b8cbef"));
        
        assert_eq!(v[6][0], hex!("e46f4cf71a95ac45b6f0823e3aba1a86"));
        assert_eq!(v[6][1], hex!("8c4ecef682fc44a8eba911b3fc7d99f9"));
        assert_eq!(v[6][2], hex!("a4fb61e2c928a2ca760b8772f2ea5f2e"));
        assert_eq!(v[6][3], hex!("3d34ea89da73caa3016c280500a155a3"));
        
        assert_eq!(v[7][0], hex!("85075f0080e9d618e7eb40f57c32d9f7"));
        assert_eq!(v[7][1], hex!("d2ab2b320c6e93b155a3787cb83e5281"));
        assert_eq!(v[7][2], hex!("0b3af0250ae36831a1b072e499929bcb"));
        assert_eq!(v[7][3], hex!("5cce4d00329d69f1aae36aa541347512"));
    }
}
