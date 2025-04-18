use std::ops::{Index, IndexMut};

use aead::inout::InOut;
use digest::typenum::Unsigned;
use hybrid_array::Array;
use hybrid_array::sizes::U32;

use super::{AegisCore, AegisParallel, C0, C1, util};
use crate::X1;
use crate::low::{AesBlock, AesBlockArray};

/// The state used by AEGIS-256.
pub struct State256X<D: AegisParallel>([D::AesBlock; 6]);

impl<D: AegisParallel> Clone for State256X<D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D: AegisParallel> Copy for State256X<D> {}

impl<D: AegisParallel> Index<usize> for State256X<D> {
    type Output = D::AesBlock;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<D: AegisParallel> IndexMut<usize> for State256X<D> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<D: AegisParallel> AegisCore for State256X<D> {
    type Key = U32;
    type Block = <D::AesBlock as AesBlockArray>::Block;

    #[inline(always)]
    fn new(key: &Array<u8, U32>, iv: &Array<u8, U32>) -> Self {
        let (k0, k1) = util::split_blocks::<AesBlock>(key);
        let (n0, n1) = util::split_blocks::<AesBlock>(iv);
        let c0 = AesBlock::from_block(&C0);
        let c1 = AesBlock::from_block(&C1);

        let k0n0 = D::AesBlock::from(k0 ^ n0);
        let k1n1 = D::AesBlock::from(k1 ^ n1);
        let k0c0 = D::AesBlock::from(k0 ^ c0);
        let k1c1 = D::AesBlock::from(k1 ^ c1);
        let k0 = D::AesBlock::from(k0);
        let k1 = D::AesBlock::from(k1);
        let c0 = D::AesBlock::from(c0);
        let c1 = D::AesBlock::from(c1);

        // for i in 0..D:
        //     V[0,i] = k0 ^ n0
        //     V[1,i] = k1 ^ n1
        //     V[2,i] = C1
        //     V[3,i] = C0
        //     V[4,i] = k0 ^ C0
        //     V[5,i] = k1 ^ C1
        let mut v = Self([k0n0, k1n1, c1, c0, k0c0, k1c1]);

        // for i in 0..D:
        //     ctx[i] = ZeroPad(Byte(i) || Byte(D - 1), 128)
        let ctx = D::ctx();

        // Repeat(4,
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[5,i] = V[5,i] ^ ctx[i]

        //     Update(k0_v)
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[5,i] = V[5,i] ^ ctx[i]

        //     Update(k1_v)
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[5,i] = V[5,i] ^ ctx[i]

        //     Update(k0n0_v)
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[5,i] = V[5,i] ^ ctx[i]

        //     Update(k1n1_v)
        // )
        for _ in 0..4 {
            v[3] = v[3] ^ ctx;
            v[5] = v[5] ^ ctx;

            v.update(k0);

            v[3] = v[3] ^ ctx;
            v[5] = v[5] ^ ctx;

            v.update(k1);

            v[3] = v[3] ^ ctx;
            v[5] = v[5] ^ ctx;

            v.update(k0n0);

            v[3] = v[3] ^ ctx;
            v[5] = v[5] ^ ctx;

            v.update(k1n1);
        }

        v
    }

    #[inline(always)]
    fn encrypt_emtpy_block(&mut self, block: &mut Array<u8, Self::Block>) {
        let v = self;

        // z = {}
        // for i in 0..D:
        //     z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))
        let z = v[1] ^ v[4] ^ v[5] ^ (v[2] & v[3]);

        // Update(xi)
        let tmp = v[5];
        v[5] = v[4].aes(v[5]);
        v[4] = v[3].aes(v[4]);
        v[3] = v[2].aes(v[3]);
        v[2] = v[1].aes(v[2]);
        v[1] = v[0].aes(v[1]);
        v[0] = tmp.aes(v[0]);

        // ci = xi ^ z
        let ci = z;

        // return ci
        *block = ci.into();
    }

    #[inline(always)]
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Array<u8, Self::Block>>) {
        let v = self;

        // z = {}
        // for i in 0..D:
        //     z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))
        let z = v[1] ^ v[4] ^ v[5] ^ (v[2] & v[3]);

        // Update(xi)
        let xi = D::AesBlock::from_block(block.get_in());
        v.update(xi);

        // ci = xi ^ z
        let ci = xi ^ z;

        // return ci
        *block.get_out() = ci.into();
    }

    #[inline(always)]
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Array<u8, Self::Block>>) {
        let v = self;

        // z = {}
        // for i in 0..D:
        //     z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))
        let z = v[1] ^ v[4] ^ v[5] ^ (v[2] & v[3]);

        // xi = ci ^ z
        let ci = D::AesBlock::from_block(block.get_in());
        let xi = ci ^ z;

        // Update(xi)
        v.update(xi);

        // return xi
        *block.get_out() = xi.into();
    }

    #[inline(always)]
    fn decrypt_partial_block(
        &mut self,
        mut padded_block: InOut<'_, '_, Array<u8, Self::Block>>,
        len: usize,
    ) {
        let v = self;

        // z = {}
        // for i in 0..D:
        //     z = z || (V[1,i] ^ V[4,i] ^ V[5,i] ^ (V[2,i] & V[3,i]))
        let z = v[1] ^ v[4] ^ v[5] ^ (v[2] & v[3]);

        // t = ZeroPad(cn, R)
        // out = t ^ z
        let t = D::AesBlock::from_block(padded_block.get_in());
        let out = t ^ z;

        // xn = Truncate(out, |cn|)
        // v = ZeroPad(xn, 128 * D)
        let xn = padded_block.get_out();
        *xn = out.into();
        xn[len..].fill(0);
        let v_ = D::AesBlock::from_block(xn);

        // Update(v)
        v.update(v_);

        // return xn
    }

    #[inline(always)]
    fn finalize128(mut self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 16] {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let u = util::concatu64(ad_len_bits, msg_len_bits).into();

        // for i in 0..D:
        //     t = t || (V[3,i] ^ u)
        let t = self[3] ^ u;

        // Repeat(7, Update(t))
        for _ in 0..7 {
            self.update(t);
        }

        //     tag = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i]
        //         tag = tag ^ ti
        self.fold_tag128().reduce_xor().into()
    }

    #[inline(always)]
    fn finalize_mac128(mut self, data_len_bits: u64) -> [u8; 16] {
        // t = {}
        // u = LE64(data_len_bits) || LE64(tag_len_bits)
        let u = util::concatu64(data_len_bits, 128).into();

        // for i in 0..D:
        //     t = t || (V[3,i] ^ u)
        let t = self[3] ^ u;

        // Repeat(7, Update(t))
        for _ in 0..7 {
            self.update(t);
        }

        let v = if <D::Blocks as Unsigned>::USIZE > 1 {
            // tags = {}
            //     for i in 1..D: # tag from state 0 is skipped
            //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i]
            //         tags = tags || ti
            let tags: Array<AesBlock, D::Blocks> = self.fold_tag128().into();

            // # Absorb tags into state 0; other states are not used anymore
            let mut v = State256X::<X1>(self.0.map(|s| s.first()));

            // for v in Split(tags, 128):
            //     Absorb(ZeroPad(v, R))
            for i in 1..<D::Blocks as Unsigned>::USIZE {
                let v_ = tags[i];
                v.update(v_);
            }

            // u = LE64(D) || LE64(tag_len_bits)
            let u = util::concatu64(<D::Blocks as Unsigned>::U64, 128);

            // t = ZeroPad(V[3,0] ^ u, R)
            let t = v[3] ^ u;

            // Repeat(7, Update(t))
            for _ in 0..7 {
                v.update(t);
            }

            v
        } else {
            // should be a noop.
            State256X::<X1>(self.0.map(|s| s.first()))
        };

        // tag = V[0,0] ^ V[1,0] ^ V[2,0] ^ V[3,0] ^ V[4,0] ^ V[5,0]
        v.fold_tag128().into()
    }

    #[inline(always)]
    fn finalize256(mut self, ad_len_bits: u64, msg_len_bits: u64) -> [u8; 32] {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let u = util::concatu64(ad_len_bits, msg_len_bits).into();

        // for i in 0..D:
        //     t = t || (V[3,i] ^ u)
        let t = self[3] ^ u;

        // Repeat(7, Update(t))
        for _ in 0..7 {
            self.update(t);
        }

        // ti0 = ZeroPad({}, 128)
        // ti1 = ZeroPad({}, 128)
        // for i in 0..D:
        //     ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i]
        //     ti1 = ti1 ^ V[3,i] ^ V[4,i] ^ V[5,i]
        let [ti0, ti1] = self.fold_tag256();
        let ti0 = ti0.reduce_xor();
        let ti1 = ti1.reduce_xor();

        //     tag = ti0 || ti1
        util::join_block(ti0, ti1)
    }

    #[inline(always)]
    fn finalize_mac256(mut self, data_len_bits: u64) -> [u8; 32] {
        // t = {}
        // u = LE64(data_len_bits) || LE64(tag_len_bits)
        let u = util::concatu64(data_len_bits, 256).into();

        // for i in 0..D:
        //     t = t || (V[3,i] ^ u)
        let t = self[3] ^ u;

        // Repeat(7, Update(t))
        for _ in 0..7 {
            self.update(t);
        }

        let v = if <D::Blocks as Unsigned>::USIZE > 1 {
            // tags = {}
            // for i in 1..D: # tag from state 0 is skipped
            // ti0 = V[0,i] ^ V[1,i] ^ V[2,i]
            // ti1 = V[3,i] ^ V[4,i] ^ V[5,i]
            // tags = tags || (ti0 || ti1)
            let [t0, t1] = self.fold_tag256();
            let tags0: Array<AesBlock, D::Blocks> = t0.into();
            let tags1: Array<AesBlock, D::Blocks> = t1.into();

            // # Absorb tags into state 0; other states are not used anymore
            let mut v = State256X::<X1>(self.0.map(|s| s.first()));

            // for v in Split(tags, 128):
            //     Absorb(ZeroPad(v, R))
            for i in 1..<D::Blocks as Unsigned>::USIZE {
                let v0 = tags0[i];
                v.update(v0);
                let v1 = tags1[i];
                v.update(v1);
            }

            // u = LE64(D) || LE64(tag_len_bits)
            let u = util::concatu64(<D::Blocks as Unsigned>::U64, 256);

            // t = ZeroPad(V[3,0] ^ u, R)
            let t = v[3] ^ u;

            // Repeat(7, Update(t))
            for _ in 0..7 {
                v.update(t);
            }

            v
        } else {
            // should be a noop.
            State256X::<X1>(self.0.map(|s| s.first()))
        };

        // t0 = V[0,0] ^ V[1,0] ^ V[2,0]
        // t1 = V[3,0] ^ V[4,0] ^ V[5,0]
        // tag = t0 || t1
        let [t0, t1] = v.fold_tag256();
        util::join_block(t0, t1)
    }

    #[inline(always)]
    fn absorb(&mut self, ad: &Array<u8, Self::Block>) {
        self.update(D::AesBlock::from_block(ad));
    }
}

impl<D: AegisParallel> State256X<D> {
    #[inline(always)]
    fn update(&mut self, m: D::AesBlock) {
        let v = self;

        // for i in 0..D:
        //     V'[0,i] = AESRound(V[5,i], V[0,i] ^ m[i])
        //     V'[1,i] = AESRound(V[0,i], V[1,i])
        //     V'[2,i] = AESRound(V[1,i], V[2,i])
        //     V'[3,i] = AESRound(V[2,i], V[3,i])
        //     V'[4,i] = AESRound(V[3,i], V[4,i])
        //     V'[5,i] = AESRound(V[4,i], V[5,i])
        let tmp = v[5];
        v[5] = v[4].aes(v[5]);
        v[4] = v[3].aes(v[4]);
        v[3] = v[2].aes(v[3]);
        v[2] = v[1].aes(v[2]);
        v[1] = v[0].aes(v[1]);
        v[0] = tmp.aes(v[0]);

        v[0] = v[0] ^ m;
    }

    #[inline(always)]
    fn fold_tag128(self) -> D::AesBlock {
        self[0] ^ self[1] ^ self[2] ^ self[3] ^ self[4] ^ self[5]
    }

    #[inline(always)]
    fn fold_tag256(self) -> [D::AesBlock; 2] {
        [self[0] ^ self[1] ^ self[2], self[3] ^ self[4] ^ self[5]]
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use hybrid_array::Array;
    use hybrid_array::sizes::{U2, U4, U16};

    use crate::{X1, X2, X4};
    use crate::{
        low::{AesBlock, AesBlockArray},
        mid::AegisCore,
    };

    use super::State256X;

    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.1>
    #[test]
    #[rustfmt::skip]
    fn update() {
        let mut s: State256X<X1> = State256X([
            AesBlock::from_block(&Array(hex!("1fa1207ed76c86f2c4bb40e8b395b43e"))),
            AesBlock::from_block(&Array(hex!("b44c375e6c1e1978db64bcd12e9e332f"))),
            AesBlock::from_block(&Array(hex!("0dab84bfa9f0226432ff630f233d4e5b"))),
            AesBlock::from_block(&Array(hex!("d7ef65c9b93e8ee60c75161407b066e7"))),
            AesBlock::from_block(&Array(hex!("a760bb3da073fbd92bdc24734b1f56fb"))),
            AesBlock::from_block(&Array(hex!("a828a18d6a964497ac6e7e53c5f55c73"))),
        ]);

        let m0 = AesBlock::from_block(&Array(hex!("b165617ed04ab738afb2612c6d18a1ec")));

        s.update(m0);

        let s: [[u8; 16]; 6] = s.0.map(|b| Array::<u8, U16>::from(b).0);

        assert_eq!(s[0], hex!("e6bc643bae82dfa3d991b1b323839dcd"));
        assert_eq!(s[1], hex!("648578232ba0f2f0a3677f617dc052c3"));
        assert_eq!(s[2], hex!("ea788e0e572044a46059212dd007a789"));
        assert_eq!(s[3], hex!("2f1498ae19b80da13fba698f088a8590"));
        assert_eq!(s[4], hex!("a54c2ee95e8c2a2c3dae2ec743ae6b86"));
        assert_eq!(s[5], hex!("a3240fceb68e32d5d114df1b5363ab67"));
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.6.1>
    #[rustfmt::skip]
    fn init_aegis256x2() {
        let key = Array(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"));

        let v = State256X::<X2>::new(&key, &nonce);
        let v: [[[u8; 16]; 2]; 6] =v.0.map(|b| Array::<AesBlock, U2>::from(b).0).map(|b| b.map(|b| Array::<u8, U16>::from(b).0));

        assert_eq!(v[0][0], hex!("eca2bf4538442e8712d4972595744039"));
        assert_eq!(v[0][1], hex!("201405efa9264f07911db58101903087"));

        assert_eq!(v[1][0], hex!("3e536a998799408a97f3479a6f779d48"));
        assert_eq!(v[1][1], hex!("0d79a7d822a5d215f78c3bf2feb33ae1"));

        assert_eq!(v[2][0], hex!("cf8c63d6f2b4563cdd9231107c85950e"));
        assert_eq!(v[2][1], hex!("78d17ed7d8d563ff11bd202c76864839"));

        assert_eq!(v[3][0], hex!("d7e0707e6bfbbad913bc94b6993a9fa0"));
        assert_eq!(v[3][1], hex!("097e4b1bff40d4c19cb29dfd125d62f2"));

        assert_eq!(v[4][0], hex!("a373cf6d537dd66bc0ef0f2f9285359f"));
        assert_eq!(v[4][1], hex!("c0d0ae0c48f9df3faaf0e7be7768c326"));

        assert_eq!(v[5][0], hex!("9f76560dcae1efacabdcce446ae283bc"));
        assert_eq!(v[5][1], hex!("bd52a6b9c8f976a26ec1409df19e8bfe"));
    }

    #[test]
    /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.7.1>
    #[rustfmt::skip]
    fn init_aegis256x4() {
        let key = Array(hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        let nonce = Array(hex!("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"));

        let v = State256X::<X4>::new(&key, &nonce);
        let v: [[[u8; 16]; 4]; 6] =v.0.map(|b| Array::<AesBlock, U4>::from(b).0).map(|b| b.map(|b| Array::<u8, U16>::from(b).0));

        assert_eq!(v[0][0], hex!("482a86e8436cd2361063a4b2702769b9"));
        assert_eq!(v[0][1], hex!("d95a2be81c9245b22996f68eea0122f9"));
        assert_eq!(v[0][2], hex!("0c2a3b348b1a5e256c6751377318c41e"));
        assert_eq!(v[0][3], hex!("f64436a21653fe7cf2e0829a177db383"));

        assert_eq!(v[1][0], hex!("e705e8866267717d96092e58e78b574c"));
        assert_eq!(v[1][1], hex!("d1dd412142df9806cc267af2fe1d830e"));
        assert_eq!(v[1][2], hex!("30e7dfd3c9941b8394e95bdf5bac99d9"));
        assert_eq!(v[1][3], hex!("9f27186f8a4fab86820689822c3c74d2"));

        assert_eq!(v[2][0], hex!("e1aa6af5d9e31dde8d94a48a0810fa89"));
        assert_eq!(v[2][1], hex!("63555cdf0d98f18fb75b029ad80786c0"));
        assert_eq!(v[2][2], hex!("a3ee0e4a3429a9539e4fcec385475608"));
        assert_eq!(v[2][3], hex!("28ea527d31ef61df498dc107fe02df99"));

        assert_eq!(v[3][0], hex!("37f06808410c8f3954525ae44584d3be"));
        assert_eq!(v[3][1], hex!("8fcc23bca2fe2209f93d34e2da35b33d"));
        assert_eq!(v[3][2], hex!("33156347df89eaa69ab11096362daccf"));
        assert_eq!(v[3][3], hex!("bbe58d9dbe8c5b0469be5a87086db5d4"));

        assert_eq!(v[4][0], hex!("d1c9eb37fecbc5ada7b351fa4f501f32"));
        assert_eq!(v[4][1], hex!("0b9b803283c1538628b507c8f6432434"));
        assert_eq!(v[4][2], hex!("bfb8b6d4f87cce28825c7e92f54b8728"));
        assert_eq!(v[4][3], hex!("8917bb5b09c32f900c6a5a1d63c46264"));

        assert_eq!(v[5][0], hex!("4f6110c2ef0c3c687e90c1e5532ddf8e"));
        assert_eq!(v[5][1], hex!("031bd85d99f64684d23728a0453c72a1"));
        assert_eq!(v[5][2], hex!("10bc7ec34d4119b5bdeb6c7dfc458247"));
        assert_eq!(v[5][3], hex!("591ece530aeaa5c9867220156f5c25e3"));
    }
}
