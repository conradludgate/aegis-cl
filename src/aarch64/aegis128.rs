use std::{
    arch::aarch64::*, hint::black_box, marker::PhantomData, mem::transmute, ops::Mul, time::Instant,
};

use aead::{
    AeadCore, AeadInOut, KeyInit, KeySizeUser, Tag,
    consts::{U0, U1, U8},
};
use block_buffer::BlockBuffer;
use cipher::{BlockCipherEncBackend, BlockModeEncBackend, BlockModeEncrypt, InOut};
use crypto_common::{BlockSizeUser, BlockSizes, IvSizeUser, KeyIvInit, ParBlocksSizeUser};
use hybrid_array::{
    Array, ArraySize,
    sizes::{U4, U16, U32},
    typenum::Prod,
};

use crate::{C0, C1};

#[derive(Clone, Copy)]
struct State128Inner(
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
);

type TagSize = U16;

#[derive(Clone)]
pub struct State128<D: ArraySize>(Array<State128Inner, D>);

impl<D: ArraySize> KeySizeUser for State128<D> {
    type KeySize = U16;
}
impl<D: ArraySize> IvSizeUser for State128<D> {
    type IvSize = U16;
}

impl<D: ArraySize> KeyIvInit for State128<D> {
    fn new(key: &aead::Key<Self>, iv: &crypto_common::Iv<Self>) -> Self {
        let key = unsafe { vld1q_u8(key.as_ptr()) };
        let nonce = unsafe { vld1q_u8(iv.as_ptr()) };

        let c0 = unsafe { vld1q_u8(C0.as_ptr()) };
        let c1 = unsafe { vld1q_u8(C1.as_ptr()) };

        // for i in 0..D:
        //     V[0,i] = key ^ nonce
        //     V[1,i] = C1
        //     V[2,i] = C0
        //     V[3,i] = C1
        //     V[4,i] = key ^ nonce
        //     V[5,i] = key ^ C0
        //     V[6,i] = key ^ C1
        //     V[7,i] = key ^ C0

        let keynonce = unsafe { veorq_u8(key, nonce) };

        let s = unsafe {
            State128Inner(
                keynonce,
                c1,
                c0,
                c1,
                keynonce,
                veorq_u8(key, c0),
                veorq_u8(key, c1),
                veorq_u8(key, c0),
            )
        };
        let mut v = Self(Array::from_fn(|_| s));

        let ctx = Array::<uint8x16_t, D>::from_fn(|i| unsafe {
            let mut a = [0; 16];
            a[0] = i as u8;
            a[1] = D::U8 - 1;
            vld1q_u8(a.as_ptr())
        });

        // Repeat(10,
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[7,i] = V[7,i] ^ ctx[i]

        //     Update(nonce_v, key_v)
        // )

        let nonce = Array::from_fn(|_| nonce);
        let key = Array::from_fn(|_| key);

        for _ in 0..4 {
            for i in 0..D::USIZE {
                v.0[i].3 = unsafe { veorq_u8(v.0[i].3, ctx[i]) };
                v.0[i].7 = unsafe { veorq_u8(v.0[i].7, ctx[i]) };
            }
            v.update_inner(nonce.clone(), key.clone());
        }

        v
    }
}

struct Aegis128Key<D>(Array<u8, U16>, PhantomData<D>);

impl<D> KeySizeUser for Aegis128Key<D> {
    type KeySize = U16;
}

impl<D> KeyInit for Aegis128Key<D> {
    fn new(key: &aead::Key<Self>) -> Self {
        Self(*key, PhantomData)
    }
}
impl<D> IvSizeUser for Aegis128Key<D> {
    type IvSize = U16;
}

impl<D> AeadCore for Aegis128Key<D> {
    type NonceSize = U16;
    type TagSize = U16;

    const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
}

impl<D: ArraySize> BlockSizeUser for State128<D>
where
    D: Mul<U32>,
    Prod<D, U32>: BlockSizes,
{
    type BlockSize = Prod<D, U32>;
}

impl<D: ArraySize> ParBlocksSizeUser for State128<D>
where
    D: Mul<U32>,
    Prod<D, U32>: BlockSizes,
{
    type ParBlocksSize = U1;
}

// impl<D: ArraySize> BlockModeEncrypt for State128<D>
// where
//     D: Mul<U32>,
//     Prod<D, U32>: BlockSizes,
// {
//     fn encrypt_with_backend(
//         &mut self,
//         f: impl cipher::BlockModeEncClosure<BlockSize = Self::BlockSize>,
//     ) {
//         f.call(self);
//     }
// }

impl<D: ArraySize> BlockModeEncBackend for State128<D>
where
    D: Mul<U32>,
    Prod<D, U32>: BlockSizes,
{
    fn encrypt_block(&mut self, block: cipher::InOut<'_, '_, cipher::Block<Self>>) {
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
        for i in 0..D::USIZE {
            let s = &self.0[i];

            let z0 = unsafe { veorq_u8(s.6, veorq_u8(s.1, vandq_u8(s.2, s.3))) };
            let z0 = Array(unsafe { vreinterpretq_p128_u8(z0) }.to_ne_bytes());

            let z1 = unsafe { veorq_u8(s.2, veorq_u8(s.5, vandq_u8(s.6, s.7))) };
            let z1 = Array(unsafe { vreinterpretq_p128_u8(z1) }.to_ne_bytes());

            chunks.get(i).xor_in2out(&z0);
            chunks.get(i + D::USIZE).xor_in2out(&z1);
        }

        let t0 = Array::from_fn(|i| unsafe { vld1q_u8(chunks.get(i).get_in().as_ptr()) });
        let t1 =
            Array::from_fn(|i| unsafe { vld1q_u8(chunks.get(i + D::USIZE).get_in().as_ptr()) });
        self.update_inner(t0, t1);
    }
}

impl<D: ArraySize> AeadInOut for Aegis128Key<D>
where
    D: Mul<U32>,
    Prod<D, U32>: BlockSizes,
{
    fn encrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: aead::inout::InOutBuf<'_, '_, u8>,
    ) -> aead::Result<aead::Tag<Self>> {
        // P_MAX (maximum length of the plaintext) is 2^61 - 1 bytes (2^64 - 8 bits).
        // A_MAX (maximum length of the associated data) is 2^61 - 1 bytes (2^64 - 8 bits).
        let msg_len_bits = u64::try_from(buffer.len())
            .map_err(|_| aead::Error)?
            .checked_mul(8)
            .ok_or(aead::Error)?;
        let ad_len_bits = u64::try_from(associated_data.len())
            .map_err(|_| aead::Error)?
            .checked_mul(8)
            .ok_or(aead::Error)?;

        // Init(key, nonce)
        // ct = {}
        let mut state = State128::<D>::new(&self.0, nonce);

        // ad_blocks = Split(ZeroPad(ad, R), R)
        // for ai in ad_blocks:
        //     Absorb(ai)
        let (ad_chunks, ad_tail) = Array::slice_as_chunks(associated_data);
        for ad_chunk in ad_chunks {
            state.absorb(ad_chunk);
        }
        if !ad_tail.is_empty() {
            let mut ad_chunk = Array::default();
            ad_chunk[..ad_tail.len()].copy_from_slice(ad_tail);
            state.absorb(&ad_chunk);
        }

        // msg_blocks = Split(ZeroPad(msg, R), R)
        // for xi in msg_blocks:
        //     ct = ct || Enc(xi)
        let (msg_chunks, mut msg_tail) = buffer.into_chunks();
        for msg_chunk in msg_chunks {
            state.encrypt_block(msg_chunk);
        }
        if !msg_tail.is_empty() {
            let len = msg_tail.len();
            let mut msg_chunk = Array::default();
            msg_chunk[..len].copy_from_slice(msg_tail.get_in());
            state.encrypt_block(InOut::from(&mut msg_chunk));
            msg_tail.get_out().copy_from_slice(&msg_chunk[..len]);
        }

        // tag = Finalize(|ad|, |msg|)
        // ct = Truncate(ct, |msg|)

        // return ct and tag
        Ok(state.finalize(ad_len_bits, msg_len_bits))
    }

    fn decrypt_inout_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: aead::inout::InOutBuf<'_, '_, u8>,
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        todo!()
    }
}

impl<D: ArraySize> State128<D> {
    pub fn finalize(mut self, ad_len_bits: u64, msg_len_bits: u64) -> Array<u8, TagSize> {
        // t = {}
        // u = LE64(ad_len_bits) || LE64(msg_len_bits)
        let mut u = [0; 16];
        u[..8].copy_from_slice(&ad_len_bits.to_le_bytes());
        u[8..].copy_from_slice(&msg_len_bits.to_le_bytes());
        let u = unsafe { vld1q_u8(u.as_ptr()) };

        // for i in 0..D:
        //     t = t || (V[2,i] ^ u)
        let t = Array::from_fn(|i| unsafe { veorq_u8(self.0[i].2, u) });

        // Repeat(7, Update(t, t))
        for _ in 0..7 {
            self.update_inner(t.clone(), t.clone());
        }

        // if tag_len_bits == 128:
        //     tag = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti = V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i] ^ V[4,i] ^ V[5,i] ^ V[6,i]
        //         tag = tag ^ ti
        let tag = self
            .0
            .into_iter()
            .map(|s| unsafe {
                veorq_u8(
                    veorq_u8(veorq_u8(s.0, s.1), veorq_u8(s.2, s.3)),
                    veorq_u8(veorq_u8(s.4, s.5), veorq_u8(s.6, s.7)),
                )
            })
            .reduce(|t1, t2| unsafe { veorq_u8(t1, t2) })
            .unwrap();

        Array(unsafe { vreinterpretq_p128_u8(tag) }.to_ne_bytes())

        // else:            # 256 bits
        //     ti0 = ZeroPad({}, 128)
        //     ti1 = ZeroPad({}, 128)
        //     for i in 0..D:
        //         ti0 = ti0 ^ V[0,i] ^ V[1,i] ^ V[2,i] ^ V[3,i]
        //         ti1 = ti1 ^ V[4,i] ^ V[5,i] ^ V[6,i] ^ V[7,i]
        //     tag = ti0 || ti1
    }

    pub fn absorb(&mut self, ad: &Array<u8, Prod<D, U32>>)
    where
        D: Mul<U32>,
        Prod<D, U32>: ArraySize,
    {
        self.update_inner(
            Array::from_fn(|i| unsafe {
                let i = i.unchecked_mul(16);
                let p = ad.as_ptr().add(i);
                vld1q_u8(p)
            }),
            Array::from_fn(|i| unsafe {
                let i = (i + D::USIZE).unchecked_mul(16);
                let p = ad.as_ptr().add(i);
                vld1q_u8(p)
            }),
        );
    }

    pub fn update(&mut self, m0: &Array<u8, Prod<D, U16>>, m1: &Array<u8, Prod<D, U16>>)
    where
        D: Mul<U16>,
        Prod<D, U16>: ArraySize,
    {
        self.update_inner(
            Array::from_fn(|i| unsafe {
                let i = i.unchecked_mul(16);
                let p = m0.as_ptr().add(i);
                let m0 = vld1q_u8(p);
                m0
            }),
            Array::from_fn(|i| unsafe {
                let i = i.unchecked_mul(16);
                let p = m1.as_ptr().add(i);
                let m0 = vld1q_u8(p);
                m0
            }),
        );
    }

    fn update_inner(&mut self, m0: Array<uint8x16_t, D>, m1: Array<uint8x16_t, D>) {
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

        // S'0 = AESRound(S7, S0 ^ M0)
        // S'1 = AESRound(S0, S1)
        // S'2 = AESRound(S1, S2)
        // S'3 = AESRound(S2, S3)
        // S'4 = AESRound(S3, S4 ^ M1)
        // S'5 = AESRound(S4, S5)
        // S'6 = AESRound(S5, S6)
        // S'7 = AESRound(S6, S7)

        unsafe {
            d!(s,m,o => o.0 = vaeseq_u8(s.7, veorq_u8(s.0, m.0)));
            d!(s,_,o => o.1 = vaeseq_u8(s.0, s.1));
            d!(s,_,o => o.2 = vaeseq_u8(s.1, s.2));
            d!(s,_,o => o.3 = vaeseq_u8(s.2, s.3));
            d!(s,m,o => o.4 = vaeseq_u8(s.3, veorq_u8(s.4, m.1)));
            d!(s,_,o => o.5 = vaeseq_u8(s.4, s.5));
            d!(s,_,o => o.6 = vaeseq_u8(s.5, s.6));
            d!(s,_,o => o.7 = vaeseq_u8(s.6, s.7));
        }

        *self = out;
    }
}

// const N: usize = 100000000;
// // const D: usize = U4;
// #[unsafe(no_mangle)]
// fn bench128() {
//     let x = unsafe {
//         vld1q_u8(const { [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] }.as_ptr())
//     };

//     let mut s = State128::<U4>::init([1; 16], [2; 16]);
//     let m = Array([(x, x); 4]);

//     let start = Instant::now();
//     for _ in 0..N {
//         s = black_box(s).update(black_box(m))
//     }
//     black_box(s);
//     dbg!(start.elapsed() * 1000 / 4 / N as u32);
// }
