use std::{arch::aarch64::*, array};

use hybrid_array::Array;

use crate::{C0, C1};

#[derive(Clone, Copy, Debug)]
pub struct State256(
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
);

impl State256 {
    pub fn init<const D: usize>(key: [u8; 32], nonce: [u8; 32]) -> [Self; D] {
        // k0, k1 = Split(key, 128)
        // n0, n1 = Split(nonce, 128)

        let k0 = unsafe { vld1q_u8(key.as_ptr()) };
        let k1 = unsafe { vld1q_u8(key.as_ptr().add(16)) };

        let n0 = unsafe { vld1q_u8(nonce.as_ptr()) };
        let n1 = unsafe { vld1q_u8(nonce.as_ptr().add(16)) };

        let c0 = unsafe { vld1q_u8(C0.as_ptr()) };
        let c1 = unsafe { vld1q_u8(C1.as_ptr()) };

        // for i in 0..D:
        //     V[0,i] = k0 ^ n0
        //     V[1,i] = k1 ^ n1
        //     V[2,i] = C1
        //     V[3,i] = C0
        //     V[4,i] = k0 ^ C0
        //     V[5,i] = k1 ^ C1

        let k0n0 = unsafe { veorq_u8(k0, n0) };
        let k1n1 = unsafe { veorq_u8(k1, n1) };

        let s = unsafe { Self(k0n0, k1n1, c0, c1, veorq_u8(k0, c0), veorq_u8(k1, c1)) };
        let mut v = [s; D];

        let ctx: [uint8x16_t; D] = array::from_fn(|i| unsafe {
            let mut a = [0; 16];
            a[0] = i as u8;
            a[1] = D as u8 - 1;
            vld1q_u8(a.as_ptr())
        });

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

        macro_rules! fold_ctx {
            () => {
                for i in 0..D {
                    v[i].3 = unsafe { veorq_u8(v[i].3, ctx[i]) };
                    v[i].5 = unsafe { veorq_u8(v[i].5, ctx[i]) };
                }
            };
        }

        for _ in 0..4 {
            fold_ctx!();
            v = Self::update(v, [k0; D]);
            fold_ctx!();
            v = Self::update(v, [k1; D]);
            fold_ctx!();
            v = Self::update(v, [k0n0; D]);
            fold_ctx!();
            v = Self::update(v, [k1n1; D]);
        }

        v
    }

    fn update<const D: usize>(s: [Self; D], m: [uint8x16_t; D]) -> [Self; D] {
        let mut out = s;

        macro_rules! d {
            ($s:ident, $m:pat, $o:ident => $e:expr) => {
                for i in 0..D {
                    let $m = &m[i];
                    let $s = &s[i];
                    let $o = &mut out[i];
                    { $e }
                }
            };
        }

        // S'0 = AESRound(S5, S0 ^ M)
        // S'1 = AESRound(S0, S1)
        // S'2 = AESRound(S1, S2)
        // S'3 = AESRound(S2, S3)
        // S'4 = AESRound(S3, S4)
        // S'5 = AESRound(S4, S5)

        unsafe {
            d!(s,m,o => o.0 = vaeseq_u8(s.5, veorq_u8(s.0, *m)));
            d!(s,_,o => o.1 = vaeseq_u8(s.0, s.1));
            d!(s,_,o => o.2 = vaeseq_u8(s.1, s.2));
            d!(s,_,o => o.3 = vaeseq_u8(s.2, s.3));
            d!(s,_,o => o.4 = vaeseq_u8(s.3, s.4));
            d!(s,_,o => o.5 = vaeseq_u8(s.4, s.5));
        }

        out
    }
}

// #[test]
// fn bench256() {
//     let x = unsafe {
//         vld1q_u8(const { [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] }.as_ptr())
//     };

//     let mut s = State256::init([1; 32], [2; 32]);
//     let m = Array([x; 4]);

//     let start = Instant::now();
//     for _ in 0..N {
//         s = update256(black_box(s), black_box(m));
//         s = update256(black_box(s), black_box(m));
//     }
//     black_box(s);
//     dbg!(start.elapsed() * 1000 / D as u32 / N as u32);
// }
