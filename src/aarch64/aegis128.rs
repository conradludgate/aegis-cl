use std::{arch::aarch64::*, array};

use crate::{C0, C1};

#[derive(Clone, Copy)]
pub struct State128(
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
    uint8x16_t,
);

impl State128 {
    pub fn init<const D: usize>(key: [u8; 16], nonce: [u8; 16]) -> [Self; D] {
        let key = unsafe { vld1q_u8(key.as_ptr()) };
        let nonce = unsafe { vld1q_u8(nonce.as_ptr()) };

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
            Self(
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
        let mut v = [s; D];

        let ctx: [uint8x16_t; D] = array::from_fn(|i| unsafe {
            let mut a = [0; 16];
            a[0] = i as u8;
            a[1] = D as u8 - 1;
            vld1q_u8(a.as_ptr())
        });

        // Repeat(10,
        //     for i in 0..D:
        //         V[3,i] = V[3,i] ^ ctx[i]
        //         V[7,i] = V[7,i] ^ ctx[i]

        //     Update(nonce_v, key_v)
        // )

        for _ in 0..4 {
            for i in 0..D {
                v[i].3 = unsafe { veorq_u8(v[i].3, ctx[i]) };
                v[i].7 = unsafe { veorq_u8(v[i].7, ctx[i]) };
            }
            v = Self::update(v, [(nonce, key); D]);
        }

        v
    }

    fn update<const D: usize>(s: [Self; D], m: [(uint8x16_t, uint8x16_t); D]) -> [Self; D] {
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

        out
    }
}
