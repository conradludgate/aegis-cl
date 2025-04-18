use crate::mid::aegis256::State256X;
use crate::{X1, X2, X4};

use super::{Aegis, AegisMac};

pub type Aegis256X<D, T> = Aegis<State256X<D>, T>;

pub type Aegis256<T> = Aegis256X<X1, T>;
pub type Aegis256X2<T> = Aegis256X<X2, T>;
pub type Aegis256X4<T> = Aegis256X<X4, T>;

pub type AegisMac256X<D, T> = AegisMac<State256X<D>, T>;

pub type AegisMac256<T> = AegisMac256X<X1, T>;
pub type AegisMac256X2<T> = AegisMac256X<X2, T>;
pub type AegisMac256X4<T> = AegisMac256X<X4, T>;

#[cfg(test)]
mod tests {
    use aead::{Aead, AeadInOut, Key, KeyInit, Nonce, Payload, Tag, inout::InOutBuf};

    use super::AegisMac256X;
    use crate::{Aegis256X, AegisParallel, high::AegisTag};

    fn test_roundtrip<D: AegisParallel, T: AegisTag>(
        key: Key<Aegis256X<D, T>>,
        nonce: Nonce<Aegis256X<D, T>>,
        aad: &[u8],
        msg: &[u8],
        ct: &[u8],
        tag: Tag<Aegis256X<D, T>>,
    ) where
        Aegis256X<D, T>: AeadInOut,
    {
        let encrypted = Aegis256X::<D, T>::new(&key)
            .encrypt(&nonce, Payload { aad, msg })
            .unwrap();

        let (actual_ct, actual_tag) = encrypted.split_at(msg.len());
        assert_eq!(actual_ct, ct);
        assert_eq!(actual_tag, tag.as_slice());

        let decrypted = Aegis256X::<D, T>::new(&key)
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

    fn test_decrypt_fail<D: AegisParallel, T: AegisTag>(
        key: Key<Aegis256X<D, T>>,
        nonce: Nonce<Aegis256X<D, T>>,
        aad: &[u8],
        ct: &[u8],
        tag: Tag<Aegis256X<D, T>>,
    ) where
        Aegis256X<D, T>: AeadInOut,
    {
        let mut buf = ct.to_vec();
        Aegis256X::<D, T>::new(&key)
            .decrypt_inout_detached(&nonce, aad, InOutBuf::from(&mut *buf), &tag)
            .unwrap_err();

        assert_eq!(buf, ct, "plaintext was cleared");
    }

    mod aegis256l {
        use hex_literal::hex;
        use hybrid_array::Array;

        use crate::{Tag128, X1};

        use super::{test_decrypt_fail, test_roundtrip};

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.2>
        fn test_vector_1() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("");
            let msg = hex!("00000000000000000000000000000000");
            let ct = hex!("754fc3d8c973246dcc6d741412a4b236");
            let tag128 = Array(hex!("3fe91994768b332ed7f570a19ec5896e"));
            // tag256: 25835bfbb21632176cf03840687cb968
            //         cace4617af1bd0f7d064c639a5c79ee4

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.3>
        fn test_vector_2() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("");
            let msg = hex!("");
            let ct = hex!("");
            let tag128 = Array(hex!("e3def978a0f054afd1e761d7553afba3"));
            // tag256: 1360dc9db8ae42455f6e5b6a9d488ea4
            //         f2184c4e12120249335c4ee84bafe25d

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.4>
        fn test_vector_3() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("0001020304050607");
            let msg = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            );
            let ct = hex!(
                "f373079ed84b2709faee373584585d60"
                "accd191db310ef5d8b11833df9dec711"
            );
            let tag128 = Array(hex!("8d86f91ee606e9ff26a01b64ccbdd91d"));
            // tag256: 022cb796fe7e0ae1197525ff67e30948
            //         4cfbab6528ddef89f17d74ef8ecd82b3

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.5>
        fn test_vector_4() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("0001020304050607");
            let msg = hex!("000102030405060708090a0b0c0d");
            let ct = hex!("f373079ed84b2709faee37358458");
            let tag128 = Array(hex!("c60b9c2d33ceb058f96e6dd03c215652"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.6>
        fn test_vector_5() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
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
                "57754a7d09963e7c787583a2e7b859bb"
                "24fa1e04d49fd550b2511a358e3bca25"
                "2a9b1b8b30cc4a67"
            );
            let tag128 = Array(hex!("ab8a7d53fd0e98d727accca94925e128"));
            // tag256: b91e2947a33da8bee89b6794e647baf0
            //         fc835ff574aca3fc27c33be0db2aff98

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.7>
        fn test_vector_6() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("0001020304050607");
            let ct = hex!("f373079ed84b2709faee37358458");
            let tag128 = Array(hex!("c60b9c2d33ceb058f96e6dd03c215652"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac
            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.8>
        fn test_vector_7() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("0001020304050607");
            let ct = hex!("f373079ed84b2709faee37358459");
            let tag128 = Array(hex!("c60b9c2d33ceb058f96e6dd03c215652"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac

            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.9>
        fn test_vector_8() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("0001020304050608");
            let ct = hex!("f373079ed84b2709faee37358458");
            let tag128 = Array(hex!("c60b9c2d33ceb058f96e6dd03c215652"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ac

            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.3.10>
        fn test_vector_9() {
            // This test MUST return a “verification failed” error.
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let nonce = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let ad = hex!("0001020304050607");
            let ct = hex!("f373079ed84b2709faee37358458");
            let tag128 = Array(hex!("c60b9c2d33ceb058f96e6dd03c215653"));
            // tag256: 86f1b80bfb463aba711d15405d094baf
            //         4a55a15dbfec81a76f35ed0b9c8b04ad

            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
        }
    }

    mod aegis256x2 {
        use hex_literal::hex;
        use hybrid_array::Array;

        use crate::{Tag128, X2};

        use super::test_roundtrip;

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.6.2>
        fn test_vector_1() {
            let key = Array(hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            ));
            let nonce = Array(hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
            ));
            let ad = hex!("");
            let msg = hex!("");
            let ct = hex!("");
            let tag128 = Array(hex!("62cdbab084c83dacdb945bb446f049c8"));
            // tag256: 25d7e799b49a80354c3f881ac2f1027f
            //         471a5d293052bd9997abd3ae84014bb7

            test_roundtrip::<X2, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.6.3>
        fn test_vector_2() {
            let key = Array(hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            ));
            let nonce = Array(hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
            ));
            let ad = hex!("0102030401020304");
            let msg = hex!(
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "0506070805060708"
            );
            let ct = hex!(
                "73110d21a920608fd77b580f1e442808"
                "7a7365cb153b4eeca6b62e1a70f7f9a8"
                "d1f31f17da4c3acfacb2517f2f5e1575"
                "8c35532e33751a964d18d29a599d2dc0"
                "7f9378339b9d8c9fa03d30a4d7837cc8"
                "eb8b99bcbba2d11cd1a0f994af2b8f94"
                "7ef18473bd519e5283736758480abc99"
                "0e79d4ccab93dde9"
            );
            let tag128 = Array(hex!("94a3bd44ad3381e36335014620ee638e"));
            // tag256: 0392c62b17ddb00c172a010b5a327d0f
            //         97317b6fbaee31ef741f004d7adc1e81

            test_roundtrip::<X2, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }
    }

    mod aegis256x4 {
        use hex_literal::hex;
        use hybrid_array::Array;

        use crate::{Tag128, X4};

        use super::test_roundtrip;

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.7.2>
        fn test_vector_1() {
            let key = Array(hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            ));
            let nonce = Array(hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
            ));
            let ad = hex!("");
            let msg = hex!("");
            let ct = hex!("");
            let tag128 = Array(hex!("3b7fee6cee7bf17888ad11ed2397beb4"));
            // tag256: 6093a1a8aab20ec635dc1ca71745b01b
            //         5bec4fc444c9ffbebd710d4a34d20eaf

            test_roundtrip::<X4, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.7.3>
        fn test_vector_2() {
            let key = Array(hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            ));
            let nonce = Array(hex!(
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
            ));
            let ad = hex!("0102030401020304");
            let msg = hex!(
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "05060708050607080506070805060708"
                "0506070805060708"
            );
            let ct = hex!(
                "bec109547f8316d598b3b7d947ad4c0e"
                "f5b98e217cffa0d858ad49ae34109a95"
                "abc5b5fada820c4d6ae2fca0f5e2444e"
                "52a04a1edb7bec71408de3e199500521"
                "94506be3ba6a4de51a15a577ea0e4c14"
                "f7539a13e751a555f48d0f49fecffb22"
                "0525e60d381e2efa803b09b7164ba59f"
                "dc66656affd51e06"
            );
            let tag128 = Array(hex!("ec44b512d713f745547be345bcc66b6c"));
            // tag256: ba3168ecd7f7120c5e204a7e0d616e39
            //         5675ddfe00e4e5490a5ba93bb1a70555

            test_roundtrip::<X4, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }
    }

    mod mac {
        use digest::{
            Key, Mac, Output,
            crypto_common::{Iv, KeyIvInit},
        };
        use hex_literal::hex;
        use hybrid_array::Array;

        use super::AegisMac256X;
        use crate::{AegisParallel, Tag128, X1, X2, X4, high::AegisTag};

        fn test_mac<D: AegisParallel, T: AegisTag>(
            key: Key<AegisMac256X<D, T>>,
            iv: Iv<AegisMac256X<D, T>>,
            data: &[u8],
            tag: Output<AegisMac256X<D, T>>,
        ) where
            AegisMac256X<D, T>: Mac,
        {
            AegisMac256X::<D, T>::new(&key, &iv)
                .chain_update(data)
                .verify(&tag)
                .unwrap();
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.8.1>
        fn test_aegismac_256l() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let iv = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let data = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122"
            );
            let tag128 = Array(hex!("c08e20cfc56f27195a46c9cef5c162d4"));

            test_mac::<X1, Tag128>(key, iv, &data, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.8.2>
        fn test_aegismac_256_x2() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let iv = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let data = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122"
            );
            let tag128 = Array(hex!("fb319cb6dd728a764606fb14d37f2a5e"));

            test_mac::<X2, Tag128>(key, iv, &data, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.8.3>
        fn test_aegismac_256_x4() {
            let key = Array(hex!(
                "10010000000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let iv = Array(hex!(
                "10000200000000000000000000000000"
                "00000000000000000000000000000000"
            ));
            let data = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122"
            );
            let tag128 = Array(hex!("a51f9bc5beae60cce77f0dbc60761edd"));

            test_mac::<X4, Tag128>(key, iv, &data, tag128);
        }
    }
}
