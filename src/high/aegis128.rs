#[cfg(test)]
mod tests {
    use aead::{Aead, AeadInOut, Key, KeyInit, Nonce, Payload, Tag, inout::InOutBuf};

    use crate::high::{Aegis128X, AegisTag};
    use crate::mid::AegisParallel;

    fn test_roundtrip<D: AegisParallel, T: AegisTag>(
        key: Key<Aegis128X<D, T>>,
        nonce: Nonce<Aegis128X<D, T>>,
        aad: &[u8],
        msg: &[u8],
        ct: &[u8],
        tag: Tag<Aegis128X<D, T>>,
    ) where
        Aegis128X<D, T>: AeadInOut,
    {
        let encrypted = Aegis128X::<D, T>::new(&key)
            .encrypt(&nonce, Payload { aad, msg })
            .unwrap();

        let (actual_ct, actual_tag) = encrypted.split_at(msg.len());
        assert_eq!(actual_ct, ct);
        assert_eq!(actual_tag, tag.as_slice());

        let decrypted = Aegis128X::<D, T>::new(&key)
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
        key: Key<Aegis128X<D, T>>,
        nonce: Nonce<Aegis128X<D, T>>,
        aad: &[u8],
        ct: &[u8],
        tag: Tag<Aegis128X<D, T>>,
    ) where
        Aegis128X<D, T>: AeadInOut,
    {
        let mut buf = ct.to_vec();
        Aegis128X::<D, T>::new(&key)
            .decrypt_inout_detached(&nonce, aad, InOutBuf::from(&mut *buf), &tag)
            .unwrap_err();

        assert_eq!(buf, ct, "plaintext was cleared");
    }

    mod aegis128l {
        use hex_literal::hex;
        use hybrid_array::Array;

        use crate::{Tag128, X1};

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

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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

            test_roundtrip::<X1, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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
            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
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

            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
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

            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
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

            test_decrypt_fail::<X1, Tag128>(key, nonce, &ad, &ct, tag128);
        }
    }

    mod aegis128x2 {
        use hex_literal::hex;
        use hybrid_array::Array;

        use crate::{Tag128, X2};

        use super::test_roundtrip;

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

            test_roundtrip::<X2, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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

            test_roundtrip::<X2, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
        }
    }

    mod aegis128x4 {
        use hex_literal::hex;
        use hybrid_array::Array;

        use crate::{Tag128, X4};

        use super::test_roundtrip;

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

            test_roundtrip::<X4, Tag128>(key, nonce, &ad, &msg, &ct, tag128);
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

        use crate::high::{AegisMac128X, AegisTag};
        use crate::mid::AegisParallel;
        use crate::{Tag128, X1, X2, X4};

        fn test_mac<D: AegisParallel, T: AegisTag>(
            key: Key<AegisMac128X<D, T>>,
            iv: Iv<AegisMac128X<D, T>>,
            data: &[u8],
            tag: Output<AegisMac128X<D, T>>,
        ) where
            AegisMac128X<D, T>: Mac,
        {
            AegisMac128X::<D, T>::new(&key, &iv)
                .chain_update(data)
                .verify(&tag)
                .unwrap();
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.8.1>
        fn test_aegismac_128l() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let iv = Array(hex!("10000200000000000000000000000000"));
            let data = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122"
            );
            let tag128 = Array(hex!("d3f09b2842ad301687d6902c921d7818"));

            test_mac::<X1, Tag128>(key, iv, &data, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.8.2>
        fn test_aegismac_128_x2() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let iv = Array(hex!("10000200000000000000000000000000"));
            let data = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122"
            );
            let tag128 = Array(hex!("6873ee34e6b5c59143b6d35c5e4f2c6e"));

            test_mac::<X2, Tag128>(key, iv, &data, tag128);
        }

        #[test]
        /// <https://www.ietf.org/archive/id/draft-irtf-cfrg-aegis-aead-16.html#appendix-A.8.3>
        fn test_aegismac_128_x4() {
            let key = Array(hex!("10010000000000000000000000000000"));
            let iv = Array(hex!("10000200000000000000000000000000"));
            let data = hex!(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122"
            );
            let tag128 = Array(hex!("c45a98fd9ab8956ce616eb008cfe4e53"));

            test_mac::<X4, Tag128>(key, iv, &data, tag128);
        }
    }
}
