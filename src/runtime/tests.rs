use super::*;
use aead::{AeadInOut, KeyInit};
fn compare<A: Algorithm, T: AegisTag>() {
    let mut key = Array::<u8, A::Key>::default();
    let mut nonce = key.clone();
    for (i, b) in key.iter_mut().enumerate() {
        *b = i as u8 ^ 0x42;
    }
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = i as u8 ^ 0x24;
    }
    let cipher = crate::high::Aegis::<A, T>::new(&key);
    let reference = crate::high::Aegis::<A::Core<crate::low::backend::Portable>, T>::new(&key);
    let choices = Choice::available();
    eprintln!(
        "{} / {}: exercising {} checked backends",
        core::any::type_name::<A>(),
        core::any::type_name::<T>(),
        choices.len()
    );
    #[cfg(not(miri))]
    let lengths = [
        0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1024,
    ];
    #[cfg(miri)]
    let lengths = [0, 1, 33];
    #[cfg(not(miri))]
    let ads = [0, 1, 31, 32, 33, 127, 128, 129];
    #[cfg(miri)]
    let ads = [0];
    for len in lengths {
        for adlen in ads {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ad = vec![0x81; adlen];
            let mut expected = msg.clone();
            let tag = reference
                .encrypt_inout_detached(&nonce, &ad, InOutBuf::from(&mut expected[..]))
                .unwrap();
            let mut automatic = msg.clone();
            assert_eq!(
                tag,
                cipher
                    .encrypt_inout_detached(&nonce, &ad, InOutBuf::from(&mut automatic[..]))
                    .unwrap()
            );
            assert_eq!(automatic, expected);
            for choice in choices.iter().copied() {
                let mut data = vec![0; len];
                let actual = choice
                    .run(Encrypt::<A, T> {
                        key: &key,
                        nonce: &nonce,
                        ad: &ad,
                        data: InOutBuf::new(&msg, &mut data).unwrap(),
                        marker: PhantomData,
                    })
                    .unwrap();
                assert_eq!(data, expected);
                assert_eq!(actual, tag);
                let mut plaintext = vec![0; len];
                choice
                    .run(Decrypt::<A, T> {
                        key: &key,
                        nonce: &nonce,
                        ad: &ad,
                        data: InOutBuf::new(&data, &mut plaintext).unwrap(),
                        tag: &tag,
                    })
                    .unwrap();
                assert_eq!(plaintext, msg);
                let mut bad_tag = tag.clone();
                bad_tag[0] ^= 1;
                assert!(
                    choice
                        .run(Decrypt::<A, T> {
                            key: &key,
                            nonce: &nonce,
                            ad: &ad,
                            data: InOutBuf::from(&mut data[..]),
                            tag: &bad_tag
                        })
                        .is_err()
                );
                assert_eq!(
                    data, expected,
                    "rejected in-place plaintext must be overwritten"
                );
            }
        }
    }
}
macro_rules! case {
    ($name:ident, $state:ident, $lanes:ident, $tag:ident) => {
        #[test]
        fn $name() {
            compare::<crate::mid::$state<crate::$lanes>, crate::$tag>();
        }
    };
}
case!(aead_128l_128, State128X, X1, Tag128);
case!(aead_128l_256, State128X, X1, Tag256);
case!(aead_128x2_128, State128X, X2, Tag128);
case!(aead_128x2_256, State128X, X2, Tag256);
case!(aead_128x4_128, State128X, X4, Tag128);
case!(aead_128x4_256, State128X, X4, Tag256);
case!(aead_256_128, State256X, X1, Tag128);
case!(aead_256_256, State256X, X1, Tag256);
case!(aead_256x2_128, State256X, X2, Tag128);
case!(aead_256x2_256, State256X, X2, Tag256);
case!(aead_256x4_128, State256X, X4, Tag128);
case!(aead_256x4_256, State256X, X4, Tag256);
