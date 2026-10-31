//! Runtime AEAD must match an independent implementation, including tails/AD.
use aegis_cl::aead::{AeadInOut, KeyInit, inout::InOutBuf};

macro_rules! compare {
    ($ours:ident, $module:ident, $reference:ident, $key_len:expr, $tag:ident, $tag_len:expr) => {{
        let key = [0x42; $key_len];
        let nonce = [0x24; $key_len];
        let cipher = aegis_cl::$ours::<aegis_cl::$tag>::new(&key.into());
        for n in [0, 1, 16, 17, 32, 33, 64, 65, 128, 129, 1024] {
            for a in [0, 1, 17, 64, 129] {
                let msg: Vec<u8> = (0..n).map(|i| i as u8).collect();
                let ad = vec![0x81; a];
                let mut actual = msg.clone();
                let tag = cipher
                    .encrypt_inout_detached(&nonce.into(), &ad, InOutBuf::from(&mut actual[..]))
                    .unwrap();
                let (ct, expected) =
                    aegis::$module::$reference::<$tag_len>::new(&key, &nonce).encrypt(&msg, &ad);
                assert_eq!(actual, ct);
                assert_eq!(&tag[..], &expected);
                cipher
                    .decrypt_inout_detached(
                        &nonce.into(),
                        &ad,
                        InOutBuf::from(&mut actual[..]),
                        &tag,
                    )
                    .unwrap();
                assert_eq!(actual, msg);
            }
        }
    }};
}
macro_rules! variant {
    ($test:ident,$ours:ident,$module:ident,$reference:ident,$key_len:expr) => {
        #[test]
        fn $test() {
            compare!($ours, $module, $reference, $key_len, Tag128, 16);
            compare!($ours, $module, $reference, $key_len, Tag256, 32);
        }
    };
}
variant!(aegis128l, Aegis128L, aegis128l, Aegis128L, 16);
variant!(aegis128x2, Aegis128X2, aegis128x2, Aegis128X2, 16);
variant!(aegis128x4, Aegis128X4, aegis128x4, Aegis128X4, 16);
variant!(aegis256, Aegis256, aegis256, Aegis256, 32);
variant!(aegis256x2, Aegis256X2, aegis256x2, Aegis256X2, 32);
variant!(aegis256x4, Aegis256X4, aegis256x4, Aegis256X4, 32);
