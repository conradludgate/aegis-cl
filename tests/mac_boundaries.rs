use aegis_cl::{
    digest::{Mac, crypto_common::KeyIvInit},
    hybrid_array::Array,
};

macro_rules! mac_cases {
    ($test:ident, $ours:ident, $reference_module:ident, $reference:ident, $key_len:expr, $tag:ident, $tag_len:expr) => {
        #[test]
        fn $test() {
            let key = [0x42; $key_len];
            let nonce = [0x24; $key_len];
            let mut mismatches = Vec::new();
            for len in [
                0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
            ] {
                let data: Vec<_> = (0..len).map(|n| n as u8).collect();
                let mut reference =
                    aegis::$reference_module::$reference::<$tag_len>::new_with_nonce(&key, &nonce);
                reference.update(&data);
                let expected = reference.finalize();
                for chunk_size in [1, 3, 16, 31, 64, 257] {
                    let mut ours =
                        aegis_cl::$ours::<aegis_cl::$tag>::new(&Array(key), &Array(nonce));
                    for chunk in data.chunks(chunk_size) {
                        Mac::update(&mut ours, chunk);
                    }
                    let actual = ours.finalize().into_bytes();
                    if actual.as_slice() != expected {
                        mismatches.push((len, chunk_size));
                    }
                }
            }
            assert!(
                mismatches.is_empty(),
                "MAC length/chunk mismatches: {mismatches:?}"
            );
        }
    };
}

mac_cases!(
    mac_128l_tag128,
    AegisMac128L,
    aegis128l,
    Aegis128LMac,
    16,
    Tag128,
    16
);
mac_cases!(
    mac_128l_tag256,
    AegisMac128L,
    aegis128l,
    Aegis128LMac,
    16,
    Tag256,
    32
);
mac_cases!(
    mac_128x2_tag128,
    AegisMac128X2,
    aegis128x2,
    Aegis128X2Mac,
    16,
    Tag128,
    16
);
mac_cases!(
    mac_128x2_tag256,
    AegisMac128X2,
    aegis128x2,
    Aegis128X2Mac,
    16,
    Tag256,
    32
);
mac_cases!(
    mac_128x4_tag128,
    AegisMac128X4,
    aegis128x4,
    Aegis128X4Mac,
    16,
    Tag128,
    16
);
mac_cases!(
    mac_128x4_tag256,
    AegisMac128X4,
    aegis128x4,
    Aegis128X4Mac,
    16,
    Tag256,
    32
);
mac_cases!(
    mac_256_tag128,
    AegisMac256,
    aegis256,
    Aegis256Mac,
    32,
    Tag128,
    16
);
mac_cases!(
    mac_256_tag256,
    AegisMac256,
    aegis256,
    Aegis256Mac,
    32,
    Tag256,
    32
);
mac_cases!(
    mac_256x2_tag128,
    AegisMac256X2,
    aegis256x2,
    Aegis256X2Mac,
    32,
    Tag128,
    16
);
mac_cases!(
    mac_256x2_tag256,
    AegisMac256X2,
    aegis256x2,
    Aegis256X2Mac,
    32,
    Tag256,
    32
);
mac_cases!(
    mac_256x4_tag128,
    AegisMac256X4,
    aegis256x4,
    Aegis256X4Mac,
    32,
    Tag128,
    16
);
mac_cases!(
    mac_256x4_tag256,
    AegisMac256X4,
    aegis256x4,
    Aegis256X4Mac,
    32,
    Tag256,
    32
);
