use aead::{
    AeadInOut, KeyInit,
    consts::{U16, U32},
    inout::InOutBuf,
};
use aegis_cl::{Aegis128L, Aegis128X2, Aegis128X4, AegisMac128L, AegisMac128X2, AegisMac128X4};
use benchmark_simple::{Bench, Options};
use digest::{Mac, crypto_common::KeyIvInit};

fn test_aegis128l(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::<U16>::new(&key.into());
    state
        .encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(m))
        .unwrap();
}

fn test_aegis128x2(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X2::<U16>::new(&key.into());
    state
        .encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(m))
        .unwrap();
}

fn test_aegis128x4(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X4::<U16>::new(&key.into());
    state
        .encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(m))
        .unwrap();
}

// fn test_aegis256(m: &mut [u8]) {
//     let key = [0u8; 32];
//     let nonce = [0u8; 32];
//     let state = Aegis256::<16>::new(&key.into());
//     state.encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(m));
// }

// fn test_aegis256x2(m: &mut [u8]) {
//     let key = [0u8; 32];
//     let nonce = [0u8; 32];
//     let state = Aegis256X2::<16>::new(&key.into());
//     state.encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(m));
// }

// fn test_aegis256x4(m: &mut [u8]) {
//     let key = [0u8; 32];
//     let nonce = [0u8; 32];
//     let state = Aegis256X4::<16>::new(&key.into());
//     state.encrypt_inout_detached(&nonce.into(), &[], InOutBuf::from(m));
// }

fn test_aegis128l_mac(state: &AegisMac128L<U32>, m: &[u8]) {
    let mut state = state.clone();
    state.update(m);
    state.finalize();
}

fn test_aegis128x2_mac(state: &AegisMac128X2<U32>, m: &[u8]) {
    let mut state = state.clone();
    state.update(m);
    state.finalize();
}

fn test_aegis128x4_mac(state: &AegisMac128X4<U32>, m: &[u8]) {
    let mut state = state.clone();
    state.update(m);
    state.finalize();
}

fn main() {
    let bench = Bench::new();

    let options = &Options {
        iterations: 250_000,
        warmup_iterations: 1_000,
        min_samples: 5,
        max_samples: 15,
        max_rsd: 1.0,
        ..Default::default()
    };

    let m = vec![0xd0u8; 65536];

    println!("* MACs:");
    println!();

    let state = AegisMac128X4::<U32>::new(&[0u8; 16].into(), &[0u8; 16].into());
    let res = bench.run(options, || test_aegis128x4_mac(&state, &m));
    println!(
        "aegis128x4-mac      : {}",
        res.throughput_bits(m.len() as _)
    );

    let state = AegisMac128X2::<U32>::new(&[0u8; 16].into(), &[0u8; 16].into());
    let res = bench.run(options, || test_aegis128x2_mac(&state, &m));
    println!(
        "aegis128x2-mac      : {}",
        res.throughput_bits(m.len() as _)
    );

    let state = AegisMac128L::<U32>::new(&[0u8; 16].into(), &[0u8; 16].into());
    let res = bench.run(options, || test_aegis128l_mac(&state, &m));
    println!(
        "aegis128l-mac       : {}",
        res.throughput_bits(m.len() as _)
    );

    println!();

    let mut m = vec![0xd0u8; 16384];

    println!("* Encryption:");
    println!();

    let res = bench.run(options, || test_aegis128x4(&mut m));
    println!(
        "aegis128x4          : {}",
        res.throughput_bits(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128x2(&mut m));
    println!(
        "aegis128x2          : {}",
        res.throughput_bits(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128l(&mut m));
    println!(
        "aegis128l           : {}",
        res.throughput_bits(m.len() as _)
    );

    // let res = bench.run(options, || test_aegis256x2(&mut m));
    // println!(
    //     "aegis256x2          : {}",
    //     res.throughput_bits(m.len() as _)
    // );

    // let res = bench.run(options, || test_aegis256x4(&mut m));
    // println!(
    //     "aegis256x4          : {}",
    //     res.throughput_bits(m.len() as _)
    // );

    // let res = bench.run(options, || test_aegis256(&mut m));
    // println!(
    //     "aegis256            : {}",
    //     res.throughput_bits(m.len() as _)
    // );
}
