use std::hint::black_box;

use aegis::aegis128l::Aegis128L;
use aegis::aegis256::Aegis256;

use aegis::aegis128x2::Aegis128X2;
use aegis::aegis128x4::Aegis128X4;
use aegis::aegis256x2::Aegis256X2;
use aegis::aegis256x4::Aegis256X4;

use aegis::{aegis128l::Aegis128LMac, aegis128x2::Aegis128X2Mac, aegis128x4::Aegis128X4Mac};
use benchmark_simple::{Bench, Options};

fn test_aegis128l(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128L::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis128x2(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X2::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis128x4(m: &mut [u8]) {
    let key = [0u8; 16];
    let nonce = [0u8; 16];
    let state = Aegis128X4::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis256(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis256x2(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256X2::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis256x4(m: &mut [u8]) {
    let key = [0u8; 32];
    let nonce = [0u8; 32];
    let state = Aegis256X4::<16>::new(&nonce, &key);
    state.encrypt_in_place(m, &[]);
}

fn test_aegis128l_mac(m: &[u8]) {
    let key = [0u8; 16];
    let mut state = Aegis128LMac::<32>::new(&key);
    state.update(m);
    black_box(state.finalize());
}

fn test_aegis128x2_mac(m: &[u8]) {
    let key = [0u8; 16];
    let mut state = Aegis128X2Mac::<32>::new(&key);
    state.update(m);
    black_box(state.finalize());
}

fn test_aegis128x4_mac(m: &[u8]) {
    let key = [0u8; 16];
    let mut state = Aegis128X4Mac::<32>::new(&key);
    state.update(m);
    black_box(state.finalize());
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

    let res = bench.run(options, || test_aegis128x4_mac(&m));
    println!(
        "aegis128x4-mac      : {}",
        res.throughput_bits(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128x2_mac(&m));
    println!(
        "aegis128x2-mac      : {}",
        res.throughput_bits(m.len() as _)
    );

    let res = bench.run(options, || test_aegis128l_mac(&m));
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

    let res = bench.run(options, || test_aegis256x2(&mut m));
    println!(
        "aegis256x2          : {}",
        res.throughput_bits(m.len() as _)
    );

    let res = bench.run(options, || test_aegis256x4(&mut m));
    println!(
        "aegis256x4          : {}",
        res.throughput_bits(m.len() as _)
    );

    let res = bench.run(options, || test_aegis256(&mut m));
    println!(
        "aegis256            : {}",
        res.throughput_bits(m.len() as _)
    );
}
