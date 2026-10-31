//! Compare the same automatic AEAD API across portable and feature-enabled builds.
use aegis_cl::{
    Tag128,
    aead::{AeadInOut, KeyInit, inout::InOutBuf},
};
use divan::{Bencher, counter::BytesCount};
use std::hint::black_box;

fn main() {
    divan::main();
}

fn encrypt<C: AeadInOut + KeyInit>(b: Bencher, len: usize) {
    let key = aegis_cl::aead::Key::<C>::default();
    let nonce = aegis_cl::aead::Nonce::<C>::default();
    let mut data = vec![0xd0; len];
    b.counter(BytesCount::new(len)).bench_local(|| {
        let cipher = C::new(black_box(&key));
        black_box(
            cipher
                .encrypt_inout_detached(
                    black_box(&nonce),
                    black_box(&[]),
                    InOutBuf::from(black_box(&mut data[..])),
                )
                .unwrap(),
        );
    });
}

#[divan::bench(types = [
    aegis_cl::Aegis128L<Tag128>, aegis_cl::Aegis128X2<Tag128>,
    aegis_cl::Aegis128X4<Tag128>, aegis_cl::Aegis256<Tag128>,
    aegis_cl::Aegis256X2<Tag128>, aegis_cl::Aegis256X4<Tag128>
], args = [0, 33, 1024, 16384, 65536])]
fn automatic<C: AeadInOut + KeyInit>(b: Bencher, len: usize) {
    encrypt::<C>(b, len);
}
