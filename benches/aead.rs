fn main() {
    divan::Divan::from_args()
        .sample_size(1000)
        .sample_count(1000)
        .main();
}

mod libaegis {
    use divan::Bencher;
    use divan::counter::BytesCount;

    use std::hint::black_box;

    use aegis::{
        aegis128l::Aegis128L, aegis128x2::Aegis128X2, aegis128x4::Aegis128X4, aegis256::Aegis256,
        aegis256x2::Aegis256X2, aegis256x4::Aegis256X4,
    };

    #[divan::bench]
    fn aegis128l(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis128L::<16>::new(&black_box(nonce), &black_box(key));
            state.encrypt_in_place(black_box(&mut m), &[])
        });
    }
    #[divan::bench]
    fn aegis128x2(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis128X2::<16>::new(&black_box(nonce), &black_box(key));
            state.encrypt_in_place(black_box(&mut m), &[])
        });
    }
    #[divan::bench]
    fn aegis128x4(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis128X4::<16>::new(&black_box(nonce), &black_box(key));
            state.encrypt_in_place(black_box(&mut m), &[])
        });
    }
    #[divan::bench]
    fn aegis256(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis256::<16>::new(&black_box(nonce), &black_box(key));
            state.encrypt_in_place(black_box(&mut m), &[])
        });
    }
    #[divan::bench]
    fn aegis256x2(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis256X2::<16>::new(&black_box(nonce), &black_box(key));
            state.encrypt_in_place(black_box(&mut m), &[])
        });
    }
    #[divan::bench]
    fn aegis256x4(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis256X4::<16>::new(&black_box(nonce), &black_box(key));
            state.encrypt_in_place(black_box(&mut m), &[])
        });
    }
}

mod aegis_cl {
    use divan::Bencher;
    use divan::counter::BytesCount;

    use std::hint::black_box;

    use aead::{AeadInOut, KeyInit, inout::InOutBuf};
    use aegis_cl::{Aegis128L, Aegis128X2, Aegis128X4, Aegis256, Aegis256X2, Aegis256X4, Tag128};

    #[divan::bench]
    fn aegis128l(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis128L::<Tag128>::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut *m)),
            )
        });
    }
    #[divan::bench]
    fn aegis128x2(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis128X2::<Tag128>::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut *m)),
            )
        });
    }
    #[divan::bench]
    fn aegis128x4(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 16];
        let nonce = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis128X4::<Tag128>::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut *m)),
            )
        });
    }
    #[divan::bench]
    fn aegis256(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis256::<Tag128>::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut *m)),
            )
        });
    }
    #[divan::bench]
    fn aegis256x2(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis256X2::<Tag128>::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut *m)),
            )
        });
    }
    #[divan::bench]
    fn aegis256x4(b: Bencher) {
        let mut m = vec![0xd0u8; 16384];
        let key = [0u8; 32];
        let nonce = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let state = Aegis256X4::<Tag128>::new(&black_box(key).into());
            state.encrypt_inout_detached(
                &black_box(nonce).into(),
                &[],
                InOutBuf::from(black_box(&mut *m)),
            )
        });
    }
}
