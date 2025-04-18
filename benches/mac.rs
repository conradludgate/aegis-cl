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
        aegis128l::Aegis128LMac, aegis128x2::Aegis128X2Mac, aegis128x4::Aegis128X4Mac,
        aegis256::Aegis256Mac, aegis256x2::Aegis256X2Mac, aegis256x4::Aegis256X4Mac,
    };

    #[divan::bench]
    fn aegis128l(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = Aegis128LMac::<16>::new(&black_box(key));
            state.update(black_box(&m));
            black_box(state.finalize());
        });
    }
    #[divan::bench]
    fn aegis128x2(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = Aegis128X2Mac::<16>::new(&black_box(key));
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis128x4(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = Aegis128X4Mac::<16>::new(&black_box(key));
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis256(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = Aegis256Mac::<16>::new(&black_box(key));
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis256x2(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = Aegis256X2Mac::<16>::new(&black_box(key));
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis256x4(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = Aegis256X4Mac::<16>::new(&black_box(key));
            state.update(black_box(&m));
            state.finalize()
        });
    }
}

mod aegis_cl {
    use divan::Bencher;
    use divan::counter::BytesCount;

    use std::hint::black_box;

    use aegis_cl::{
        AegisMac128L, AegisMac128X2, AegisMac128X4, AegisMac256, AegisMac256X2, AegisMac256X4,
        Tag128,
    };
    use digest::{Mac, crypto_common::KeyIvInit};

    #[divan::bench]
    fn aegis128l(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = AegisMac128L::<Tag128>::new(&black_box(key).into(), &[0u8; 16].into());
            state.update(black_box(&m));
            black_box(state.finalize());
        });
    }
    #[divan::bench]
    fn aegis128x2(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = AegisMac128X2::<Tag128>::new(&black_box(key).into(), &[0u8; 16].into());
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis128x4(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 16];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = AegisMac128X4::<Tag128>::new(&black_box(key).into(), &[0u8; 16].into());
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis256(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = AegisMac256::<Tag128>::new(&black_box(key).into(), &[0u8; 32].into());
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis256x2(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = AegisMac256X2::<Tag128>::new(&black_box(key).into(), &[0u8; 32].into());
            state.update(black_box(&m));
            state.finalize()
        });
    }
    #[divan::bench]
    fn aegis256x4(b: Bencher) {
        let m = vec![0xd0u8; 65536];
        let key = [0u8; 32];

        b.counter(BytesCount::of_slice(&m)).bench_local(|| {
            let mut state = AegisMac256X4::<Tag128>::new(&black_box(key).into(), &[0u8; 32].into());
            state.update(black_box(&m));
            state.finalize()
        });
    }
}
