#![allow(unused_imports)]

// todo: software impl?
mod avx_l;
pub use avx_l::AesBlock;

cfg_if::cfg_if! {
    if #[cfg(all(target_feature="avx2",target_feature="vaes"))] {
        mod avx2_x2;
        use avx2_x2::AesBlock2;
    } else {
        mod polyfill_x2 {
            include!("generic/polyfill_x2.rs");
        }
        use polyfill_x2::AesBlock2;
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(target_feature="avx512f",target_feature="vaes"))] {
        mod avx512_x4;
        use avx512_x4::AesBlock4;
    } else {
        mod polyfill_x4 {
            include!("generic/polyfill_x4.rs");
        }
        use polyfill_x4::AesBlock4;
    }
}
