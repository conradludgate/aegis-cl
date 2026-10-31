//! Native block types are private in a portable build. They are used only inside
//! runtime entry points after CPU detection, or through compile-time aliases
//! whose global target features establish the same instruction requirements.
//! Backend is sealed, so downstream safe code cannot select a native backend
//! without satisfying one of those two boundaries.
mod avx_l;
pub use avx_l::AesBlock;
pub(crate) mod avx2_x2;
pub(crate) mod avx512_x4;

pub(crate) mod aesni {
    pub use super::AesBlock;
    mod pair {
        include!("generic/polyfill_x2.rs");
    }
    pub use pair::AesBlock2;
    mod quad {
        include!("generic/polyfill_x4.rs");
    }
    pub use quad::AesBlock4;
}

pub(crate) mod vaes {
    pub use super::AesBlock;
    pub use super::avx2_x2::AesBlock2;
    mod quad {
        include!("generic/polyfill_x4.rs");
    }
    pub use quad::AesBlock4;
}

#[cfg(target_feature = "aes")]
cfg_if::cfg_if! {
    if #[cfg(all(target_feature="avx2",target_feature="vaes"))] {
        pub use avx2_x2::AesBlock2;
    } else {
        pub use aesni::AesBlock2;
    }
}
#[cfg(target_feature = "aes")]
cfg_if::cfg_if! {
    if #[cfg(all(target_feature="avx512f",target_feature="vaes"))] {
        pub use avx512_x4::AesBlock4;
    } else if #[cfg(all(target_feature="avx2",target_feature="vaes"))] {
        pub use vaes::AesBlock4;
    } else {
        pub use aesni::AesBlock4;
    }
}
