//! Whole-operation CPU dispatch behind the existing AEAD API.
//!
//! The call path is `high::Aegis` -> `AegisCore`'s AEAD hooks -> this module.
//! Custom cores use the hooks' default static engine. Built-in cores arrive here
//! with a fixed algorithm (128/256, X1/X2/X4), independent of CPU representation.
//!
//! If the cfg-selected backend is already sufficient, call the engine directly.
//! Otherwise select a checked backend and enter its target-feature function.
//! The operation inlines the complete `high` engine there, keeping detection
//! outside the block loops. Engine helpers bypass the hooks, avoiding redispatch.
use crate::{
    high::AegisTag,
    low::backend::Backend,
    mid::{AegisCore, AegisParallel, State128X, State256X},
};
use aead::inout::InOutBuf;
use cipher::typenum::Unsigned;
use core::marker::PhantomData;
use hybrid_array::Array;

#[allow(unsafe_code)]
mod dispatch;
use dispatch::{Choice, Enabled, Operation};

// Changing CPU representation must preserve the algorithm's lane count.
// This trait is public only to satisfy the private lane-mapping bounds in mid;
// the runtime module itself is private, so downstream code cannot implement it.
pub trait Algorithm: AegisCore {
    type Core<B: Backend>: AegisCore<Key = Self::Key>;
    const LANES: usize;
    // Concrete backend cores bypass selection; only the default core detects.
    const AUTO_DETECT: bool;
}
macro_rules! algorithm {
    ($state:ident, $lanes:ident) => {
        impl<B: Backend> Algorithm for $state<crate::$lanes, B> {
            type Core<Other: Backend> = $state<crate::$lanes, Other>;
            const LANES: usize = <crate::$lanes as AegisParallel>::Blocks::USIZE;
            const AUTO_DETECT: bool = B::AUTO_DETECT;
        }
    };
}
algorithm!(State128X, X1);
algorithm!(State128X, X2);
algorithm!(State128X, X4);
algorithm!(State256X, X1);
algorithm!(State256X, X2);
algorithm!(State256X, X4);

#[inline(always)]
pub(crate) fn encrypt<A: Algorithm, T: AegisTag>(
    key: &Array<u8, A::Key>,
    nonce: &Array<u8, A::Key>,
    ad: &[u8],
    data: InOutBuf<'_, '_, u8>,
) -> aead::Result<Array<u8, T::Size>> {
    if !A::AUTO_DETECT || dispatch::statically_enabled(A::LANES) {
        return crate::high::encrypt::<A, T>(key, nonce, ad, data);
    }
    Choice::detect(A::LANES).run(Encrypt::<A, T> {
        key,
        nonce,
        ad,
        data,
        marker: PhantomData,
    })
}

#[inline(always)]
pub(crate) fn decrypt<A: Algorithm, T: AegisTag>(
    key: &Array<u8, A::Key>,
    nonce: &Array<u8, A::Key>,
    ad: &[u8],
    data: InOutBuf<'_, '_, u8>,
    tag: &Array<u8, T::Size>,
) -> aead::Result<()> {
    if !A::AUTO_DETECT || dispatch::statically_enabled(A::LANES) {
        return crate::high::decrypt::<A, T>(key, nonce, ad, data, tag);
    }
    Choice::detect(A::LANES).run(Decrypt::<A, T> {
        key,
        nonce,
        ad,
        data,
        tag,
    })
}

struct Encrypt<'a, 'i, 'o, A: Algorithm, T: AegisTag> {
    key: &'a Array<u8, A::Key>,
    nonce: &'a Array<u8, A::Key>,
    ad: &'a [u8],
    data: InOutBuf<'i, 'o, u8>,
    marker: PhantomData<T>,
}
impl<A: Algorithm, T: AegisTag, B: Backend> Operation<B, aead::Result<Array<u8, T::Size>>>
    for Encrypt<'_, '_, '_, A, T>
{
    #[inline(always)]
    fn run(self, _enabled: Enabled<B>) -> aead::Result<Array<u8, T::Size>> {
        crate::high::encrypt::<A::Core<B>, T>(self.key, self.nonce, self.ad, self.data)
    }
}
struct Decrypt<'a, 'i, 'o, A: Algorithm, T: AegisTag> {
    key: &'a Array<u8, A::Key>,
    nonce: &'a Array<u8, A::Key>,
    ad: &'a [u8],
    data: InOutBuf<'i, 'o, u8>,
    tag: &'a Array<u8, T::Size>,
}
impl<A: Algorithm, T: AegisTag, B: Backend> Operation<B, aead::Result<()>>
    for Decrypt<'_, '_, '_, A, T>
{
    #[inline(always)]
    fn run(self, _enabled: Enabled<B>) -> aead::Result<()> {
        crate::high::decrypt::<A::Core<B>, T>(self.key, self.nonce, self.ad, self.data, self.tag)
    }
}

#[cfg(test)]
mod tests;
