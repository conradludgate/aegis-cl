//! CPU selection and the checked boundary around target-feature code.
//!
//! Choice selects a representation; Enabled proves its instruction requirements.
//! Native tokens come only from cached CPU checks. Consuming one enters a
//! specialized function, where the complete Operation is inlined.
//! Fully enabled builds bypass this path through statically_enabled.
#[cfg(target_arch = "x86_64")]
use crate::low::backend::{Aesni, Vaes256, Vaes512};
use crate::low::backend::{Backend, Portable};
use core::marker::PhantomData;

/// Evidence that executing this closed backend's instructions is supported.
/// The field is private; safe code outside this module cannot manufacture it.
#[derive(Clone, Copy)]
pub(super) struct Enabled<B: Backend>(PhantomData<B>);

pub(super) trait Operation<B: Backend, R> {
    /// The token establishes B's CPU preconditions. Implementations inline the
    /// complete processing loop into the selected entry, not just an AES round.
    fn run(self, enabled: Enabled<B>) -> R;
}

impl Enabled<Portable> {
    #[inline(always)]
    fn run<O: Operation<Portable, R>, R>(self, operation: O) -> R {
        operation.run(self)
    }
}

#[cfg(target_arch = "x86_64")]
macro_rules! entry {
    ($backend:ident, $features:literal) => {
        impl Enabled<$backend> {
            #[inline(always)]
            fn run<O: Operation<$backend, R>, R>(self, operation: O) -> R {
                #[target_feature(enable = $features)]
                #[inline]
                /// # Safety
                /// The CPU must support all features enabled on this entry.
                /// A valid token for the concrete backend establishes them.
                unsafe fn specialized<O: Operation<$backend, R>, R>(
                    enabled: Enabled<$backend>,
                    operation: O,
                ) -> R {
                    operation.run(enabled)
                }
                // SAFETY: A native Enabled token is constructed only after
                // Capabilities::get checks this backend's complete feature set.
                // That set matches specialized's target features exactly.
                // Moving/copying the token preserves this capability evidence.
                unsafe { specialized(self, operation) }
            }
        }
    };
}
#[cfg(target_arch = "x86_64")]
entry!(Aesni, "aes");
#[cfg(target_arch = "x86_64")]
entry!(Vaes256, "aes,avx2,vaes");
#[cfg(target_arch = "x86_64")]
entry!(Vaes512, "aes,avx2,vaes,avx512f");

#[cfg(target_arch = "x86_64")]
struct Capabilities {
    aesni: Option<Enabled<Aesni>>,
    vaes256: Option<Enabled<Vaes256>>,
    vaes512: Option<Enabled<Vaes512>>,
}
#[cfg(target_arch = "x86_64")]
impl Capabilities {
    fn get() -> &'static Self {
        static DETECTED: std::sync::OnceLock<Capabilities> = std::sync::OnceLock::new();
        DETECTED.get_or_init(|| {
            // Miri does not execute hardware backends. Scalar library tests
            // still cover the portable engine under the interpreter.
            #[cfg(miri)]
            {
                Self {
                    aesni: None,
                    vaes256: None,
                    vaes512: None,
                }
            }
            #[cfg(not(miri))]
            {
                let aesni = std::is_x86_feature_detected!("aes");
                let vaes256 = aesni
                    && std::is_x86_feature_detected!("avx2")
                    && std::is_x86_feature_detected!("vaes");
                let vaes512 = vaes256 && std::is_x86_feature_detected!("avx512f");
                Self {
                    // Construct evidence only in the supported branch.
                    aesni: if aesni {
                        Some(Enabled(PhantomData))
                    } else {
                        None
                    },
                    vaes256: if vaes256 {
                        Some(Enabled(PhantomData))
                    } else {
                        None
                    },
                    vaes512: if vaes512 {
                        Some(Enabled(PhantomData))
                    } else {
                        None
                    },
                }
            }
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum Choice {
    Portable(Enabled<Portable>),
    #[cfg(target_arch = "x86_64")]
    Aesni(Enabled<Aesni>),
    #[cfg(target_arch = "x86_64")]
    Vaes256(Enabled<Vaes256>),
    #[cfg(target_arch = "x86_64")]
    Vaes512(Enabled<Vaes512>),
}
impl Choice {
    #[inline]
    pub(super) fn detect(lanes: usize) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let caps = Capabilities::get();
            if lanes == 4
                && let Some(token) = caps.vaes512
            {
                return Self::Vaes512(token);
            }
            // The 256-bit entry also benefits scalar AES through VEX encoding;
            // algorithm lanes remain fixed even when only one lane is used.
            if let Some(token) = caps.vaes256 {
                return Self::Vaes256(token);
            }
            if let Some(token) = caps.aesni {
                return Self::Aesni(token);
            }
        }
        let _ = lanes;
        Self::Portable(Enabled(PhantomData))
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub(super) fn run<O, R>(self, operation: O) -> R
    where
        O: Operation<Portable, R>
            + Operation<Aesni, R>
            + Operation<Vaes256, R>
            + Operation<Vaes512, R>,
    {
        match self {
            Self::Portable(token) => token.run(operation),
            Self::Aesni(token) => token.run(operation),
            Self::Vaes256(token) => token.run(operation),
            Self::Vaes512(token) => token.run(operation),
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    pub(super) fn run<O: Operation<Portable, R>, R>(self, operation: O) -> R {
        let Self::Portable(token) = self;
        token.run(operation)
    }

    #[cfg(test)]
    pub(super) fn available() -> Vec<Self> {
        let mut all = vec![Self::Portable(Enabled(PhantomData))];
        #[cfg(target_arch = "x86_64")]
        {
            let caps = Capabilities::get();
            if let Some(token) = caps.aesni {
                all.push(Self::Aesni(token));
            }
            if let Some(token) = caps.vaes256 {
                all.push(Self::Vaes256(token));
            }
            if let Some(token) = caps.vaes512 {
                all.push(Self::Vaes512(token));
            }
        }
        all
    }
}

/// The cfg-selected engine is already the highest-priority backend. This is a
/// compile-time decision for each algorithm; no selector is stored or read.
#[inline(always)]
pub(super) const fn statically_enabled(lanes: usize) -> bool {
    if cfg!(miri) {
        return false;
    }
    if cfg!(target_arch = "x86_64") {
        cfg!(all(
            target_feature = "aes",
            target_feature = "avx2",
            target_feature = "vaes"
        )) && (lanes != 4 || cfg!(target_feature = "avx512f"))
    } else {
        // Other architectures currently have no additional runtime engine.
        true
    }
}
