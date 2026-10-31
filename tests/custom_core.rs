//! Existing generic/custom cores retain the default complete AEAD engine.
use aegis_cl::{
    Aegis128L, Aegis128X4, Aegis256X4, Tag128, X1,
    aead::{AeadInOut, KeyInit, inout::InOut},
    high::Aegis,
    hybrid_array::{
        Array,
        sizes::{U16, U32},
    },
    mid::{AegisCore, State128X},
};

#[derive(Clone, Copy)]
struct CustomCore(State128X<X1>);

// Deliberately implements only the original core methods, without the new
// complete-operation hooks. No runtime algorithm mapping exists for this type.
impl AegisCore for CustomCore {
    type Key = U16;
    type Block = U32;
    fn new(key: &Array<u8, U16>, nonce: &Array<u8, U16>) -> Self {
        Self(State128X::new(key, nonce))
    }
    fn encrypt_emtpy_block(&mut self, block: &mut Array<u8, U32>) {
        self.0.encrypt_emtpy_block(block);
    }
    fn encrypt_block(&mut self, block: InOut<'_, '_, Array<u8, U32>>) {
        self.0.encrypt_block(block);
    }
    fn decrypt_block(&mut self, block: InOut<'_, '_, Array<u8, U32>>) {
        self.0.decrypt_block(block);
    }
    fn decrypt_partial_block(&mut self, block: InOut<'_, '_, Array<u8, U32>>, len: usize) {
        self.0.decrypt_partial_block(block, len);
    }
    fn absorb(&mut self, block: &Array<u8, U32>) {
        self.0.absorb(block);
    }
    fn finalize128(self, ad: u64, msg: u64) -> [u8; 16] {
        self.0.finalize128(ad, msg)
    }
    fn finalize256(self, ad: u64, msg: u64) -> [u8; 32] {
        self.0.finalize256(ad, msg)
    }
    fn finalize_mac128(self, len: u64) -> [u8; 16] {
        self.0.finalize_mac128(len)
    }
    fn finalize_mac256(self, len: u64) -> [u8; 32] {
        self.0.finalize_mac256(len)
    }
}

#[test]
fn original_type_identity_and_storage() {
    let _: Aegis<State128X<X1>, Tag128> = Aegis128L::new(&[0; 16].into());
    assert_eq!(size_of::<Aegis128L<Tag128>>(), 16);
    assert_eq!(size_of::<Aegis128X4<Tag128>>(), 16);
    assert_eq!(size_of::<Aegis256X4<Tag128>>(), 32);
}

#[test]
fn custom_core_uses_default_engine() {
    let key = [0x42; 16].into();
    let nonce = [0x24; 16].into();
    let custom = Aegis::<CustomCore, Tag128>::new(&key);
    let automatic = Aegis128L::<Tag128>::new(&key);
    let mut expected = [0x81; 65];
    let mut actual = expected;
    let tag = automatic
        .encrypt_inout_detached(&nonce, b"ad", (&mut expected[..]).into())
        .unwrap();
    assert_eq!(
        custom
            .encrypt_inout_detached(&nonce, b"ad", (&mut actual[..]).into())
            .unwrap(),
        tag
    );
    assert_eq!(actual, expected);
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    assert!(
        custom
            .decrypt_inout_detached(&nonce, b"ad", (&mut actual[..]).into(), &bad_tag)
            .is_err()
    );
    assert_eq!(actual, expected);
    custom
        .decrypt_inout_detached(&nonce, b"ad", (&mut actual[..]).into(), &tag)
        .unwrap();
    assert_eq!(actual, [0x81; 65]);
}
