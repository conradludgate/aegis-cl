use aead::inout::{InOut, InOutBuf};
use hybrid_array::{Array, ArraySize};

use crate::{AegisParallel, arch::AesBlock};

pub fn process_inout_chunks_padded<'in_, 'out, T: ArraySize>(
    buffer: InOutBuf<'in_, 'out, u8>,
    mut f: impl for<'in2, 'out2> FnMut(InOut<'in2, 'out2, Array<u8, T>>),
) {
    let (msg_chunks, mut msg_tail) = buffer.into_chunks();
    for msg_chunk in msg_chunks {
        f(msg_chunk);
    }
    if !msg_tail.is_empty() {
        let len = msg_tail.len();
        let mut msg_chunk = Array::default();
        msg_chunk[..len].copy_from_slice(msg_tail.get_in());
        f(InOut::from(&mut msg_chunk));
        msg_tail.get_out().copy_from_slice(&msg_chunk[..len]);
    }
}

pub fn process_chunks_padded<T: ArraySize>(data: &[u8], mut f: impl FnMut(&Array<u8, T>)) {
    let (chunks, tail) = Array::slice_as_chunks(data);
    for ad_chunk in chunks {
        f(ad_chunk);
    }
    if !tail.is_empty() {
        let mut chunk = Array::default();
        chunk[..tail.len()].copy_from_slice(tail);
        f(&chunk);
    }
}

pub fn ctx<D: AegisParallel>() -> D::AesBlock {
    Array::from_fn(|i| {
        let mut a = [0; 16];
        a[0] = i as u8;
        a[1] = D::U8 - 1;
        AesBlock::from_bytes(&a)
    })
    .into()
}

pub fn bits(bytes: usize) -> aead::Result<u64> {
    u64::try_from(bytes)
        .ok()
        .and_then(|b| b.checked_mul(8))
        .ok_or(aead::Error)
}
