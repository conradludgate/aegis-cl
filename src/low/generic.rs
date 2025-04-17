mod soft;

pub use soft::AesBlock;

mod polyfill_x2;

use polyfill_x2::AesBlock2;

mod polyfill_x4;
