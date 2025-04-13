// *  C0: an AES block built from the following bytes in hexadecimal
// format: { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15,
// 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }.
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];

// *  C1: an AES block built from the following bytes in hexadecimal
// format: { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20,
// 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }.
const C1: [u8; 16] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

#[cfg(all(target_arch = "aarch64", target_feature = "aes"))]
mod aarch64 {
    mod aegis128;
    mod aegis256;
}

// const N: usize = 100000000;
// const D: usize = 16;
// #[test]
// fn bench128() {
//     let x = unsafe {
//         vld1q_u8(const { [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] }.as_ptr())
//     };

//     let mut s = [State128(x, x, x, x, x, x, x, x); D];
//     let m = [(x, x); D];

//     let start = Instant::now();
//     for _ in 0..N {
//         s = update128(black_box(s), black_box(m))
//     }
//     black_box(s);
//     dbg!(start.elapsed() * 1000 / D as u32 / N as u32);
// }

// #[test]
// fn bench256() {
//     let x = unsafe {
//         vld1q_u8(const { [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] }.as_ptr())
//     };

//     let mut s = [State256(x, x, x, x, x, x); D];
//     let m = [x; D];

//     let start = Instant::now();
//     for _ in 0..N {
//         s = update256(black_box(s), black_box(m));
//         s = update256(black_box(s), black_box(m));
//     }
//     black_box(s);
//     dbg!(start.elapsed() * 1000 / D as u32 / N as u32);
// }
