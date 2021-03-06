extern mod test;

use std::libc::*;
use std::uint;

use test::aesni::*;

struct timespec {
    tv_sec: time_t,
    tv_nsec: c_long
}

type clockid_t = i32;

static CLOCK_MONOTONIC: clockid_t = 1;

extern {
    unsafe fn clock_gettime(clk_id: clockid_t, tp: *timespec) -> c_int;
}

fn get_ns() -> i64 {
    let ts = timespec {tv_sec: 0, tv_nsec: 0};
    unsafe { clock_gettime(CLOCK_MONOTONIC, &ts); }
    return ts.tv_sec * 1_000_000_000 + ts.tv_nsec;
}

fn main() {
    let key128: [u8, ..16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let key192: [u8, ..24] = [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b];
    let key256: [u8, ..32] = [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4];
    let plain: [u8, ..16] = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
    let cipher: [u8, ..16] = [0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97];

    let mut enc = AesEncryptor::new();
    enc.init(key128);

    let mut dec = AesDecryptor::new();
    dec.init(key128);

    let mut out1 = [0u8, ..16];
    let mut out2 = [0u8, ..16];

    let count = 60000000;

    let start_ns = get_ns();

    for uint::range(0, count) |_| {
        out1 = enc.encrypt_block(&plain);
//        out2 = dec.decrypt_block(&out1);
    }

    let end_ns = get_ns();

    let total_ns = (end_ns - start_ns);
    println(fmt!("time (ns): %?", total_ns));
    let total_ms = (end_ns - start_ns) / 1_000_000;
    println(fmt!("time (ms): %?", total_ms));
    let size_mb = count * plain.len() / 1024 / 1024;
    println(fmt!("size (mb): %?", size_mb));
    println(fmt!("size (mb/s): %?", (size_mb as f64) / (total_ms as f64) * 1000f64 ));
}
