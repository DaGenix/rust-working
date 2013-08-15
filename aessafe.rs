// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::uint;

use cryptoutil::*;
use symmetriccipher::*;


macro_rules! define_aes_struct(
    (
        $name:ident,
        $rounds:expr
    ) => (
        struct $name {
            round_keys: [[u32, ..4], ..$rounds + 1],
            sk: [bs8_state, ..$rounds + 1]
        }
    )
)

macro_rules! define_aes_impl(
    (
        $name:ident,
        $mode:ident,
        $rounds:expr,
        $key_size:expr
    ) => (
        impl $name {
            pub fn new(key: &[u8]) -> $name {
                let mut a =  $name {
                    round_keys: [[0u32, ..4], ..$rounds + 1],
                    sk: [(0,0,0,0,0,0,0,0), ..$rounds + 1]
                };
                setup_round_keys(key, $mode, a.round_keys, a.sk);
                return a;
            }
        }
    )
)

macro_rules! define_aes_enc(
    (
        $name:ident,
        $rounds:expr
    ) => (
        impl BlockEncryptor for $name {
            fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
                encrypt_block($rounds, input, self.sk, output);
            }
        }
    )
)

macro_rules! define_aes_dec(
    (
        $name:ident,
        $rounds:expr
    ) => (
        impl BlockDecryptor for $name {
            fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
                decrypt_block($rounds, input, self.round_keys, output);
            }
        }
    )
)

define_aes_struct!(AesSafe128Encryptor, 10)
define_aes_struct!(AesSafe128Decryptor, 10)
define_aes_impl!(AesSafe128Encryptor, Encryption, 10, 16)
define_aes_impl!(AesSafe128Decryptor, Decryption, 10, 16)
define_aes_enc!(AesSafe128Encryptor, 10)
define_aes_dec!(AesSafe128Decryptor, 10)

define_aes_struct!(AesSafe192Encryptor, 12)
define_aes_struct!(AesSafe192Decryptor, 12)
define_aes_impl!(AesSafe192Encryptor, Encryption, 12, 24)
define_aes_impl!(AesSafe192Decryptor, Decryption, 12, 24)
define_aes_enc!(AesSafe192Encryptor, 12)
define_aes_dec!(AesSafe192Decryptor, 12)

define_aes_struct!(AesSafe256Encryptor, 14)
define_aes_struct!(AesSafe256Decryptor, 14)
define_aes_impl!(AesSafe256Encryptor, Encryption, 14, 32)
define_aes_impl!(AesSafe256Decryptor, Decryption, 14, 32)
define_aes_enc!(AesSafe256Encryptor, 14)
define_aes_dec!(AesSafe256Decryptor, 14)


fn shift(r: u32, shift: u32) -> u32 {
    return (r >> shift) | (r << (32 - shift));
}

fn ffmulx(x: u32) -> u32 {
    static m1: u32 = 0x80808080;
    static m2: u32 = 0x7f7f7f7f;
    static m3: u32 = 0x0000001b;

    return ((x & m2) << 1) ^ (((x & m1) >> 7) * m3);
}

// Mix columns step
fn mcol(x: u32) -> u32 {
    let f2 = ffmulx(x);
    return f2 ^ shift(x ^ f2, 8) ^ shift(x, 16) ^ shift(x, 24);
}

// The inverse mix columns step
fn inv_mcol(x: u32) -> u32 {
    let f2 = ffmulx(x);
    let f4 = ffmulx(f2);
    let f8 = ffmulx(f4);
    let f9 = x ^ f8;

    return f2 ^ f4 ^ f8 ^ shift(f2 ^ f9, 8) ^ shift(f4 ^ f9, 16) ^ shift(f9, 24);
}

fn sub_word(x: u32) -> u32 {
    return s(x) | (s(x >> 8) << 8) | (s(x >> 16) << 16) | (s(x >> 24) << 24);
}

enum KeyType {
    Encryption,
    Decryption
}

fn setup_round_keys(key: &[u8], key_type: KeyType, round_keys: &mut [[u32, ..4]], sk: &mut [bs8_state]) {
    let (key_words, rounds) = match key.len() {
        16 => (4, 10u),
        24 => (6, 12u),
        32 => (8, 14u),
        _ => fail!("Invalid AES key size.")
    };

    // They key becomes the first few round keys - just copy it directly
    let mut j = 0;
    do uint::range_step(0, key.len(), 4) |i| {
        round_keys[j / 4][j % 4] =
            (key[i] as u32) |
            ((key[i+1] as u32) << 8) |
            ((key[i+2] as u32) << 16) |
            ((key[i+3] as u32) << 24);
        j += 1;
        true
    };

    // Calculate the rest of the round keys
    for i in range(key_words, (rounds + 1) * 4) {
        let mut temp = round_keys[(i - 1) / 4][(i - 1) % 4];
        if (i % key_words) == 0 {
            temp = sub_word(shift(temp, 8)) ^ RCON[(i / key_words) - 1];
        } else if (key_words == 8) && ((i % key_words) == 4) {
            // This is only necessary for AES-256 keys
            temp = sub_word(temp);
        }
        round_keys[i / 4][i % 4] = round_keys[(i - key_words) / 4][(i - key_words) % 4] ^ temp;
    }

    for i in range(0, rounds + 1) {
        sk[i] = bs8(round_keys[i][0], round_keys[i][1], round_keys[i][2], round_keys[i][3])
    }

    // Decryption round keys require extra processing
    match key_type {
        Decryption => {
            for j in range(1, rounds) {
                for i in range(0, 4) {
                    round_keys[j][i] = inv_mcol(round_keys[j][i]);
                }
            }
        },
        Encryption => { }
    }
}

fn shift_rows(bs: bs8_state) -> bs8_state {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    fn sr(x: u32) -> u32 {
        // first 4 bits represent first row - don't shift
        (x & 0x000f) |
        // next 4 bits represent 2nd row - left rotate 1 bit
        ((x & 0x00e0) >> 1) | ((x & 0x0010) << 3) |
        // next 4 bits represent 3rd row - left rotate 2 bits
        ((x & 0x0c00) >> 2) | ((x & 0x0300) << 2) |
        // next 4 bits represent 4th row - left rotate 3 bits
        ((x & 0x8000) >> 3) | ((x & 0x7000) << 1)
    }

    (sr(bs0), sr(bs1), sr(bs2), sr(bs3), sr(bs4), sr(bs5), sr(bs6), sr(bs7))
}

fn mix_columns(bs: bs8_state) -> bs8_state {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    fn rl4(x: u32) -> u32 {
        ((x >> 4) & 0x0fff) | (x << 12)
    }

    fn rl8(x: u32) -> u32 {
        ((x >> 8) & 0x00ff) | (x << 8)
    }

    let bs0out = (bs7 ^ rl4(bs7)) ^ rl4(bs0) ^ rl8(bs0 ^ rl4(bs0));
    let bs1out = (bs0 ^ rl4(bs0)) ^ (bs7 ^ rl4(bs7)) ^ rl4(bs1) ^ rl8(bs1 ^ rl4(bs1));
    let bs2out = (bs1 ^ rl4(bs1)) ^ rl4(bs2) ^ rl8(bs2 ^ rl4(bs2));
    let bs3out = (bs2 ^ rl4(bs2)) ^ (bs7 ^ rl4(bs7)) ^ rl4(bs3) ^ rl8(bs3 ^ rl4(bs3));
    let bs4out = (bs3 ^ rl4(bs3)) ^ (bs7 ^ rl4(bs7)) ^ rl4(bs4) ^ rl8(bs4 ^ rl4(bs4));
    let bs5out = (bs4 ^ rl4(bs4)) ^ rl4(bs5) ^ rl8(bs5 ^ rl4(bs5));
    let bs6out = (bs5 ^ rl4(bs5)) ^ rl4(bs6) ^ rl8(bs6 ^ rl4(bs6));
    let bs7out = (bs6 ^ rl4(bs6)) ^ rl4(bs7) ^ rl8(bs7 ^ rl4(bs7));

    (bs0out, bs1out, bs2out, bs3out, bs4out, bs5out, bs6out, bs7out)
}

fn encrypt_block(rounds: uint, input: &[u8], sk: &[bs8_state], output: &mut [u8]) {
    let mut c = [0u32, ..4];
    read_u32v_le(c, input);

    let mut bs = bs8(c[0], c[1], c[2], c[3]);

    // Round 0 - add round key
    bs = bs8_xor(bs, sk[0]);

    // Remaining rounds (except last round)
    for i in range(1, rounds) {
        bs = sbox_bs(bs);
        bs = shift_rows(bs);
        bs = mix_columns(bs);
        bs = bs8_xor(bs, sk[i]);
    }

    // Last round
    bs = sbox_bs(bs);
    bs = shift_rows(bs);
    bs = bs8_xor(bs, sk[rounds]);

    let (c0, c1, c2, c3) = un_bs8(bs);

    write_u32_le(output.mut_slice(0, 4), c0);
    write_u32_le(output.mut_slice(4, 8), c1);
    write_u32_le(output.mut_slice(8, 12), c2);
    write_u32_le(output.mut_slice(12, 16), c3);
}

#[cfg(slow)]
fn encrypt_block(rounds: uint, input: &[u8], rk: &[[u32, ..4]], output: &mut [u8]) {
    fn sr(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        let w = (a & 0xff) | (b & 0xff00) | (c & 0xff0000) | (d & 0xff000000);
        let x = (b & 0xff) | (c & 0xff00) | (d & 0xff0000) | (a & 0xff000000);
        let y = (c & 0xff) | (d & 0xff00) | (a & 0xff0000) | (b & 0xff000000);
        let z = (d & 0xff) | (a & 0xff00) | (b & 0xff0000) | (c & 0xff000000);
        (w, x, y, z)
    }

    fn d(c0: u32, c1: u32, c2: u32, c3: u32) {
        printfln!("a: %x", c0 as uint);
        printfln!("b: %x", c1 as uint);
        printfln!("c: %x", c2 as uint);
        printfln!("d: %x", c3 as uint);
        println("");
    }

    let mut c = [0u32, ..4];
    read_u32v_le(c, input);

    let mut c0 = c[0];
    let mut c1 = c[1];
    let mut c2 = c[2];
    let mut c3 = c[3];

    c0 ^= rk[0][0];
    c1 ^= rk[0][1];
    c2 ^= rk[0][2];
    c3 ^= rk[0][3];

    for i in range(1, rounds) {
        // sub bytes
        let (t0, t1, t2, t3) = un_bs8(sbox_bs(bs8(c0, c1, c2, c3)));
        c0 = t0; c1 = t1; c2 = t2; c3 = t3;

        // shift rows
        let (t0, t1, t2, t3) = sr(c0, c1, c2, c3);
        c0 = t0; c1 = t1; c2 = t2; c3 = t3;

        // mix columns
        c0 = mcol(c0);
        c1 = mcol(c1);
        c2 = mcol(c2);
        c3 = mcol(c3);

        // add round key
        c0 ^= rk[i][0];
        c1 ^= rk[i][1];
        c2 ^= rk[i][2];
        c3 ^= rk[i][3];
    }

    // sub bytes
    let (t0, t1, t2, t3) = un_bs8(sbox_bs(bs8(c0, c1, c2, c3)));
    c0 = t0; c1 = t1; c2 = t2; c3 = t3;

    // shift rows
    let (t0, t1, t2, t3) = sr(c0, c1, c2, c3);
    c0 = t0; c1 = t1; c2 = t2; c3 = t3;

    // add round key
    c0 ^= rk[rounds][0];
    c1 ^= rk[rounds][1];
    c2 ^= rk[rounds][2];
    c3 ^= rk[rounds][3];

    write_u32_le(output.mut_slice(0, 4), c0);
    write_u32_le(output.mut_slice(4, 8), c1);
    write_u32_le(output.mut_slice(8, 12), c2);
    write_u32_le(output.mut_slice(12, 16), c3);
}

#[cfg(fast)]
fn encrypt_block(rounds: uint, input: &[u8], rk: &[[u32, ..4]], output: &mut [u8]) {
    fn op(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        printfln!("x: %x", ((v & 0xff) ^ (x & 0xff00) ^ (y & 0xff0000) ^ (z & 0xff000000)) as uint);
        return mcol((v & 0xff) ^ (x & 0xff00) ^ (y & 0xff0000) ^ (z & 0xff000000)) ^ k;
    }

    fn op_end(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return (v & 0xff) ^ (x & 0xff00) ^ (y & 0xff0000) ^ (z & 0xff000000) ^ k;
    }

    fn d(c0: u32, c1: u32, c2: u32, c3: u32) {
        printfln!("a: %x", c0 as uint);
        printfln!("b: %x", c1 as uint);
        printfln!("c: %x", c2 as uint);
        printfln!("d: %x", c3 as uint);
        println("");
    }

    let mut c = [0u32, ..4];
    read_u32v_le(c, input);

    let mut c0 = c[0];
    let mut c1 = c[1];
    let mut c2 = c[2];
    let mut c3 = c[3];

    c0 ^= rk[0][0];
    c1 ^= rk[0][1];
    c2 ^= rk[0][2];
    c3 ^= rk[0][3];

    let mut r = 1;
    while (r < rounds - 1) {
        let (t0, t1, t2, t3) = un_bs8(sbox_bs(bs8(c0, c1, c2, c3)));
        c0 = t0; c1 = t1; c2 = t2; c3 = t3;
        let mut r0 = op(c0, c1, c2, c3, rk[r][0]);
        let mut r1 = op(c1, c2, c3, c0, rk[r][1]);
        let mut r2 = op(c2, c3, c0, c1, rk[r][2]);
        let mut r3 = op(c3, c0, c1, c2, rk[r][3]);
        r += 1;

        println("");
//        d(r0, r1, r2, r3);

        let (t0, t1, t2, t3) = un_bs8(sbox_bs(bs8(r0, r1, r2, r3)));
        r0 = t0; r1 = t1; r2 = t2; r3 = t3;
        c0 = op(r0, r1, r2, r3, rk[r][0]);
        c1 = op(r1, r2, r3, r0, rk[r][1]);
        c2 = op(r2, r3, r0, r1, rk[r][2]);
        c3 = op(r3, r0, r1, r2, rk[r][3]);
        r += 1;

        println("");
//        d(c0, c1, c2, c3);
    }

    let (t0, t1, t2, t3) = un_bs8(sbox_bs(bs8(c0, c1, c2, c3)));
    c0 = t0; c1 = t1; c2 = t2; c3 = t3;
    let mut r0 = op(c0, c1, c2, c3, rk[r][0]);
    let mut r1 = op(c1, c2, c3, c0, rk[r][1]);
    let mut r2 = op(c2, c3, c0, c1, rk[r][2]);
    let mut r3 = op(c3, c0, c1, c2, rk[r][3]);
    r += 1;

    let (t0, t1, t2, t3) = un_bs8(sbox_bs(bs8(r0, r1, r2, r3)));
    r0 = t0; r1 = t1; r2 = t2; r3 = t3;
    c0 = op_end(r0, r1, r2, r3, rk[r][0]);
    c1 = op_end(r1, r2, r3, r0, rk[r][1]);
    c2 = op_end(r2, r3, r0, r1, rk[r][2]);
    c3 = op_end(r3, r0, r1, r2, rk[r][3]);

    write_u32_le(output.mut_slice(0, 4), c0);
    write_u32_le(output.mut_slice(4, 8), c1);
    write_u32_le(output.mut_slice(8, 12), c2);
    write_u32_le(output.mut_slice(12, 16), c3);
}


fn decrypt_block(rounds: uint, input: &[u8], rk: &[[u32, ..4]], output: &mut [u8]) {
    fn op(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return inv_mcol(s_inv(v) ^ (s_inv(x >> 8) << 8) ^ (s_inv(y >> 16) << 16) ^
            (s_inv(z >> 24) << 24)) ^ k;
    }

    fn op_end(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return s_inv(v) ^ (s_inv(x >> 8) << 8) ^ (s_inv(y >> 16) << 16) ^ (s_inv(z >> 24) << 24) ^
            k;
    }

    let mut r0: u32;
    let mut r1: u32;
    let mut r2: u32;
    let mut r3: u32;

    let mut c = [0u32, ..4];
    read_u32v_le(c, input);

    let mut c0 = c[0];
    let mut c1 = c[1];
    let mut c2 = c[2];
    let mut c3 = c[3];

    c0 ^= rk[rounds][0];
    c1 ^= rk[rounds][1];
    c2 ^= rk[rounds][2];
    c3 ^= rk[rounds][3];

    let mut r = rounds - 1;
    while (r > 1) {
        r0 = op(c0, c3, c2, c1, rk[r][0]);
        r1 = op(c1, c0, c3, c2, rk[r][1]);
        r2 = op(c2, c1, c0, c3, rk[r][2]);
        r3 = op(c3, c2, c1, c0, rk[r][3]);
        r -= 1;

        c0 = op(r0, r3, r2, r1, rk[r][0]);
        c1 = op(r1, r0, r3, r2, rk[r][1]);
        c2 = op(r2, r1, r0, r3, rk[r][2]);
        c3 = op(r3, r2, r1, r0, rk[r][3]);
        r -= 1;
    }

    r0 = op(c0, c3, c2, c1, rk[r][0]);
    r1 = op(c1, c0, c3, c2, rk[r][1]);
    r2 = op(c2, c1, c0, c3, rk[r][2]);
    r3 = op(c3, c2, c1, c0, rk[r][3]);
    r -= 1;

    c0 = op_end(r0, r3, r2, r1, rk[r][0]);
    c1 = op_end(r1, r0, r3, r2, rk[r][1]);
    c2 = op_end(r2, r1, r0, r3, rk[r][2]);
    c3 = op_end(r3, r2, r1, r0, rk[r][3]);

    write_u32_le(output.mut_slice(0, 4), c0);
    write_u32_le(output.mut_slice(4, 8), c1);
    write_u32_le(output.mut_slice(8, 12), c2);
    write_u32_le(output.mut_slice(12, 16), c3);
}


fn plex(a: u64, b: u64, c: u64) -> u64 {
    return (a & !c) | (b & c);
}

fn bsbit(a: u64, b: u64, c: u64, d: u64, x: u8) -> u8 {
    let e = plex(c, a, ((x & 0x01) as u64) - 1);
    let f = plex(d, b, ((x & 0x01) as u64) - 1);

    let g = plex(f, e, (((x & 0x02) >> 1) as u64) - 1);

    // todo - remove shift with by moving bits around!
    return ((g >> (63 - (x >> 2))) & 0x01) as u8;
}

fn sbox(x: u8) -> u8 {
    return
    bsbit(0x8293d868c05d12e6, 0xfcfc145199089b2b, 0x74e9baed7834375a, 0xea392fee711c22ba, x) |
    bsbit(0xdcc36b4447289134, 0xf7c972f3a98d1665, 0x584ff28b67e34c24, 0xb28ea5a951a2fd13, x) << 1 |
    bsbit(0x13ea0022f30f411c, 0xe464b210687fef62, 0x93ed45d7f3567a35, 0x5ad1196cea48ed5b, x) << 2 |
    bsbit(0x1f05d302c146f47c, 0x5800d3963ba511db, 0xc4d067f59709b8e2, 0xaa448fb8addfb73e, x) << 3 |
    bsbit(0x75f4689f4110c825, 0x81d16757b68a6f81, 0x96d62c3751b7baf3, 0x9c35a6a57b5023d1, x) << 4 |
    bsbit(0xf6f116021c8baac5, 0xf37996c522fbec13, 0xc1e174bb2681da8c, 0xbea36ab6b03e8a24, x) << 5 |
    bsbit(0xdc112bf8fbeb3ed2, 0xed60610b68162604, 0xd6985fe1132fa1d5, 0xdd6b0da5997a4834, x) << 6 |
    bsbit(0x5f810086a1bca1bd, 0x1ae3269306335ce9, 0x1bbc9eaf6a3c71ce, 0x476e79dd8d065370, x) << 7;
}

/// Get the S value using a fixed number of instructions
/// Only the bottom byte is used - basically the "idx" argument is a u8, but this lets us avoid
/// some casts
fn s(idx: u32) -> u32 {
    return sbox(idx as u8) as u32;
//    return Sbox(idx as u8) as u32;
}

fn s_inv_box(x: u8) -> u8 {
    return
    bsbit(0x3401152364e0b71b, 0x7f7905d6a74448f0, 0x9c871717c7e3cf3f, 0x9563022b94d8ff93, x) |
    bsbit(0xa472c324eeb6915c, 0xb65292cd33b94ea4, 0x5fdb0017602e607c, 0x3dbc565f793a930e, x) << 1 |
    bsbit(0x2be37f606dec9249, 0x54a4b31e7f58594f, 0x4728376e5d29c604, 0xa659e338252317ad, x) << 2 |
    bsbit(0x2c2d1e54c17bc664, 0x8d006daf619d9fb1, 0x87bfc5ce0e53816a, 0x71722449637a3fa9, x) << 3 |
    bsbit(0xee82b6b8b94ba50d, 0x1ca1f56acf9d2bf6, 0x51968ad5b3beac14, 0xf0c45e001093f269, x) << 4 |
    bsbit(0x6a678d3096393ac6, 0xed4e94821e3c9ae0, 0x5c98fc7e7fe006ef, 0x50cd80015b87c97f, x) << 5 |
    bsbit(0x89b3be2e56ad0823, 0x9711aa7079675e44, 0x39f6dca0638f8bb6, 0x931aae01f38b319b, x) << 6 |
    bsbit(0x356065fe3e1e61f6, 0x75bbd5c37152d174, 0x1b55a5f2bea797a0, 0xbd04350866430b40, x) << 7;
}

/// Get the S_INV value using a fixed number of instructions
/// Only the bottom byte is used - basically the "idx" argument is a u8, but this lets us avoid
/// some casts
fn s_inv(idx: u32) -> u32 {
    return s_inv_box(idx as u8) as u32;
}

static RCON: [u32, ..10] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36
];



























// to convert between polynomial (A^7...1) basis A & normal basis X
// or to basis S which incorporates bit matrix of Sbox
static A2X_new: [[u32, ..8], ..8] = [
    [0, 0, 0, -1, -1, 0, 0, -1],
    [-1, -1, 0, 0, -1, -1, -1, -1],
    [0, -1, 0, 0, -1, -1, -1, -1],
    [0, 0, 0, -1, 0, 0, -1, 0],
    [-1, 0, 0, -1, 0, 0, 0, 0],
    [-1, 0, 0, 0, 0, 0, 0, -1],
    [-1, 0, 0, -1, 0, -1, 0, -1],
    [-1, -1, -1, -1, -1, -1, -1, -1]
];
static X2A_new: [[u32, ..8], ..8] = [
    [0, 0, -1, 0, 0, -1, -1, 0],
    [0, 0, 0, -1, -1, -1, -1, 0],
    [0, -1, -1, -1, 0, -1, -1, 0],
    [0, 0, -1, -1, 0, 0, 0, -1],
    [0, 0, 0, -1, 0, -1, -1, 0],
    [-1, 0, 0, -1, 0, -1, 0, 0],
    [0, -1, -1, -1, -1, 0, -1, -1],
    [0, 0, 0, 0, 0, -1, -1, 0],
];
static X2S_new: [[u32, ..8], ..8] = [
    [0, 0, 0, -1, -1, 0, -1, 0],
    [-1, 0, -1, -1, 0, -1, 0, 0],
    [0, -1, -1, -1, -1, 0, 0, -1],
    [-1, -1, 0, -1, 0, 0, 0, 0],
    [0, 0, -1, -1, -1, 0, -1, -1],
    [0, 0, -1, 0, 0, 0, 0, 0],
    [-1, -1, 0, 0, 0, 0, 0, 0],
    [0, 0, -1, 0, 0, -1, 0, 0],
];
static S2X_new: [[u32, ..8], ..8] = [
    [0, 0, -1, -1, 0, 0, 0, -1],
    [-1, 0, 0, -1, -1, -1, -1, 0],
    [-1, 0, -1, 0, 0, 0, 0, 0],
    [-1, -1, 0, -1, 0, -1, -1, -1],
    [0, -1, 0, 0, -1, 0, 0, 0],
    [0, 0, -1, 0, 0, 0, 0, 0],
    [-1, 0, 0, 0, -1, 0, -1, 0],
    [-1, -1, 0, 0, -1, 0, -1, 0],
];

// multiply in GF(2^2), using normal basis (Omega^2,Omega)
fn g4_mul(x: bs2_state, y: bs2_state) -> bs2_state {
    let (b, a) = x;
    let (d, c) = y;
    let e = (a ^ b) & (c ^ d);
    let p = (a & c) ^ e;
    let q = (b & d) ^ e;
    return (q, p);
}

// scale by N = Omega^2 in GF(2^2), using normal basis (Omega^2,Omega)
fn g4_scl_n(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    let p = b;
    let q = a ^ b;
    return (q, p);
}

// scale by N^2 = Omega in GF(2^2), using normal basis (Omega^2,Omega)
fn g4_scl_n2(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    let p = a ^ b;
    let q = a;
    return (q, p);
}

// square in GF(2^2), using normal basis (Omega^2,Omega)
// NOTE: inverse is identical
fn g4_sq(x: bs2_state) -> bs2_state {
    let (b, a) = x;
    return (a, b);
}

fn g4_inv(x: bs2_state) -> bs2_state {
    // Same as sqaure
    return g4_sq(x);
}

// multiply in GF(2^4), using normal basis (alpha^8,alpha^2)
fn g16_mul(x: bs4_state, y: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let (d, c) = bs4_split(y);
    let e = g4_mul(bs2_xor(a, b), bs2_xor(c, d));
    let e = g4_scl_n(e);
    let p = bs2_xor(g4_mul(a, c), e);
    let q = bs2_xor(g4_mul(b, d), e);
    return bs2_join(q, p);
}

// square & scale by nu in GF(2^4)/GF(2^2), normal basis (alpha^8,alpha^2)
// nu = beta^8 = N^2*alpha^2, N = w^2 */
fn g16_sq_scl(x: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let p = g4_sq(bs2_xor(a, b));
    let q = g4_scl_n2(g4_sq(b));
    return bs2_join(q, p);
}

// inverse in GF(2^4), using normal basis (alpha^8,alpha^2)
fn g16_inv(x: bs4_state) -> bs4_state {
    let (b, a) = bs4_split(x);
    let c = g4_scl_n(g4_sq(bs2_xor(a, b)));
    let d = g4_mul(a, b);
    let e = g4_inv(bs2_xor(c, d));
    let p = g4_mul(e, b);
    let q = g4_mul(e, a);
    return bs2_join(q, p);
}

// inverse in GF(2^8), using normal basis (d^16,d)
fn g256_inv(x: bs8_state) -> bs8_state {
    let (b, a) = bs8_split(x);
    let c = g16_sq_scl(bs4_xor(a, b));
    let d = g16_mul(a, b);
    let e = g16_inv(bs4_xor(c, d));
    let p = g16_mul(e, b);
    let q = g16_mul(e, a);
    return bs4_join(q, p);
}

fn bs_newbasis(bs: bs8_state, arr: &[[u32, ..8], ..8]) -> bs8_state {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

    let mut bs0_out = 0;
    let mut bs1_out = 0;
    let mut bs2_out = 0;
    let mut bs3_out = 0;
    let mut bs4_out = 0;
    let mut bs5_out = 0;
    let mut bs6_out = 0;
    let mut bs7_out = 0;

    macro_rules! helper( ($bs:ident, $idx:expr) => (
            {
                bs0_out ^= $bs & arr[7 - $idx][0];
                bs1_out ^= $bs & arr[7 - $idx][1];
                bs2_out ^= $bs & arr[7 - $idx][2];
                bs3_out ^= $bs & arr[7 - $idx][3];
                bs4_out ^= $bs & arr[7 - $idx][4];
                bs5_out ^= $bs & arr[7 - $idx][5];
                bs6_out ^= $bs & arr[7 - $idx][6];
                bs7_out ^= $bs & arr[7 - $idx][7];
            }
        )
    )

    helper!(bs0, 0);
    helper!(bs1, 1);
    helper!(bs2, 2);
    helper!(bs3, 3);
    helper!(bs4, 4);
    helper!(bs5, 5);
    helper!(bs6, 6);
    helper!(bs7, 7);

    return (bs0_out, bs1_out, bs2_out, bs3_out, bs4_out, bs5_out, bs6_out, bs7_out);
}

// find Sbox of n in GF(2^8) mod POLY
fn sbox_bs(bs: bs8_state) -> bs8_state {
    let nb = bs_newbasis(bs, &A2X_new);
    let inv = g256_inv(nb);
    let nb2 = bs_newbasis(inv, &X2S_new);
    return bs8_xor(nb2, (-1, -1, 0, 0, 0, -1, -1, 0));
}

// find inverse Sbox of n in GF(2^8) mod POLY
fn isbox_bs(bs: bs8_state) -> bs8_state {
    let nb = bs_newbasis(bs, &S2X_new);
    let inv = g256_inv(nb);
    let nb2 = bs_newbasis(inv, &X2A_new);
    return bs8_xor(nb2, (-1, -1, 0, 0, 0, -1, -1, 0));
}


type bs8_state = (u32, u32, u32, u32, u32, u32, u32, u32);
type bs4_state = (u32, u32, u32, u32);
type bs2_state = (u32, u32);

fn pick(x: u32, bit: u32, shift: u32) -> u32 {
    ((x >> bit) & 1) << shift
}

fn construct(a: u32, b: u32, c: u32, d: u32, bit: u32) -> u32 {
//     pick(a, bit, 0)  | pick(a, bit + 8, 1)  | pick(a, bit + 16, 2)  | pick(a, bit + 24, 3) |
//     pick(b, bit, 4)  | pick(b, bit + 8, 5)  | pick(b, bit + 16, 6)  | pick(b, bit + 24, 7) |
//     pick(c, bit, 8)  | pick(c, bit + 8, 9)  | pick(c, bit + 16, 10) | pick(c, bit + 24, 11) |
//     pick(d, bit, 12) | pick(d, bit + 8, 13) | pick(d, bit + 16, 14) | pick(d, bit + 24, 15)
    pick(a, bit, 0)       | pick(b, bit, 1)       | pick(c, bit, 2)       | pick(d, bit, 3)       |
    pick(a, bit + 8, 4)   | pick(b, bit + 8, 5)   | pick(c, bit + 8, 6)   | pick(d, bit + 8, 7)   |
    pick(a, bit + 16, 8)  | pick(b, bit + 16, 9)  | pick(c, bit + 16, 10) | pick(d, bit + 16, 11) |
    pick(a, bit + 24, 12) | pick(b, bit + 24, 13) | pick(c, bit + 24, 14) | pick(d, bit + 24, 15)
}

fn bs8(a: u32, b: u32, c: u32, d: u32) -> bs8_state {
    let bs0 = construct(a, b, c, d, 0);
    let bs1 = construct(a, b, c, d, 1);
    let bs2 = construct(a, b, c, d, 2);
    let bs3 = construct(a, b, c, d, 3);
    let bs4 = construct(a, b, c, d, 4);
    let bs5 = construct(a, b, c, d, 5);
    let bs6 = construct(a, b, c, d, 6);
    let bs7 = construct(a, b, c, d, 7);
    return (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7);
}

fn deconstruct(bs: bs8_state, bit: u32) -> u32 {
    let (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = bs;

//     pick(bs0, bit, 0) | pick(bs1, bit, 1) | pick(bs2, bit, 2) | pick(bs3, bit, 3) |
//     pick(bs4, bit, 4) | pick(bs5, bit, 5) | pick(bs6, bit, 6) | pick(bs7, bit, 7) |
//
//     pick(bs0, bit + 1, 8) | pick(bs1, bit + 1, 9) | pick(bs2, bit + 1, 10) | pick(bs3, bit + 1, 11) |
//     pick(bs4, bit + 1, 12) | pick(bs5, bit + 1, 13) | pick(bs6, bit + 1, 14) | pick(bs7, bit + 1, 15) |
//
//     pick(bs0, bit + 2, 16) | pick(bs1, bit + 2, 17) | pick(bs2, bit + 2, 18) | pick(bs3, bit + 2, 19) |
//     pick(bs4, bit + 2, 20) | pick(bs5, bit + 2, 21) | pick(bs6, bit + 2, 22) | pick(bs7, bit + 2, 23) |
//
//     pick(bs0, bit + 3, 24) | pick(bs1, bit + 3, 25) | pick(bs2, bit + 3, 26) | pick(bs3, bit + 3, 27) |
//     pick(bs4, bit + 3, 28) | pick(bs5, bit + 3, 29) | pick(bs6, bit + 3, 30) | pick(bs7, bit + 3, 31)

    pick(bs0, bit, 0) | pick(bs1, bit, 1) | pick(bs2, bit, 2) | pick(bs3, bit, 3) |
    pick(bs4, bit, 4) | pick(bs5, bit, 5) | pick(bs6, bit, 6) | pick(bs7, bit, 7) |

    pick(bs0, bit + 4, 8)  | pick(bs1, bit + 4, 9)  | pick(bs2, bit + 4, 10) | pick(bs3, bit + 4, 11) |
    pick(bs4, bit + 4, 12) | pick(bs5, bit + 4, 13) | pick(bs6, bit + 4, 14) | pick(bs7, bit + 4, 15) |

    pick(bs0, bit + 8, 16) | pick(bs1, bit + 8, 17) | pick(bs2, bit + 8, 18) | pick(bs3, bit + 8, 19) |
    pick(bs4, bit + 8, 20) | pick(bs5, bit + 8, 21) | pick(bs6, bit + 8, 22) | pick(bs7, bit + 8, 23) |

    pick(bs0, bit + 12, 24) | pick(bs1, bit + 12, 25) | pick(bs2, bit + 12, 26) | pick(bs3, bit + 12, 27) |
    pick(bs4, bit + 12, 28) | pick(bs5, bit + 12, 29) | pick(bs6, bit + 12, 30) | pick(bs7, bit + 12, 31)
}

fn un_bs8(bs: bs8_state) -> (u32, u32, u32, u32) {
    let a0 = deconstruct(bs, 0);
    let a1 = deconstruct(bs, 1);
    let a2 = deconstruct(bs, 2);
    let a3 = deconstruct(bs, 3);
    return (a0, a1, a2, a3);
}


fn bs4(x: u32) -> bs4_state {
    return (x & 1, (x >> 1) & 1, (x >> 2) & 1, (x >> 3) & 1);
}

fn un_bs4(bs: bs4_state) -> u32 {
    let (bs0, bs1, bs2, bs3) = bs;
    return (bs0 & 1) | ((bs1 & 1) << 1) | ((bs2 & 1) << 2) | ((bs3 & 1) << 3);
}

fn bs2(x: u32) -> bs2_state {
    return (x & 1, (x >> 1) & 1);
}

fn un_bs2(bs: bs2_state) -> u32 {
    let (bs0, bs1) = bs;
    return (bs0 & 1) | ((bs1 & 1) << 1);
}

fn bs8_split(bs8: bs8_state) -> (bs4_state, bs4_state) {
    match bs8 {
        (bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) => ((bs0, bs1, bs2, bs3), (bs4, bs5, bs6, bs7))
    }
}

fn bs4_split(bs4: bs4_state) -> (bs2_state, bs2_state) {
    match bs4 {
        (bs0, bs1, bs2, bs3) => ((bs0, bs1), (bs2, bs3))
    }
}

fn bs8_xor(a: bs8_state, b: bs8_state) -> bs8_state {
    let (a0, a1, a2, a3, a4, a5, a6, a7) = a;
    let (b0, b1, b2, b3, b4, b5, b6, b7) = b;
    (a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3, a4 ^ b4, a5 ^ b5, a6 ^ b6, a7 ^ b7)
}

fn bs4_xor(a: bs4_state, b: bs4_state) -> bs4_state {
    let (a0, a1, a2, a3) = a;
    let (b0, b1, b2, b3) = b;
    (a0 ^ b0, a1 ^ b1, a2 ^ b2, a3 ^ b3)
}

fn bs2_xor(a: bs2_state, b: bs2_state) -> bs2_state {
    let (a0, a1) = a;
    let (b0, b1) = b;
    (a0 ^ b0, a1 ^ b1)
}

fn bs4_join(a: bs4_state, b: bs4_state) -> bs8_state {
    let (a0, a1, a2, a3) = a;
    let (b0, b1, b2, b3) = b;
    (a0, a1, a2, a3, b0, b1, b2, b3)
}

fn bs2_join(a: bs2_state, b: bs2_state) -> bs4_state {
    let (a0, a1) = a;
    let (b0, b1) = b;
    (a0, a1, b0, b1)
}
