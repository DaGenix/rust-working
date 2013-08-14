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
            round_keys: [[u32, ..4], ..$rounds + 1]
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
                    round_keys: [[0u32, ..4], ..$rounds + 1]
                };
                setup_round_keys(key, $mode, a.round_keys);
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
                encrypt_block($rounds, input, self.round_keys, output);
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

fn setup_round_keys(key: &[u8], key_type: KeyType, round_keys: &mut [[u32, ..4]]) {
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

fn encrypt_block(rounds: uint, input: &[u8], rk: &[[u32, ..4]], output: &mut [u8]) {
    fn op(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return mcol((v & 0xff) ^ (x & 0xff00) ^ (y & 0xff0000) ^ (z & 0xff000000)) ^ k;
    }

    fn op_end(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return (v & 0xff) ^ (x & 0xff00) ^ (y & 0xff0000) ^ (z & 0xff000000) ^ k;
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
        unpack(Sbox(pack(c0, c1)), &mut c0, &mut c1);
        unpack(Sbox(pack(c2, c3)), &mut c2, &mut c3);
        let mut r0 = op(c0, c1, c2, c3, rk[r][0]);
        let mut r1 = op(c1, c2, c3, c0, rk[r][1]);
        let mut r2 = op(c2, c3, c0, c1, rk[r][2]);
        let mut r3 = op(c3, c0, c1, c2, rk[r][3]);
        r += 1;

        unpack(Sbox(pack(r0, r1)), &mut r0, &mut r1);
        unpack(Sbox(pack(r2, r3)), &mut r2, &mut r3);
        c0 = op(r0, r1, r2, r3, rk[r][0]);
        c1 = op(r1, r2, r3, r0, rk[r][1]);
        c2 = op(r2, r3, r0, r1, rk[r][2]);
        c3 = op(r3, r0, r1, r2, rk[r][3]);
        r += 1;
    }

    unpack(Sbox(pack(c0, c1)), &mut c0, &mut c1);
    unpack(Sbox(pack(c2, c3)), &mut c2, &mut c3);
    let mut r0 = op(c0, c1, c2, c3, rk[r][0]);
    let mut r1 = op(c1, c2, c3, c0, rk[r][1]);
    let mut r2 = op(c2, c3, c0, c1, rk[r][2]);
    let mut r3 = op(c3, c0, c1, c2, rk[r][3]);
    r += 1;

    unpack(Sbox(pack(r0, r1)), &mut r0, &mut r1);
    unpack(Sbox(pack(r2, r3)), &mut r2, &mut r3);
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
static A2X: [u64, ..8] = [0x9898989898989898, 0xF3F3F3F3F3F3F3F3, 0xF2F2F2F2F2F2F2F2, 0x4848484848484848, 0x0909090909090909, 0x8181818181818181, 0xA9A9A9A9A9A9A9A9, 0xFFFFFFFFFFFFFFFF];
static X2A: [u64, ..8] = [0x6464646464646464, 0x7878787878787878, 0x6E6E6E6E6E6E6E6E, 0x8C8C8C8C8C8C8C8C, 0x6868686868686868, 0x2929292929292929, 0xDEDEDEDEDEDEDEDE, 0x6060606060606060];
static X2S: [u64, ..8] = [0x5858585858585858, 0x2D2D2D2D2D2D2D2D, 0x9E9E9E9E9E9E9E9E, 0x0B0B0B0B0B0B0B0B, 0xDCDCDCDCDCDCDCDC, 0x0404040404040404, 0x0303030303030303, 0x2424242424242424];
static S2X: [u64, ..8] = [0x8C8C8C8C8C8C8C8C, 0x7979797979797979, 0x0505050505050505, 0xEBEBEBEBEBEBEBEB, 0x1212121212121212, 0x0404040404040404, 0x5151515151515151, 0x5353535353535353];

// multiply in GF(2^2), using normal basis (Omega^2,Omega)
fn G4_mul(x: u64, y: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    let c = (y & 0x0202020202020202) >> 1;
    let d = (y & 0x0101010101010101);
    let e = (a ^ b) & (c ^ d);
    let p = (a & c) ^ e;
    let q = (b & d) ^ e;
    return (p << 1) | q;
}

// scale by N = Omega^2 in GF(2^2), using normal basis (Omega^2,Omega)
fn G4_scl_N(x: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    let p = b;
    let q = a ^ b;
    return (p << 1) | q;
}

// scale by N^2 = Omega in GF(2^2), using normal basis (Omega^2,Omega)
fn G4_scl_N2(x: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    let p = a ^ b;
    let q = a;
    return (p << 1) | q;
}

// square in GF(2^2), using normal basis (Omega^2,Omega)
// NOTE: inverse is identical
fn G4_sq(x: u64) -> u64 {
    let a = (x & 0x0202020202020202) >> 1;
    let b = (x & 0x0101010101010101);
    return (b << 1) | a;
}

fn G4_inv(x: u64) -> u64 {
    // Same as sqaure
    return G4_sq(x);
}

// multiply in GF(2^4), using normal basis (alpha^8,alpha^2)
fn G16_mul(x: u64, y: u64) -> u64 {
    let a = (x & 0x0C0C0C0C0C0C0C0C) >> 2;
    let b = (x & 0x0303030303030303);
    let c = (y & 0x0C0C0C0C0C0C0C0C) >> 2;
    let d = (y & 0x0303030303030303);
    let e = G4_mul(a ^ b, c ^ d);
    let e = G4_scl_N(e);
    let p = G4_mul(a, c) ^ e;
    let q = G4_mul(b, d) ^ e;
    return (p << 2) | q;
}

// square & scale by nu in GF(2^4)/GF(2^2), normal basis (alpha^8,alpha^2)
// nu = beta^8 = N^2*alpha^2, N = w^2 */
fn G16_sq_scl(x: u64) -> u64 {
    let a = (x & 0x0C0C0C0C0C0C0C0C) >> 2;
    let b = (x & 0x0303030303030303);
    let p = G4_sq(a ^ b);
    let q = G4_scl_N2(G4_sq(b));
    return (p << 2) | q;
}

// inverse in GF(2^4), using normal basis (alpha^8,alpha^2)
fn G16_inv(x: u64) -> u64 {
    let a = (x & 0x0C0C0C0C0C0C0C0C) >> 2;
    let b = (x & 0x0303030303030303);
    let c = G4_scl_N(G4_sq(a ^ b));
    let d = G4_mul(a, b);
    let e = G4_inv(c ^ d);
    let p = G4_mul(e, b);
    let q = G4_mul(e, a);
    return (p <<2 ) | q;
}

// inverse in GF(2^8), using normal basis (d^16,d)
fn G256_inv(x: u64) -> u64 {
    let a = (x & 0xF0F0F0F0F0F0F0F0) >> 4;
    let b = (x & 0x0F0F0F0F0F0F0F0F);
    let c = G16_sq_scl(a ^ b);
    let d = G16_mul(a, b);
    let e = G16_inv(c ^ d);
    let p = G16_mul(e, b);
    let q = G16_mul(e, a);
    return (p << 4) | q;
}

fn helper(mut x: u64, b: &[u64, ..8]) -> u64 {
    let mut i = 7;
    let mut y = 0;
    while i >= 0 {
        if (x & 1) != 0 {
            y ^= b[i];
        }
        x >>= 1;
        i -= 1;
    }
    return y & 0xFF;
}

// convert to new basis in GF(2^8)
// i.e., bit matrix multiply
fn G256_newbasis(x: u64, k: &[u64, ..8]) -> u64 {
    let a = helper((x & 0x00000000000000FF), k);
    let b = helper((x & 0x000000000000FF00) >> 8, k) << 8;
    let c = helper((x & 0x0000000000FF0000) >> 16, k) << 16;
    let d = helper((x & 0x00000000FF000000) >> 24, k) << 24;
    let e = helper((x & 0x000000FF00000000) >> 32, k) << 32;
    let f = helper((x & 0x0000FF0000000000) >> 40, k) << 40;
    let g = helper((x & 0x00FF000000000000) >> 48, k) << 48;
    let h = helper((x & 0xFF00000000000000) >> 56, k) << 56;
    let t = a | b | c | d | e | f | g | h;
    return t;
}

// find Sbox of n in GF(2^8) mod POLY
fn Sbox(n: u64) -> u64 {
    let mut t = G256_newbasis(n, &A2X);
    t = G256_inv(t);
    t = G256_newbasis(t, &X2S);
    return t ^ 0x6363636363636363;
}

// find inverse Sbox of n in GF(2^8) mod POLY
fn iSbox(n: u64) -> u64 {
    let mut t = G256_newbasis(n, &S2X);
    t = G256_inv(t);
    t = G256_newbasis(t, &X2A);
    return t ^ 0x6363636363636363;
}

fn pack(a: u32, b: u32) -> u64 {
    return (a as u64) << 32 | (b as u64);
}

fn unpack(x: u64, outa: &mut u32, outb: &mut u32) {
    *outa = (x >> 32) as u32;
    *outb = x as u32;
}
