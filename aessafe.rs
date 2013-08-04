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
            initialized: bool
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
            pub fn new() -> $name {
                return $name {
                    round_keys: [[0u32, ..4], ..$rounds + 1],
                    initialized: false
                };
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
                assert!(self.initialized);
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
                assert!(self.initialized);
                decrypt_block($rounds, input, self.round_keys, output);
            }
        }
    )
)

macro_rules! define_aes_init(
    (
        $name:ident,
        $mode:expr
    ) => (
        impl SymmetricCipher for $name {
            fn set_key(&mut self, key: &[u8]) {
                setup_round_keys(key, $mode, self.round_keys);
                self.initialized = true;
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
define_aes_init!(AesSafe128Encryptor, Encryption)
define_aes_init!(AesSafe128Decryptor, Decryption)

define_aes_struct!(AesSafe192Encryptor, 12)
define_aes_struct!(AesSafe192Decryptor, 12)
define_aes_impl!(AesSafe192Encryptor, Encryption, 12, 24)
define_aes_impl!(AesSafe192Decryptor, Decryption, 12, 24)
define_aes_enc!(AesSafe192Encryptor, 12)
define_aes_dec!(AesSafe192Decryptor, 12)
define_aes_init!(AesSafe192Encryptor, Encryption)
define_aes_init!(AesSafe192Decryptor, Decryption)

define_aes_struct!(AesSafe256Encryptor, 14)
define_aes_struct!(AesSafe256Decryptor, 14)
define_aes_impl!(AesSafe256Encryptor, Encryption, 14, 32)
define_aes_impl!(AesSafe256Decryptor, Decryption, 14, 32)
define_aes_enc!(AesSafe256Encryptor, 14)
define_aes_dec!(AesSafe256Decryptor, 14)
define_aes_init!(AesSafe256Encryptor, Encryption)
define_aes_init!(AesSafe256Decryptor, Decryption)


/// Get the value from the specified index using a fixed number of instructions
fn fixed_get(v: &[u8], idx: uint) -> u32 {
    let mut out: u32 = 0;
    for i in range(0, v.len()) {
        out = (i as u8).fixed_eq(idx as u8).fixed_select(v[i] as u32, out);
    }
    return out;
}

/// Get the S value using a fixed number of instructions
/// Only the bottom byte is used - basically the "idx" argument is a u8, but this lets us avoid
/// some casts
fn s(idx: u32) -> u32 {
    return fixed_get(S, (idx & 0xff) as uint);
}

/// Get the S_INV value using a fixed number of instructions
/// Only the bottom byte is used - basically the "idx" argument is a u8, but this lets us avoid
/// some casts
fn s_inv(idx: u32) -> u32 {
    return fixed_get(S_INV, (idx & 0xff) as uint);
}

/// Get the RCON value at the specified index using a fixed number of instructions
fn rcon(idx: uint) -> u32 {
    return fixed_get(RCON, idx as uint);
}

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
            temp = sub_word(shift(temp, 8)) ^ rcon((i / key_words) - 1);
        } else if (key_words > 6) && ((i % key_words) == 4) {
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
        return mcol(s(v) ^ (s(x >> 8) << 8) ^ (s(y >> 16) << 16) ^ (s(z >> 24) <<24)) ^ k;
    }

    fn op_end(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return s(v) ^ (s(x >> 8) << 8) ^ (s(y >> 16) << 16) ^ (s(z >> 24) <<24) ^ k;
    }

    let mut r0: u32;
    let mut r1: u32;
    let mut r2: u32;
    let mut r3: u32;

    let mut c = [0u32, ..4];
    read_u32v_le(c, input);

    c[0] ^= rk[0][0];
    c[1] ^= rk[0][1];
    c[2] ^= rk[0][2];
    c[3] ^= rk[0][3];

    let mut r = 1;
    while (r < rounds - 1) {
        r0 = op(c[0], c[1], c[2], c[3], rk[r][0]);
        r1 = op(c[1], c[2], c[3], c[0], rk[r][1]);
        r2 = op(c[2], c[3], c[0], c[1], rk[r][2]);
        r3 = op(c[3], c[0], c[1], c[2], rk[r][3]);
        r += 1;

        c[0] = op(r0, r1, r2, r3, rk[r][0]);
        c[1] = op(r1, r2, r3, r0, rk[r][1]);
        c[2] = op(r2, r3, r0, r1, rk[r][2]);
        c[3] = op(r3, r0, r1, r2, rk[r][3]);
        r += 1;
    }

    r0 = op(c[0], c[1], c[2], c[3], rk[r][0]);
    r1 = op(c[1], c[2], c[3], c[0], rk[r][1]);
    r2 = op(c[2], c[3], c[0], c[1], rk[r][2]);
    r3 = op(c[3], c[0], c[1], c[2], rk[r][3]);
    r += 1;

    c[0] = op_end(r0, r1, r2, r3, rk[r][0]);
    c[1] = op_end(r1, r2, r3, r0, rk[r][1]);
    c[2] = op_end(r2, r3, r0, r1, rk[r][2]);
    c[3] = op_end(r3, r0, r1, r2, rk[r][3]);

    write_u32_le(output.mut_slice(0, 4), c[0]);
    write_u32_le(output.mut_slice(4, 8), c[1]);
    write_u32_le(output.mut_slice(8, 12), c[2]);
    write_u32_le(output.mut_slice(12, 16), c[3]);
}

fn decrypt_block(rounds: uint, input: &[u8], rk: &[[u32, ..4]], output: &mut [u8]) {
    fn op(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return inv_mcol(s_inv(v) ^ (s_inv(x >> 8) << 8) ^ (s_inv(y >> 16) << 16) ^
            (s_inv(z >> 24) <<24)) ^ k;
    }

    fn op_end(v: u32, x: u32, y: u32, z: u32, k: u32) -> u32 {
        return s_inv(v) ^ (s_inv(x >> 8) << 8) ^ (s_inv(y >> 16) << 16) ^ (s_inv(z >> 24) <<24) ^ k;
    }

    let mut r0: u32;
    let mut r1: u32;
    let mut r2: u32;
    let mut r3: u32;

    let mut c = [0u32, ..4];
    read_u32v_le(c, input);

    c[0] ^= rk[rounds][0];
    c[1] ^= rk[rounds][1];
    c[2] ^= rk[rounds][2];
    c[3] ^= rk[rounds][3];

    let mut r = rounds - 1;
    while (r > 1) {
        r0 = op(c[0], c[3], c[2], c[1], rk[r][0]);
        r1 = op(c[1], c[0], c[3], c[2], rk[r][1]);
        r2 = op(c[2], c[1], c[0], c[3], rk[r][2]);
        r3 = op(c[3], c[2], c[1], c[0], rk[r][3]);
        r -= 1;

        c[0] = op(r0, r3, r2, r1, rk[r][0]);
        c[1] = op(r1, r0, r3, r2, rk[r][1]);
        c[2] = op(r2, r1, r0, r3, rk[r][2]);
        c[3] = op(r3, r2, r1, r0, rk[r][3]);
        r -= 1;
    }

    r0 = op(c[0], c[3], c[2], c[1], rk[r][0]);
    r1 = op(c[1], c[0], c[3], c[2], rk[r][1]);
    r2 = op(c[2], c[1], c[0], c[3], rk[r][2]);
    r3 = op(c[3], c[2], c[1], c[0], rk[r][3]);
    r -= 1;

    c[0] = op_end(r0, r3, r2, r1, rk[r][0]);
    c[1] = op_end(r1, r0, r3, r2, rk[r][1]);
    c[2] = op_end(r2, r1, r0, r3, rk[r][2]);
    c[3] = op_end(r3, r2, r1, r0, rk[r][3]);

    write_u32_le(output.mut_slice(0, 4), c[0]);
    write_u32_le(output.mut_slice(4, 8), c[1]);
    write_u32_le(output.mut_slice(8, 12), c[2]);
    write_u32_le(output.mut_slice(12, 16), c[3]);
}

static S: [u8, ..256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

static S_INV: [u8, ..256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
    0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
    0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2,
    0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA,
    0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
    0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA,
    0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20,
    0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31,
    0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0,
    0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
    0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
];

static RCON: [u8, ..30] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
    0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
];
