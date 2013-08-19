// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::num::Zero;
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
            sk: [Bs8State<u32>, ..$rounds + 1]
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
                    sk: [Bs8State(0,0,0,0,0,0,0,0), ..$rounds + 1]
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
                decrypt_block($rounds, input, self.sk, output);
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

static RCON: [u32, ..10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn setup_round_keys(key: &[u8], key_type: KeyType, round_keys: &mut [[u32, ..4]], sk: &mut [Bs8State<u32>]) {
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

    for i in range(0, rounds + 1) {
        sk[i] = bit_splice_4x4_with_u32(
            round_keys[i][0],
            round_keys[i][1],
            round_keys[i][2],
            round_keys[i][3])
    }
}

trait AesRowTypeOps: BitXor<Self, Self> + BitAnd<Self, Self> + Clone + Zero {
    fn a2x() -> &'static [[Self, ..8], ..8];
    fn x2s() -> &'static [[Self, ..8], ..8];
    fn s2x() -> &'static [[Self, ..8], ..8];
    fn x2a() -> &'static [[Self, ..8], ..8];
    fn x63() -> Bs8State<Self>;

    fn shift_row(&self) -> Self;
    fn inv_shift_row(&self) -> Self;
    fn ror1(&self) -> Self;
    fn ror2(&self) -> Self;
    fn ror3(&self) -> Self;
}

impl AesRowTypeOps for u32 {
    fn a2x() -> &'static [[u32, ..8], ..8] { &A2X_new }
    fn x2s() -> &'static [[u32, ..8], ..8] { &X2S_new }
    fn s2x() -> &'static [[u32, ..8], ..8] { &S2X_new }
    fn x2a() -> &'static [[u32, ..8], ..8] { &X2A_new }
    fn x63() -> Bs8State<u32> { Bs8State(-1, -1, 0, 0, 0, -1, -1, 0) }

    fn shift_row(&self) -> u32 {
        // first 4 bits represent first row - don't shift
        (*self & 0x000f) |
        // next 4 bits represent 2nd row - left rotate 1 bit
        ((*self & 0x00e0) >> 1) | ((*self & 0x0010) << 3) |
        // next 4 bits represent 3rd row - left rotate 2 bits
        ((*self & 0x0c00) >> 2) | ((*self & 0x0300) << 2) |
        // next 4 bits represent 4th row - left rotate 3 bits
        ((*self & 0x8000) >> 3) | ((*self & 0x7000) << 1)
    }
    fn inv_shift_row(&self) -> u32 {
        // first 4 bits represent first row - don't shift
        (*self & 0x000f) |
        // next 4 bits represent 2nd row - right rotate 1 bit
        ((*self & 0x0080) >> 3) | ((*self & 0x0070) << 1) |
        // next 4 bits represent 3rd row - right rotate 2 bits
        ((*self & 0x0c00) >> 2) | ((*self & 0x0300) << 2) |
        // next 4 bits represent 4th row - right rotate 3 bits
        ((*self & 0xe000) >> 1) | ((*self & 0x1000) << 3)
    }
    fn ror1(&self) -> u32 {
        ((*self >> 4) & 0x0fff) | (*self << 12)
    }
    fn ror2(&self) -> u32 {
        ((*self >> 8) & 0x00ff) | (*self << 8)
    }
    fn ror3(&self) -> u32 {
        ((*self >> 12) & 0x000f) | (*self << 4)
    }
}

trait AesOps {
    fn sub_bytes(&self) -> Self;
    fn inv_sub_bytes(&self) -> Self;
    fn shift_rows(&self) -> Self;
    fn inv_shift_rows(&self) -> Self;
    fn mix_columns(&self) -> Self;
    fn inv_mix_columns(&self) -> Self;
    fn add_round_key(&self, rk: &Self) -> Self;
}

impl <T: AesRowTypeOps> AesOps for Bs8State<T> {
    // find Sbox of n in GF(2^8) mod POLY
    fn sub_bytes(&self) -> Bs8State<T> {
        let nb = self.change_basis(AesRowTypeOps::a2x::<T>());
        let inv = nb.inv();
        let nb2 = inv.change_basis(AesRowTypeOps::x2s::<T>());
        let x63 = AesRowTypeOps::x63::<T>();
        return nb2.xor(&x63);
    }
    // find inverse Sbox of n in GF(2^8) mod POLY
    fn inv_sub_bytes(&self) -> Bs8State<T> {
        let x63 = AesRowTypeOps::x63::<T>();
        let t = self.xor(&x63);
        let nb = t.change_basis(AesRowTypeOps::s2x::<T>());
        let inv = nb.inv();
        let nb2 = inv.change_basis(AesRowTypeOps::x2a::<T>());
        return nb2;
    }
    fn shift_rows(&self) -> Bs8State<T> {
        let Bs8State(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7) = *self;
        return Bs8State(
            x0.shift_row(),
            x1.shift_row(),
            x2.shift_row(),
            x3.shift_row(),
            x4.shift_row(),
            x5.shift_row(),
            x6.shift_row(),
            x7.shift_row());
    }
    fn inv_shift_rows(&self) -> Bs8State<T> {
        let Bs8State(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7) = *self;
        return Bs8State(
            x0.inv_shift_row(),
            x1.inv_shift_row(),
            x2.inv_shift_row(),
            x3.inv_shift_row(),
            x4.inv_shift_row(),
            x5.inv_shift_row(),
            x6.inv_shift_row(),
            x7.inv_shift_row());
    }
    fn mix_columns(&self) -> Bs8State<T> {
        let Bs8State(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7) = *self;

        let x0out = x7 ^ x7.ror1() ^ x0.ror1() ^ (x0 ^ x0.ror1()).ror2();
        let x1out = x0 ^ x0.ror1() ^ *x7 ^ x7.ror1() ^ x1.ror1() ^ (x1 ^ x1.ror1()).ror2();
        let x2out = x1 ^ x1.ror1() ^ x2.ror1() ^ (x2 ^ x2.ror1()).ror2();
        let x3out = x2 ^ x2.ror1() ^ *x7 ^ x7.ror1() ^ x3.ror1() ^ (x3 ^ x3.ror1()).ror2();
        let x4out = x3 ^ x3.ror1() ^ *x7 ^ x7.ror1() ^ x4.ror1() ^ (x4 ^ x4.ror1()).ror2();
        let x5out = x4 ^ x4.ror1() ^ x5.ror1() ^ (x5 ^ x5.ror1()).ror2();
        let x6out = x5 ^ x5.ror1() ^ x6.ror1() ^ (x6 ^ x6.ror1()).ror2();
        let x7out = x6 ^ x6.ror1() ^ x7.ror1() ^ (x7 ^ x7.ror1()).ror2();

        return Bs8State(x0out, x1out, x2out, x3out, x4out, x5out, x6out, x7out);
    }
    fn inv_mix_columns(&self) -> Bs8State<T> {
        let Bs8State(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7) = *self;

        let x0out = *x5 ^ *x6 ^ *x7 ^
            x5.ror1() ^ x7.ror1() ^ x0.ror1() ^
            x0.ror2() ^ x5.ror2() ^ x6.ror2() ^
            x5.ror3() ^ x0.ror3();
        let x1out = *x5 ^ *x0 ^
            x6.ror1() ^ x5.ror1() ^ x0.ror1() ^ x7.ror1() ^ x1.ror1() ^
            x1.ror2() ^ x7.ror2() ^ x5.ror2() ^
            x6.ror3() ^ x5.ror3() ^ x1.ror3();
        let x2out = *x6 ^ *x0 ^ *x1 ^
            x7.ror1() ^ x6.ror1() ^ x1.ror1() ^ x2.ror1() ^
            x0.ror2() ^ x2.ror2() ^ x6.ror2() ^
            x7.ror3() ^ x6.ror3() ^ x2.ror3();
        let x3out = *x0 ^ *x5 ^ *x1 ^ *x6 ^ *x2 ^
            x0.ror1() ^ x5.ror1() ^ x2.ror1() ^ x3.ror1() ^
            x0.ror2() ^ x1.ror2() ^ x3.ror2() ^ x5.ror2() ^ x6.ror2() ^ x7.ror2() ^
            x0.ror3() ^ x5.ror3() ^ x7.ror3() ^ x3.ror3();
        let x4out = *x1 ^ *x5 ^ *x2 ^ *x3 ^
            x1.ror1() ^ x6.ror1() ^ x5.ror1() ^ x3.ror1() ^ x7.ror1() ^ x4.ror1() ^
            x1.ror2() ^ x2.ror2() ^ x4.ror2() ^ x5.ror2() ^ x7.ror2() ^
            x1.ror3() ^ x5.ror3() ^ x6.ror3() ^ x4.ror3();
        let x5out = *x2 ^ *x6 ^ *x3 ^ *x4 ^
            x2.ror1() ^ x7.ror1() ^ x6.ror1() ^ x4.ror1() ^ x5.ror1() ^
            x2.ror2() ^ x3.ror2() ^ x5.ror2() ^ x6.ror2() ^
            x2.ror3() ^ x6.ror3() ^ x7.ror3() ^ x5.ror3();
        let x6out =  *x3 ^ *x7 ^ *x4 ^ *x5 ^
            x3.ror1() ^ x7.ror1() ^ x5.ror1() ^ x6.ror1() ^
            x3.ror2() ^ x4.ror2() ^ x6.ror2() ^ x7.ror2() ^
            x3.ror3() ^ x7.ror3() ^ x6.ror3();
        let x7out = *x4 ^ *x5 ^ *x6 ^
            x4.ror1() ^ x6.ror1() ^ x7.ror1() ^
            x4.ror2() ^ x5.ror2() ^ x7.ror2() ^
            x4.ror3() ^ x7.ror3();

        Bs8State(x0out, x1out, x2out, x3out, x4out, x5out, x6out, x7out)
    }
    fn add_round_key(&self, rk: &Bs8State<T>) -> Bs8State<T> {
        return self.xor(rk);
    }
}

fn encrypt_core<S: AesOps>(state: &S, sk: &[S]) -> S {
    // Round 0 - add round key
    let mut tmp = state.add_round_key(&sk[0]);

    // Remaining rounds (except last round)
    for i in range(1, sk.len() - 1) {
        tmp = tmp.sub_bytes();
        tmp = tmp.shift_rows();
        tmp = tmp.mix_columns();
        tmp = tmp.add_round_key(&sk[i]);
    }

    // Last round
    tmp = tmp.sub_bytes();
    tmp = tmp.shift_rows();
    tmp = tmp.add_round_key(&sk[sk.len() - 1]);

    return tmp;
}

fn encrypt_block(rounds: uint, input: &[u8], sk: &[Bs8State<u32>], output: &mut [u8]) {
    let mut bs = bit_splice_1x16_with_u32(input);
    bs = encrypt_core(&bs, sk);
    un_bit_splice_1x16_with_u32(&bs, output);
}

fn decrypt_core<S: AesOps>(state: &S, sk: &[S]) -> S {
    // Round 0 - add round key
    let mut tmp = state.add_round_key(&sk[sk.len() - 1]);

    // Remaining rounds (except last round)
    for i in range(1, sk.len() - 1) {
        tmp = tmp.inv_sub_bytes();
        tmp = tmp.inv_shift_rows();
        tmp = tmp.inv_mix_columns();
        tmp = tmp.add_round_key(&sk[sk.len() - 1 - i]);
    }

    // Last round
    tmp = tmp.inv_sub_bytes();
    tmp = tmp.inv_shift_rows();
    tmp = tmp.add_round_key(&sk[0]);

    return tmp;
}

fn decrypt_block(rounds: uint, input: &[u8], sk: &[Bs8State<u32>], output: &mut [u8]) {
    let mut bs = bit_splice_1x16_with_u32(input);
    bs = decrypt_core(&bs, sk);
    un_bit_splice_1x16_with_u32(&bs, output);
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




















struct Bs8State<T>(T, T, T, T, T, T, T, T);

impl <T: Clone> Bs8State<T> {
    fn split(&self) -> (Bs4State<T>, Bs4State<T>) {
        let Bs8State(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7) = *self;
        return (Bs4State(x0.clone(), x1.clone(), x2.clone(), x3.clone()),
            Bs4State(x4.clone(), x5.clone(), x6.clone(), x7.clone()));
    }
}

impl <T: BitXor<T, T>> Bs8State<T> {
    fn xor(&self, rhs: &Bs8State<T>) -> Bs8State<T> {
        let Bs8State(ref a0, ref a1, ref a2, ref a3, ref a4, ref a5, ref a6, ref a7) = *self;
        let Bs8State(ref b0, ref b1, ref b2, ref b3, ref b4, ref b5, ref b6, ref b7) = *rhs;
        return Bs8State(*a0 ^ *b0, *a1 ^ *b1, *a2 ^ *b2, *a3 ^ *b3,
            *a4 ^ *b4, *a5 ^ *b5, *a6 ^ *b6, *a7 ^ *b7);
    }
}


struct Bs4State<T>(T, T, T, T);

impl <T: Clone> Bs4State<T> {
    fn split(&self) -> (Bs2State<T>, Bs2State<T>) {
        let Bs4State(ref x0, ref x1, ref x2, ref x3) = *self;
        return (Bs2State(x0.clone(), x1.clone()), Bs2State(x2.clone(), x3.clone()));
    }
    fn join(&self, rhs: &Bs4State<T>) -> Bs8State<T> {
        let Bs4State(ref a0, ref a1, ref a2, ref a3) = *self;
        let Bs4State(ref b0, ref b1, ref b2, ref b3) = *rhs;
        return Bs8State(a0.clone(), a1.clone(), a2.clone(), a3.clone(),
            b0.clone(), b1.clone(), b2.clone(), b3.clone());
    }
}

impl <T: BitXor<T, T>> Bs4State<T> {
    fn xor(&self, rhs: &Bs4State<T>) -> Bs4State<T> {
        let Bs4State(ref a0, ref a1, ref a2, ref a3) = *self;
        let Bs4State(ref b0, ref b1, ref b2, ref b3) = *rhs;
        return Bs4State(*a0 ^ *b0, *a1 ^ *b1, *a2 ^ *b2, *a3 ^ *b3);
    }
}


struct Bs2State<T>(T, T);

impl <T: Clone> Bs2State<T> {
    fn split(&self) -> (T, T) {
        let Bs2State(ref x0, ref x1) = *self;
        return (x0.clone(), x1.clone());
    }
    fn join(&self, rhs: &Bs2State<T>) -> Bs4State<T> {
        let Bs2State(ref a0, ref a1) = *self;
        let Bs2State(ref b0, ref b1) = *rhs;
        return Bs4State(a0.clone(), a1.clone(), b0.clone(), b1.clone());
    }
}

impl <T: BitXor<T, T>> Bs2State<T> {
    fn xor(&self, rhs: &Bs2State<T>) -> Bs2State<T> {
        let Bs2State(ref a0, ref a1) = *self;
        let Bs2State(ref b0, ref b1) = *rhs;
        return Bs2State(*a0 ^ *b0, *a1 ^ *b1);
    }
}


fn pb(x: u32, bit: uint, shift: uint) -> u32 {
    ((x >> bit) & 1) << shift
}

fn bit_splice_4x4_with_u32(a: u32, b: u32, c: u32, d: u32) -> Bs8State<u32> {
    fn construct(a: u32, b: u32, c: u32, d: u32, bit: uint) -> u32 {
        pb(a, bit, 0)       | pb(b, bit, 1)       | pb(c, bit, 2)       | pb(d, bit, 3)       |
        pb(a, bit + 8, 4)   | pb(b, bit + 8, 5)   | pb(c, bit + 8, 6)   | pb(d, bit + 8, 7)   |
        pb(a, bit + 16, 8)  | pb(b, bit + 16, 9)  | pb(c, bit + 16, 10) | pb(d, bit + 16, 11) |
        pb(a, bit + 24, 12) | pb(b, bit + 24, 13) | pb(c, bit + 24, 14) | pb(d, bit + 24, 15)
    }

    let bs0 = construct(a, b, c, d, 0);
    let bs1 = construct(a, b, c, d, 1);
    let bs2 = construct(a, b, c, d, 2);
    let bs3 = construct(a, b, c, d, 3);
    let bs4 = construct(a, b, c, d, 4);
    let bs5 = construct(a, b, c, d, 5);
    let bs6 = construct(a, b, c, d, 6);
    let bs7 = construct(a, b, c, d, 7);

    return Bs8State(bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7);
}

fn bit_splice_1x16_with_u32(data: &[u8]) -> Bs8State<u32> {
    let mut n = [0u32, ..4];
    read_u32v_le(n, data);

    let a = n[0];
    let b = n[1];
    let c = n[2];
    let d = n[3];

    return bit_splice_4x4_with_u32(a, b, c, d);
}

fn un_bit_splice_1x16_with_u32(bs: &Bs8State<u32>, output: &mut [u8]) {
    fn deconstruct(bs: &Bs8State<u32>, bit: uint) -> u32 {
        let Bs8State(bs0, bs1, bs2, bs3, bs4, bs5, bs6, bs7) = *bs;

        pb(bs0, bit, 0) | pb(bs1, bit, 1) | pb(bs2, bit, 2) | pb(bs3, bit, 3) |
        pb(bs4, bit, 4) | pb(bs5, bit, 5) | pb(bs6, bit, 6) | pb(bs7, bit, 7) |

        pb(bs0, bit + 4, 8)  | pb(bs1, bit + 4, 9)  | pb(bs2, bit + 4, 10) | pb(bs3, bit + 4, 11) |
        pb(bs4, bit + 4, 12) | pb(bs5, bit + 4, 13) | pb(bs6, bit + 4, 14) | pb(bs7, bit + 4, 15) |

        pb(bs0, bit + 8, 16) | pb(bs1, bit + 8, 17) | pb(bs2, bit + 8, 18) | pb(bs3, bit + 8, 19) |
        pb(bs4, bit + 8, 20) | pb(bs5, bit + 8, 21) | pb(bs6, bit + 8, 22) | pb(bs7, bit + 8, 23) |

        pb(bs0, bit + 12, 24) | pb(bs1, bit + 12, 25) | pb(bs2, bit + 12, 26) | pb(bs3, bit + 12, 27) |
        pb(bs4, bit + 12, 28) | pb(bs5, bit + 12, 29) | pb(bs6, bit + 12, 30) | pb(bs7, bit + 12, 31)
    }

    let a = deconstruct(bs, 0);
    let b = deconstruct(bs, 1);
    let c = deconstruct(bs, 2);
    let d = deconstruct(bs, 3);

    write_u32_le(output.mut_slice(0, 4), a);
    write_u32_le(output.mut_slice(4, 8), b);
    write_u32_le(output.mut_slice(8, 12), c);
    write_u32_le(output.mut_slice(12, 16), d);
}




































impl <T: BitXor<T, T> + BitAnd<T, T> + Clone> Bs2State<T> {
    // multiply in GF(2^2), using normal basis (Omega^2,Omega)
    fn mul(&self, y: &Bs2State<T>) -> Bs2State<T> {
        let (b, a) = self.split();
        let (d, c) = y.split();
        let e = (a ^ b) & (c ^ d);
        let p = (a & c) ^ e;
        let q = (b & d) ^ e;
        return Bs2State(q, p);
    }

    // scale by N = Omega^2 in GF(2^2), using normal basis (Omega^2,Omega)
    fn scl_n(&self) -> Bs2State<T> {
        let (b, a) = self.split();
        let q = a ^ b;
        return Bs2State(q, b);
    }

    // scale by N^2 = Omega in GF(2^2), using normal basis (Omega^2,Omega)
    fn scl_n2(&self) -> Bs2State<T> {
        let (b, a) = self.split();
        let p = a ^ b;
        let q = a;
        return Bs2State(q, p);
    }

    // square in GF(2^2), using normal basis (Omega^2,Omega)
    // NOTE: inverse is identical
    fn sq(&self) -> Bs2State<T> {
        let (b, a) = self.split();
        return Bs2State(a, b);
    }

    fn inv(&self) -> Bs2State<T> {
        // Same as sqaure
        return self.sq();
    }
}

impl <T: BitXor<T, T> + BitAnd<T, T> + Clone> Bs4State<T> {
    // multiply in GF(2^4), using normal basis (alpha^8,alpha^2)
    fn mul(&self, y: &Bs4State<T>) -> Bs4State<T> {
        let (b, a) = self.split();
        let (d, c) = y.split();
        let f = c.xor(&d);
        let e = a.xor(&b).mul(&f).scl_n();
        let p = a.mul(&c).xor(&e);
        let q = b.mul(&d).xor(&e);
        return q.join(&p);
    }

    // square & scale by nu in GF(2^4)/GF(2^2), normal basis (alpha^8,alpha^2)
    // nu = beta^8 = N^2*alpha^2, N = w^2
    fn sq_scl(&self) -> Bs4State<T> {
        let (b, a) = self.split();
        let p = a.xor(&b).sq();
        let q = b.sq().scl_n2();
        return q.join(&p);
    }

    // inverse in GF(2^4), using normal basis (alpha^8,alpha^2)
    fn inv(&self) -> Bs4State<T> {
        let (b, a) = self.split();
        let c = a.xor(&b).sq().scl_n();
        let d = a.mul(&b);
        let e = c.xor(&d).inv();
        let p = e.mul(&b);
        let q = e.mul(&a);
        return q.join(&p);
    }
}

impl <T: BitXor<T, T> + BitAnd<T, T> + Clone + Zero> Bs8State<T> {
    // inverse in GF(2^8), using normal basis (d^16,d)
    fn inv(&self) -> Bs8State<T> {
        let (b, a) = self.split();
        let c = a.xor(&b).sq_scl();
        let d = a.mul(&b);
        let e = c.xor(&d).inv();
        let p = e.mul(&b);
        let q = e.mul(&a);
        return q.join(&p);
    }

    fn change_basis(&self, arr: &[[T, ..8], ..8]) -> Bs8State<T> {
        let Bs8State(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7) = *self;

        let mut x0_out: T = Zero::zero();
        let mut x1_out: T = Zero::zero();
        let mut x2_out: T = Zero::zero();
        let mut x3_out: T = Zero::zero();
        let mut x4_out: T = Zero::zero();
        let mut x5_out: T = Zero::zero();
        let mut x6_out: T = Zero::zero();
        let mut x7_out: T = Zero::zero();

        /*
        // XXX - This is prettier, but crashes

        macro_rules! helper( ($x:ident, $idx:expr) => (
                {
                    x0_out = x0_out ^ (*($x) & arr[7 - $idx][0]);
                    x1_out = x1_out ^ (*($x) & arr[7 - $idx][1]);
                    x2_out = x2_out ^ (*($x) & arr[7 - $idx][2]);
                    x3_out = x3_out ^ (*($x) & arr[7 - $idx][3]);
                    x4_out = x4_out ^ (*($x) & arr[7 - $idx][4]);
                    x5_out = x5_out ^ (*($x) & arr[7 - $idx][5]);
                    x6_out = x6_out ^ (*($x) & arr[7 - $idx][6]);
                    x7_out = x7_out ^ (*($x) & arr[7 - $idx][7]);
                }
            )
        )

        helper!(x0, 0);
        helper!(x1, 1);
        helper!(x2, 2);
        helper!(x3, 3);
        helper!(x4, 4);
        helper!(x5, 5);
        helper!(x6, 6);
        helper!(x7, 7);
        */

        x0_out = x0_out ^ (*x0 & arr[7][0]);
        x1_out = x1_out ^ (*x0 & arr[7][1]);
        x2_out = x2_out ^ (*x0 & arr[7][2]);
        x3_out = x3_out ^ (*x0 & arr[7][3]);
        x4_out = x4_out ^ (*x0 & arr[7][4]);
        x5_out = x5_out ^ (*x0 & arr[7][5]);
        x6_out = x6_out ^ (*x0 & arr[7][6]);
        x7_out = x7_out ^ (*x0 & arr[7][7]);

        x0_out = x0_out ^ (*x1 & arr[6][0]);
        x1_out = x1_out ^ (*x1 & arr[6][1]);
        x2_out = x2_out ^ (*x1 & arr[6][2]);
        x3_out = x3_out ^ (*x1 & arr[6][3]);
        x4_out = x4_out ^ (*x1 & arr[6][4]);
        x5_out = x5_out ^ (*x1 & arr[6][5]);
        x6_out = x6_out ^ (*x1 & arr[6][6]);
        x7_out = x7_out ^ (*x1 & arr[6][7]);

        x0_out = x0_out ^ (*x2 & arr[5][0]);
        x1_out = x1_out ^ (*x2 & arr[5][1]);
        x2_out = x2_out ^ (*x2 & arr[5][2]);
        x3_out = x3_out ^ (*x2 & arr[5][3]);
        x4_out = x4_out ^ (*x2 & arr[5][4]);
        x5_out = x5_out ^ (*x2 & arr[5][5]);
        x6_out = x6_out ^ (*x2 & arr[5][6]);
        x7_out = x7_out ^ (*x2 & arr[5][7]);

        x0_out = x0_out ^ (*x3 & arr[4][0]);
        x1_out = x1_out ^ (*x3 & arr[4][1]);
        x2_out = x2_out ^ (*x3 & arr[4][2]);
        x3_out = x3_out ^ (*x3 & arr[4][3]);
        x4_out = x4_out ^ (*x3 & arr[4][4]);
        x5_out = x5_out ^ (*x3 & arr[4][5]);
        x6_out = x6_out ^ (*x3 & arr[4][6]);
        x7_out = x7_out ^ (*x3 & arr[4][7]);

        x0_out = x0_out ^ (*x4 & arr[3][0]);
        x1_out = x1_out ^ (*x4 & arr[3][1]);
        x2_out = x2_out ^ (*x4 & arr[3][2]);
        x3_out = x3_out ^ (*x4 & arr[3][3]);
        x4_out = x4_out ^ (*x4 & arr[3][4]);
        x5_out = x5_out ^ (*x4 & arr[3][5]);
        x6_out = x6_out ^ (*x4 & arr[3][6]);
        x7_out = x7_out ^ (*x4 & arr[3][7]);

        x0_out = x0_out ^ (*x5 & arr[2][0]);
        x1_out = x1_out ^ (*x5 & arr[2][1]);
        x2_out = x2_out ^ (*x5 & arr[2][2]);
        x3_out = x3_out ^ (*x5 & arr[2][3]);
        x4_out = x4_out ^ (*x5 & arr[2][4]);
        x5_out = x5_out ^ (*x5 & arr[2][5]);
        x6_out = x6_out ^ (*x5 & arr[2][6]);
        x7_out = x7_out ^ (*x5 & arr[2][7]);

        x0_out = x0_out ^ (*x6 & arr[1][0]);
        x1_out = x1_out ^ (*x6 & arr[1][1]);
        x2_out = x2_out ^ (*x6 & arr[1][2]);
        x3_out = x3_out ^ (*x6 & arr[1][3]);
        x4_out = x4_out ^ (*x6 & arr[1][4]);
        x5_out = x5_out ^ (*x6 & arr[1][5]);
        x6_out = x6_out ^ (*x6 & arr[1][6]);
        x7_out = x7_out ^ (*x6 & arr[1][7]);

        x0_out = x0_out ^ (*x7 & arr[0][0]);
        x1_out = x1_out ^ (*x7 & arr[0][1]);
        x2_out = x2_out ^ (*x7 & arr[0][2]);
        x3_out = x3_out ^ (*x7 & arr[0][3]);
        x4_out = x4_out ^ (*x7 & arr[0][4]);
        x5_out = x5_out ^ (*x7 & arr[0][5]);
        x6_out = x6_out ^ (*x7 & arr[0][6]);
        x7_out = x7_out ^ (*x7 & arr[0][7]);

        return Bs8State(x0_out, x1_out, x2_out, x3_out, x4_out, x5_out, x6_out, x7_out);
    }
}

// to convert between polynomial (A^7...1) basis A & normal basis X
// or to basis S which incorporates bit matrix of Sbox
static A2X_new: [[u32, ..8], ..8] = [
    [ 0,  0,  0, -1, -1,  0,  0, -1],
    [-1, -1,  0,  0, -1, -1, -1, -1],
    [ 0, -1,  0,  0, -1, -1, -1, -1],
    [ 0,  0,  0, -1,  0,  0, -1,  0],
    [-1,  0,  0, -1,  0,  0,  0,  0],
    [-1,  0,  0,  0,  0,  0,  0, -1],
    [-1,  0,  0, -1,  0, -1,  0, -1],
    [-1, -1, -1, -1, -1, -1, -1, -1]
];
static X2A_new: [[u32, ..8], ..8] = [
    [ 0,  0, -1,  0,  0, -1, -1,  0],
    [ 0,  0,  0, -1, -1, -1, -1,  0],
    [ 0, -1, -1, -1,  0, -1, -1,  0],
    [ 0,  0, -1, -1,  0,  0,  0, -1],
    [ 0,  0,  0, -1,  0, -1, -1,  0],
    [-1,  0,  0, -1,  0, -1,  0,  0],
    [ 0, -1, -1, -1, -1,  0, -1, -1],
    [ 0,  0,  0,  0,  0, -1, -1,  0],
];
static X2S_new: [[u32, ..8], ..8] = [
    [ 0,  0,  0, -1, -1,  0, -1,  0],
    [-1,  0, -1, -1,  0, -1,  0,  0],
    [ 0, -1, -1, -1, -1,  0,  0, -1],
    [-1, -1,  0, -1,  0,  0,  0,  0],
    [ 0,  0, -1, -1, -1,  0, -1, -1],
    [ 0,  0, -1,  0,  0,  0,  0,  0],
    [-1, -1,  0,  0,  0,  0,  0,  0],
    [ 0,  0, -1,  0,  0, -1,  0,  0],
];
static S2X_new: [[u32, ..8], ..8] = [
    [0, 0 ,  -1, -1,  0,  0,  0, -1],
    [-1,  0,  0, -1, -1, -1, -1,  0],
    [-1,  0, -1,  0,  0,  0,  0,  0],
    [-1, -1,  0, -1,  0, -1, -1, -1],
    [0,  -1,  0,  0, -1,  0,  0,  0],
    [0,   0, -1,  0,  0,  0,  0,  0],
    [-1,  0,  0,  0, -1,  0, -1,  0],
    [-1, -1,  0,  0, -1,  0, -1,  0],
];











