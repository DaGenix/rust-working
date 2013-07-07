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

use symmetriccipher::*;

/*
 * A Simple AES implementation using Intel AES-NI instructions
 */

pub struct AesNi128Encryptor {
    priv kw: [u8, ..16 * (10 + 1)]
}

pub struct AesNi128Decryptor {
    priv kw: [u8, ..16 * (10 + 1)]
}

impl AesNi128Encryptor {
    pub fn new() -> AesNi128Encryptor {
        return AesNi128Encryptor {
            kw: ([0u8, ..16 * (10 + 1)])
        };
    }
}

impl AesNi128Decryptor {
    pub fn new() -> AesNi128Decryptor {
        return AesNi128Decryptor {
            kw: ([0u8, ..16 * (10 + 1)])
        };
    }
}

impl BlockEncryptor128 for AesNi128Encryptor {
    fn encrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        return encrypt_block_aseni(10, in, self.kw);
    }
}

impl SymmetricCipher128 for AesNi128Encryptor {
    fn set_key(&mut self, key: &[u8, ..16]) {
        self.kw = setup_working_key_aesni_128(key, Encryption);
    }
}

impl BlockDecryptor128 for AesNi128Decryptor {
    fn decrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        return decrypt_block_aseni(10, in, self.kw);
    }
}

impl SymmetricCipher128 for AesNi128Decryptor {
    fn set_key(&mut self, key: &[u8, ..16]) {
        self.kw = setup_working_key_aesni_128(key, Decryption);
    }
}

pub struct AesNi192Encryptor {
    priv kw: [u8, ..16 * (12 + 1)]
}

pub struct AesNi192Decryptor {
    priv kw: [u8, ..16 * (12 + 1)]
}

impl AesNi192Encryptor {
    pub fn new() -> AesNi192Encryptor {
        return AesNi192Encryptor {
            kw: ([0u8, ..16 * (12 + 1)])
        };
    }
}

impl AesNi192Decryptor {
    pub fn new() -> AesNi192Decryptor {
        return AesNi192Decryptor {
            kw: ([0u8, ..16 * (12 + 1)])
        };
    }
}

impl BlockEncryptor128 for AesNi192Encryptor {
    fn encrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        return encrypt_block_aseni(12, in, self.kw);
    }
}

impl SymmetricCipher192 for AesNi192Encryptor {
    fn set_key(&mut self, key: &[u8, ..24]) {
        self.kw = setup_working_key_aesni_192(key, Encryption);
    }
}

impl BlockDecryptor128 for AesNi192Decryptor {
    fn decrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        return decrypt_block_aseni(12, in, self.kw);
    }
}

impl SymmetricCipher192 for AesNi192Decryptor {
    fn set_key(&mut self, key: &[u8, ..24]) {
        self.kw = setup_working_key_aesni_192(key, Decryption);
    }
}

pub struct AesNi256Encryptor {
    priv kw: [u8, ..16 * (14 + 1)]
}

pub struct AesNi256Decryptor {
    priv kw: [u8, ..16 * (14 + 1)]
}

impl AesNi256Encryptor {
    pub fn new() -> AesNi256Encryptor {
        return AesNi256Encryptor {
            kw: ([0u8, ..16 * (14 + 1)])
        };
    }
}

impl AesNi256Decryptor {
    pub fn new() -> AesNi256Decryptor {
        return AesNi256Decryptor {
            kw: ([0u8, ..16 * (14 + 1)])
        };
    }
}

impl BlockEncryptor128 for AesNi256Encryptor {
    fn encrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        return encrypt_block_aseni(14, in, self.kw);
    }
}

impl SymmetricCipher256 for AesNi256Encryptor {
    fn set_key(&mut self, key: &[u8, ..32]) {
        self.kw = setup_working_key_aesni_256(key, Encryption);
    }
}

impl BlockDecryptor128 for AesNi256Decryptor {
    fn decrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        return decrypt_block_aseni(14, in, self.kw);
    }
}

impl SymmetricCipher256 for AesNi256Decryptor {
    fn set_key(&mut self, key: &[u8, ..32]) {
        self.kw = setup_working_key_aesni_256(key, Decryption);
    }
}

enum KeyType {
    Encryption,
    Decryption
}

#[inline]
unsafe fn aesimc(kw: *u8) {
    asm!(
    "
    movdqu ($0), %xmm1
    aesimc %xmm1, %xmm1
    movdqu %xmm1, ($0)
    "
    : // outputs
    : "r" (kw) // inputs
    : "xmm1", "memory" // clobbers
    : "volatile"
    )
}

fn setup_working_key_aesni_128(key: &[u8, ..16], key_type: KeyType) -> [u8, ..16 * (10 + 1)] {
    let kw = [0u8, ..16 * (10 + 1)];

    unsafe {
        let mut kwp: *u8 = kw.unsafe_ref(0);
        let keyp: *u8 = key.unsafe_ref(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu %xmm1, ($0)
            add $$0x10, $0

            aeskeygenassist $$0x01, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x02, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x04, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x08, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x10, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x20, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x40, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x80, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x1b, %xmm1, %xmm2
            call key_expansion_128
            aeskeygenassist $$0x36, %xmm1, %xmm2
            call key_expansion_128

            jmp end_key_128

            key_expansion_128:
            pshufd $$0xff, %xmm2, %xmm2
            vpslldq $$0x04, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            vpslldq $$0x4, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            vpslldq $$0x04, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            pxor %xmm2, %xmm1
            movdqu %xmm1, ($0)
            add $$0x10, $0
            ret

            end_key_128:
        "
        : "=r" (kwp)
        : "r" (keyp), "0" (kwp)
        : "xmm1", "xmm2", "xmm3", "memory"
        : "volatile"
        )

        match key_type {
            Encryption => { /* nothing more to do */ }
            Decryption => {
                // range of rounds keys from #1 to #9; skip the first and last key
                for uint::range(1, 10) |i| {
                    aesimc(kw.unsafe_ref(16 * i));
                }
            }
        }
    }

    return kw;
}

#[cfg(not(off))]
fn setup_working_key_aesni_192(key: &[u8, ..24], key_type: KeyType) -> [u8, ..16 * (12 + 1)] {
    [0u8, ..16 * (12 + 1)]
}

#[cfg(off)]
fn setup_working_key_aesni_192(key: &[u8, ..24], key_type: KeyType) -> [u8, ..16 * (12 + 1)] {
    let kw = [0u8, ..16 * (12 + 1)];

    unsafe {
        let mut kwp: *u8 = kw.unsafe_ref(0);
        let keyp: *u8 = key.unsafe_ref(0);

        asm!(
        "
            movdqu ($1), %xmm1
            movdqu %xmm1, ($0)
            add $$0x10, $0

                __m128i temp1, temp2, temp3, temp4;
                __m128i *Key_Schedule = (__m128i*)key;
                temp1 = _mm_loadu_si128((__m128i*)userkey);
                temp3 = _mm_loadu_si128((__m128i*)(userkey+16));
                Key_Schedule[0]=temp1;
                Key_Schedule[1]=temp3;
                temp2=_mm_aeskeygenassist_si128 (temp3,0x1);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[1] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[1],
                (__m128d)temp1,0);
                Key_Schedule[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
                temp2=_mm_aeskeygenassist_si128 (temp3,0x2);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[3]=temp1;
                Key_Schedule[4]=temp3;
                temp2=_mm_aeskeygenassist_si128 (temp3,0x4);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[4] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[4],
                (__m128d)temp1,0);
                Key_Schedule[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
                temp2=_mm_aeskeygenassist_si128 (temp3,0x8);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[6]=temp1;
                Key_Schedule[7]=temp3;
                temp2=_mm_aeskeygenassist_si128 (temp3,0x10);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[7] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[7],
                (__m128d)temp1,0);
                Key_Schedule[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
                temp2=_mm_aeskeygenassist_si128 (temp3,0x20);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[9]=temp1;
                Key_Schedule[10]=temp3;
                temp2=_mm_aeskeygenassist_si128 (temp3,0x40);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[10] = (__m128i)_mm_shuffle_pd((__m128d)Key_Schedule[10],
                (__m128d)temp1,0);
                Key_Schedule[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
                temp2=_mm_aeskeygenassist_si128 (temp3,0x80);
                KEY_192_ASSIST(&temp1, &temp2, &temp3);
                Key_Schedule[12]=temp1;

            jmp end_key_192

            key_expansion_192:
                __m128i temp4;
                *temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
                temp4 = _mm_slli_si128 (*temp1, 0x4);
                *temp1 = _mm_xor_si128 (*temp1, temp4);
                temp4 = _mm_slli_si128 (temp4, 0x4);
                *temp1 = _mm_xor_si128 (*temp1, temp4);
                temp4 = _mm_slli_si128 (temp4, 0x4);
                *temp1 = _mm_xor_si128 (*temp1, temp4);
                *temp1 = _mm_xor_si128 (*temp1, *temp2);
                *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
                temp4 = _mm_slli_si128 (*temp3, 0x4);
                *temp3 = _mm_xor_si128 (*temp3, temp4);
                *temp3 = _mm_xor_si128 (*temp3, *temp2);
            ret

            end_key_192:
        "
        : "=r" (kwp)
        : "r" (keyp), "0" (kwp)
        : "xmm1", "xmm2", "xmm3", "memory"
        : "volatile"
        )

        match key_type {
            Encryption => { /* nothing more to do */ }
            Decryption => {
                // range of rounds keys from #1 to #11; skip the first and last key
                for uint::range(1, 12) |i| {
                    aesimc(kw.unsafe_ref(16 * i));
                }
            }
        }
    }

    return kw;
}

fn setup_working_key_aesni_256(key: &[u8, ..32], key_type: KeyType) -> [u8, ..16 * (14 + 1)] {
    [0u8, ..16 * (14 + 1)]
}

fn encrypt_block_aseni(rounds: uint, in: &[u8, ..16], kw: &[u8]) -> [u8, ..16] {
    use std::cast::transmute;

    let out = [0u8, ..16];

    unsafe {
        let mut rounds = rounds;
        let mut kwp: *u8 = kw.unsafe_ref(0);
        let outp: *u8 = out.unsafe_ref(0);
        let inp: *u8 = in.unsafe_ref(0);

        asm!(
        "
        /* Copy the data to encrypt to xmm15 */
        movdqu ($2), %xmm15

        /* Perform round 0 - the whitening step */
        movdqu ($1), %xmm0
        add $$0x10, $1
        pxor %xmm0, %xmm15

        /* Perform all remaining rounds (except the final one) */
        enc_round:
        movdqu ($1), %xmm0
        add $$0x10, $1
        aesenc %xmm0, %xmm15
        sub $$0x01, $0
        cmp $$0x01, $0
        jne enc_round

        /* Perform the last round */
        movdqu ($1), %xmm0
        aesenclast %xmm0, %xmm15

        /* Finally, move the result from xmm15 to outp */
        movdqu %xmm15, ($3)
        "
        : "=r" (rounds), "=r" (kwp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (kwp) // inputs
        : "xmm0", "xmm15", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }

    return out;
}

fn decrypt_block_aseni(rounds: uint, in: &[u8, ..16], kw: &[u8]) -> [u8, ..16] {
    let out = [0u8, ..16];

    unsafe {
        let mut rounds = rounds;
        let mut kwp: *u8 = kw.unsafe_ref(kw.len() - 16);
        let outp: *u8 = out.unsafe_ref(0);
        let inp: *u8 = in.unsafe_ref(0);

        asm!(
        "
        /* Copy the data to decrypt to xmm15 */
        movdqu ($2), %xmm15

        /* Perform round 0 - the whitening step */
        movdqu ($1), %xmm0
        sub $$0x10, $1
        pxor %xmm0, %xmm15

        /* Perform all remaining rounds (except the final one) */
        dec_round:
        movdqu ($1), %xmm0
        sub $$0x10, $1
        aesdec %xmm0, %xmm15
        sub $$0x01, $0
        cmp $$0x01, $0
        jne dec_round

        /* Perform the last round */
        movdqu ($1), %xmm0
        aesdeclast %xmm0, %xmm15

        /* Finally, move the result from xmm15 to outp */
        movdqu %xmm15, ($3)
        "
        : "=r" (rounds), "=r" (kwp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (kwp) // inputs
        : "xmm0", "xmm15", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }

    return out;
}
