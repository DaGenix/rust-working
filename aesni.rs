// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::vec::bytes;

use symmetriccipher::*;

pub struct AesNi128Encryptor {
    priv round_keys: [u8, ..16 * (10 + 1)]
}

pub struct AesNi128Decryptor {
    priv round_keys: [u8, ..16 * (10 + 1)]
}

impl AesNi128Encryptor {
    pub fn new() -> AesNi128Encryptor {
        return AesNi128Encryptor {
            round_keys: ([0u8, ..16 * (10 + 1)])
        };
    }
}

impl AesNi128Decryptor {
    pub fn new() -> AesNi128Decryptor {
        return AesNi128Decryptor {
            round_keys: ([0u8, ..16 * (10 + 1)])
        };
    }
}

impl BlockEncryptor for AesNi128Encryptor {
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aseni(10, input, self.round_keys, output);
    }
}

impl SymmetricCipher for AesNi128Encryptor {
    fn set_key(&mut self, key: &[u8]) {
        setup_working_key_aesni_128(key, Encryption, self.round_keys);
    }
}

impl BlockDecryptor for AesNi128Decryptor {
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aseni(10, input, self.round_keys, output);
    }
}

impl SymmetricCipher for AesNi128Decryptor {
    fn set_key(&mut self, key: &[u8]) {
        setup_working_key_aesni_128(key, Decryption, self.round_keys);
    }
}

pub struct AesNi192Encryptor {
    priv round_keys: [u8, ..16 * (12 + 1)]
}

pub struct AesNi192Decryptor {
    priv round_keys: [u8, ..16 * (12 + 1)]
}

impl AesNi192Encryptor {
    pub fn new() -> AesNi192Encryptor {
        return AesNi192Encryptor {
            round_keys: ([0u8, ..16 * (12 + 1)])
        };
    }
}

impl AesNi192Decryptor {
    pub fn new() -> AesNi192Decryptor {
        return AesNi192Decryptor {
            round_keys: ([0u8, ..16 * (12 + 1)])
        };
    }
}

impl BlockEncryptor for AesNi192Encryptor {
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aseni(12, input, self.round_keys, output);
    }
}

impl SymmetricCipher for AesNi192Encryptor {
    fn set_key(&mut self, key: &[u8]) {
        setup_working_key_aesni_192(key, Encryption, self.round_keys);
    }
}

impl BlockDecryptor for AesNi192Decryptor {
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aseni(12, input, self.round_keys, output);
    }
}

impl SymmetricCipher for AesNi192Decryptor {
    fn set_key(&mut self, key: &[u8]) {
        setup_working_key_aesni_192(key, Decryption, self.round_keys);
    }
}

pub struct AesNi256Encryptor {
    priv round_keys: [u8, ..16 * (14 + 1)]
}

pub struct AesNi256Decryptor {
    priv round_keys: [u8, ..16 * (14 + 1)]
}

impl AesNi256Encryptor {
    pub fn new() -> AesNi256Encryptor {
        return AesNi256Encryptor {
            round_keys: ([0u8, ..16 * (14 + 1)])
        };
    }
}

impl AesNi256Decryptor {
    pub fn new() -> AesNi256Decryptor {
        return AesNi256Decryptor {
            round_keys: ([0u8, ..16 * (14 + 1)])
        };
    }
}

impl BlockEncryptor for AesNi256Encryptor {
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt_block_aseni(14, input, self.round_keys, output);
    }
}

impl SymmetricCipher for AesNi256Encryptor {
    fn set_key(&mut self, key: &[u8]) {
        setup_working_key_aesni_256(key, Encryption, self.round_keys);
    }
}

impl BlockDecryptor for AesNi256Decryptor {
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt_block_aseni(14, input, self.round_keys, output);
    }
}

impl SymmetricCipher for AesNi256Decryptor {
    fn set_key(&mut self, key: &[u8]) {
        setup_working_key_aesni_256(key, Decryption, self.round_keys);
    }
}

enum KeyType {
    Encryption,
    Decryption
}

#[inline]
unsafe fn aesimc(round_keys: *u8) {
    asm!(
    "
    movdqu ($0), %xmm1
    aesimc %xmm1, %xmm1
    movdqu %xmm1, ($0)
    "
    : // outputs
    : "r" (round_keys) // inputs
    : "xmm1", "memory" // clobbers
    : "volatile"
    )
}

#[inline(never)]
fn setup_working_key_aesni_128(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
    unsafe {
        // copy the key into the round_key
        bytes::copy_memory(round_key, key, key.len());

        let mut round_keysp: *u8 = round_key.unsafe_ref(0);
        let keyp: *u8 = key.unsafe_ref(0);

        asm!(
        "
            movdqu ($1), %xmm1
            add $$0x10, $0 /* skip over the bytes we already copied */

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
        : "=r" (round_keysp)
        : "r" (keyp), "0" (round_keysp)
        : "xmm1", "xmm2", "xmm3", "memory"
        : "volatile"
        )

        match key_type {
            Decryption => {
                // range of rounds keys from #1 to #9; skip the first and last key
                for i in range(1u, 10) {
                    aesimc(round_key.unsafe_ref(16 * i));
                }
            }
            Encryption => { /* nothing more to do */ }
        }
    }
}

fn setup_working_key_aesni_192(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
}

fn setup_working_key_aesni_256(key: &[u8], key_type: KeyType, round_key: &mut [u8]) {
}

#[inline(never)]
fn encrypt_block_aseni(rounds: uint, input: &[u8], round_keys: &[u8], output: &mut [u8]) {
    unsafe {
        let mut rounds = rounds;
        let mut round_keysp: *u8 = round_keys.unsafe_ref(0);
        let outp: *u8 = output.unsafe_ref(0);
        let inp: *u8 = input.unsafe_ref(0);

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
        : "=r" (rounds), "=r" (round_keysp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (round_keysp) // inputs
        : "xmm0", "xmm15", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }
}

#[inline(never)]
fn decrypt_block_aseni(rounds: uint, input: &[u8], round_keys: &[u8], output: &mut [u8]) {
    unsafe {
        let mut rounds = rounds;
        let mut round_keysp: *u8 = round_keys.unsafe_ref(round_keys.len() - 16);
        let outp: *u8 = output.unsafe_ref(0);
        let inp: *u8 = input.unsafe_ref(0);

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
        : "=r" (rounds), "=r" (round_keysp) // outputs
        : "r" (inp), "r" (outp), "0" (rounds), "1" (round_keysp) // inputs
        : "xmm0", "xmm15", "memory", "cc" // clobbers
        : "volatile" // options
        );
    }
}
