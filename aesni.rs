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

/*
 * A Simple AES implementation using Intel AES-NI instructions
 */

pub trait SymmetricBlockEncryptor16 {
    fn init(&mut self, key: &[u8]);
    fn encrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16];
}

pub trait SymmetricBlockDecryptor16 {
    fn init(&mut self, key: &[u8]);
    fn decrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16];
}

struct AesEncryptor {
    kw: [u8, ..16 * (10 + 1)]
}

struct AesDecryptor {
    kw: [u8, ..16 * (10 + 1)]
}

impl AesEncryptor {
    pub fn new() -> AesEncryptor {
        return AesEncryptor {
            kw: ([0u8, ..16 * (10 + 1)])
        };
    }
}

impl AesDecryptor {
    pub fn new() -> AesDecryptor {
        return AesDecryptor {
            kw: ([0u8, ..16 * (10 + 1)])
        };
    }
}


impl SymmetricBlockEncryptor16 for AesEncryptor {
    fn init(&mut self, key: &[u8]) {
        self.kw = setup_working_key_aesni_128(key, Encryption);
    }

    fn encrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16] {
        return encrypt_block_aseni(10, in, self.kw);
    }
}

impl SymmetricBlockDecryptor16 for AesDecryptor {
    fn init(&mut self, key: &[u8]) {
        self.kw = setup_working_key_aesni_128(key, Decryption);
    }

    fn decrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16] {
        return decrypt_block_aseni(10, in, self.kw);
    }
}


fn cpuid(func: u32) -> (u32, u32, u32, u32) {
    let mut a = 0u32;
    let mut b = 0u32;
    let mut c = 0u32;
    let mut d = 0u32;

    unsafe {
        asm!(
        "
        movl $4, %eax;
        cpuid;
        movl %eax, $0;
        movl %ebx, $1;
        movl %ecx, $2;
        movl %edx, $3;
        "
        : "=r" (a), "=r" (b), "=r" (c), "=r" (d)
        : "r" (func)
        : "eax", "ebx", "ecx", "edx"
        : "volatile"
        )
    }

    return (a, b, c, d);
}

fn supports_aesni() -> bool {
    let (_, _, c, _) = cpuid(1);
    return (c & 0x02000000) != 0;
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

fn setup_working_key_aesni_128(key: &[u8], key_type: KeyType) -> [u8, ..16 * (10 + 1)] {
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

#[cfg(off)]
fn setup_working_key_aesni_192(key: &[u8], key_type: KeyType) -> [u8, ..16 * (12 + 1)] {
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


#[cfg(test)]
mod test {
    use std::vec;

    use aesni::*;
    use symmetriccipher::*;

    // Test vectors from:
    // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

    struct Test {
        key: ~[u8],
        data: ~[TestData]
    }

    struct TestData {
        plain: [u8, ..16],
        cipher: [u8, ..16]
    }

    fn to_hex(rr: &[u8]) -> ~str {
        use std::uint;
        let mut s = ~"";
        for rr.iter().advance() |b| {
            let hex = uint::to_str_radix(*b as uint, 16u);
            if hex.len() == 1 {
                s.push_char('0');
            }
            s.push_str(hex);
        }
        return s;
    }

    macro_rules! define_run_test(($func:ident, $enc:ident, $dec:ident) => (
            fn $func(test: &Test) {
                let mut enc = $enc::new();
                enc.init(test.key);
                let mut dec = $dec::new();
                dec.init(test.key);

                for test.data.iter().advance() |data| {
                    let tmp = enc.encrypt_block(&data.plain);
                    assert!(vec::eq(tmp, data.cipher));
                    let tmp = dec.decrypt_block(&data.cipher);
                    assert!(vec::eq(tmp, data.plain));
                }
            }
        )
    )
    define_run_test!(run_test128, AesEncryptor, AesDecryptor)
//    define_run_test!(run_test192, Aes192Encrypt, Aes192Decrypt)
//    define_run_test!(run_test256, Aes256Encrypt, Aes256Decrypt)

    #[test]
    fn testAes128() {
        let tests = ~[
            Test {
                key: ~[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
                data: ~[
                    TestData {
                        plain:  [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: [0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                                 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97]
                    },
                    TestData {
                        plain:  [0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: [0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
                                 0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf]
                    },
                    TestData {
                        plain:  [0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: [0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
                                 0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88]
                    },
                    TestData {
                        plain:  [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: [0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
                                 0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4]
                    }
                ]
            }
        ];

        for tests.iter().advance() |t| {
            run_test128(t);
        }
    }

    /*
//    #[test]
    fn testAes192() {
        let tests = ~[
            Test {
                key: ~[0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                       0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
                data: ~[
                    TestData {
                        plain:  [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: [0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
                                 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc]
                    },
                    TestData {
                        plain:  [0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: [0x97, 0x41, 0x04, 0x84, 0x6d, 0x0a, 0xd3, 0xad,
                                 0x77, 0x34, 0xec, 0xb3, 0xec, 0xee, 0x4e, 0xef]
                    },
                    TestData {
                        plain:  [0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: [0xef, 0x7a, 0xfd, 0x22, 0x70, 0xe2, 0xe6, 0x0a,
                                 0xdc, 0xe0, 0xba, 0x2f, 0xac, 0xe6, 0x44, 0x4e]
                    },
                    TestData {
                        plain:  [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: [0x9a, 0x4b, 0x41, 0xba, 0x73, 0x8d, 0x6c, 0x72,
                                 0xfb, 0x16, 0x69, 0x16, 0x03, 0xc1, 0x8e, 0x0e]
                    }
                ]
            }
        ];

        for tests.iter().advance() |t| {
            run_test192(t);
        }
    }

//    #[test]
    fn testAes256() {
        let tests = ~[
            Test {
                key: ~[0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                       0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                       0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                       0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
                data: ~[
                    TestData {
                        plain:  [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a],
                        cipher: [0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                                 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8]
                    },
                    TestData {
                        plain:  [0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51],
                        cipher: [0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
                                 0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70]
                    },
                    TestData {
                        plain:  [0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef],
                        cipher: [0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
                                 0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d]
                    },
                    TestData {
                        plain:  [0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10],
                        cipher: [0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                                 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7]
                    }
                ]
            }
        ];

        for tests.iter().advance() |t| {
            run_test256(t);
        }
    }
    */
}
