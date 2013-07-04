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

impl AesEncryptor {
    fn new() -> AesEncryptor {
        return AesEncryptor {
            kw: ([0u8, ..16 * (10 + 1)])
        };
    }
}


impl SymmetricBlockEncryptor16 for AesEncryptor {
    fn init(&mut self, key: &[u8]) {
        setup_working_key(key, 10, Encryption, self.kw);
    }

    fn encrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16] {
        return encrypt_block_aseni(10, in, self.kw);
    }
}


/*
impl SymmetricBlockDecryptor16 for AesEncryptor {
    fn init(&mut self, key: &[u8, ..16]) {

    }

    fn decrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16] {
        [0u8, ..16]
    }
}
*/

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

fn setup_working_key(key: &[u8], rounds: uint, key_type: KeyType, kw: &mut [u8]) {
    use std::cast::transmute;
    use std::ptr::to_unsafe_ptr;

    unsafe {
        let keyp: *u8 = key.unsafe_ref(0);
        let kwp: *u8 = kw.unsafe_ref(0);

        asm!(
        "
            movdqu ($0), %xmm1
            movdqu %xmm1, ($1)
            mov $1, %rcx
            add $$0x10, %rcx

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

            jmp END

            key_expansion_128:
            pshufd $$0xff, %xmm2, %xmm2
            vpslldq $$0x04, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            vpslldq $$0x4, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            vpslldq $$0x04, %xmm1, %xmm3
            pxor %xmm3, %xmm1
            pxor %xmm2, %xmm1
            movdqu %xmm1, (%rcx)
            add $$0x10, %rcx
            ret

            END:
        "
        :
        : "r" (keyp), "r" (kwp)
        : "rcx", "xmm1", "xmm2", "xmm3" /* is "cc" needed? other registers? */
        : "volatile"
        )
    }

}

fn encrypt_block_aseni(rounds: uint, in: &[u8, ..16], kw: &[u8]) -> [u8, ..16] {
    use std::cast::transmute;

    let out = [0u8, ..16];

    unsafe {
        let kwp: *u8 = kw.unsafe_ref(0);
        let inp: *u8 = in.unsafe_ref(0);
        let mut outp: *u8 = out.unsafe_ref(0);

        asm!(
        "
        movdqu ($1), %xmm15

        mov $0, %rcx

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        pxor %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenc %xmm0, %xmm15

        movdqu (%rcx), %xmm0
        add $$0x10, %rcx
        aesenclast %xmm0, %xmm15

        movdqu %xmm15, ($2)
        "
        : // outputs
        : "r" (kwp), "r" (inp), "r" (outp) // inputs
        : "xmm0", "xmm15", "rcx" // clobbers
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
  //              let mut dec = $dec::new(test.key);

                for test.data.iter().advance() |data| {
                    let tmp = enc.encrypt_block(&data.plain);

                    println(to_hex(data.cipher));
                    println(to_hex(tmp));

                    assert!(vec::eq(tmp, data.cipher));
  //                  let tmp = dec.decrypt_block(&data.cipher);
  //                  assert!(vec::eq(tmp, data.plain));
                }
            }
        )
    )
    define_run_test!(run_test128, AesEncryptor, Aes128Decrypt)
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
//                         plain:  [0x2a, 0x17, 0x93, 0x73, 0x11, 0x7e, 0x3d, 0xe9,
//                                  0x96, 0x9f, 0x40, 0x2e, 0xe2, 0xbe, 0xc1, 0x6b],
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
