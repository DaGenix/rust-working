// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use aesni::*;
use aesdangerous::*;
use symmetriccipher::*;
use util::*;

////////////////////////////////////////////////////////////////////////////////////////////////////
// AES - Default handlinger for 128 bit varient
////////////////////////////////////////////////////////////////////////////////////////////////////

enum AesEncryptionEngine128 {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    AesNiEncryptionEngine128(AesNi128Encryptor),
    AesSoftwareDangerousEncryptionEngine128(Aes128Encrypt)
}

enum AesDecryptionEngine128 {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    AesNiDecryptionEngine128(AesNi128Decryptor),
    AesSoftwareDangerousDecryptionEngine128(Aes128Decrypt)
}

struct Aes128Encryptor {
    engine: AesEncryptionEngine128
}

struct Aes128Decryptor {
    engine: AesDecryptionEngine128
}

impl Aes128Encryptor {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Aes128Encryptor {
        if (supports_aesni()) {
            Aes128Encryptor {
                engine: AesNiEncryptionEngine128(AesNi128Encryptor::new())
            }
        } else {
            Aes128Encryptor {
                engine: AesSoftwareDangerousEncryptionEngine128(Aes128Encrypt::new())
            }
        }
    }

    #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
    pub fn new() -> Aes128Encryptor {
        fail!("Not yet implemented.")
    }
}

impl SymmetricCipher128 for Aes128Encryptor {
    fn set_key(&mut self, key: &[u8, ..16]) {
        match self.engine {
            AesNiEncryptionEngine128(ref mut engine) => {
                engine.set_key(key);
            },
            AesSoftwareDangerousEncryptionEngine128(ref mut engine) => {
                engine.set_key(key);
            }
        }
    }
}

impl BlockEncryptor128 for Aes128Encryptor {
    fn encrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        match self.engine {
            AesNiEncryptionEngine128(ref engine) => {
                return engine.encrypt_block(in);
            },
            AesSoftwareDangerousEncryptionEngine128(ref engine) => {
                return engine.encrypt_block(in);
            }
        }
    }
}

impl Aes128Decryptor {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Aes128Decryptor {
        if (supports_aesni()) {
            Aes128Decryptor {
                engine: AesNiDecryptionEngine128(AesNi128Decryptor::new())
            }
        } else {
            Aes128Decryptor {
                engine: AesSoftwareDangerousDecryptionEngine128(Aes128Decrypt::new())
            }
        }
    }

    #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
    pub fn new() -> Aes128Decryptor {
        fail!("Not yet implemented.")
    }
}

impl SymmetricCipher128 for Aes128Decryptor {
    fn set_key(&mut self, key: &[u8, ..16]) {
        match self.engine {
            AesNiDecryptionEngine128(ref mut engine) => {
                engine.set_key(key);
            },
            AesSoftwareDangerousDecryptionEngine128(ref mut engine) => {
                engine.set_key(key);
            }
        }
    }
}

impl BlockDecryptor128 for Aes128Decryptor {
    fn decrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        match self.engine {
            AesNiDecryptionEngine128(ref engine) => {
                return engine.decrypt_block(in);
            },
            AesSoftwareDangerousDecryptionEngine128(ref engine) => {
                return engine.decrypt_block(in);
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// AES - Default handlinger for 128 bit varient
////////////////////////////////////////////////////////////////////////////////////////////////////

enum AesEncryptionEngine192 {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    AesNiEncryptionEngine192(AesNi192Encryptor),
    AesSoftwareDangerousEncryptionEngine192(Aes192Encrypt)
}

enum AesDecryptionEngine192 {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    AesNiDecryptionEngine192(AesNi192Decryptor),
    AesSoftwareDangerousDecryptionEngine192(Aes192Decrypt)
}

struct Aes192Encryptor {
    engine: AesEncryptionEngine192
}

struct Aes192Decryptor {
    engine: AesDecryptionEngine192
}

impl Aes192Encryptor {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Aes192Encryptor {
        if (supports_aesni()) {
            Aes192Encryptor {
                engine: AesNiEncryptionEngine192(AesNi192Encryptor::new())
            }
        } else {
            Aes192Encryptor {
                engine: AesSoftwareDangerousEncryptionEngine192(Aes192Encrypt::new())
            }
        }
    }

    #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
    pub fn new() -> Aes192Encryptor {
        fail!("Not yet implemented.")
    }
}

impl SymmetricCipher192 for Aes192Encryptor {
    fn set_key(&mut self, key: &[u8, ..24]) {
        match self.engine {
            AesNiEncryptionEngine192(ref mut engine) => {
                engine.set_key(key);
            },
            AesSoftwareDangerousEncryptionEngine192(ref mut engine) => {
                engine.set_key(key);
            }
        }
    }
}

impl BlockEncryptor128 for Aes192Encryptor {
    fn encrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        match self.engine {
            AesNiEncryptionEngine192(ref engine) => {
                return engine.encrypt_block(in);
            },
            AesSoftwareDangerousEncryptionEngine192(ref engine) => {
                return engine.encrypt_block(in);
            }
        }
    }
}

impl Aes192Decryptor {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Aes192Decryptor {
        if (supports_aesni()) {
            Aes192Decryptor {
                engine: AesNiDecryptionEngine192(AesNi192Decryptor::new())
            }
        } else {
            Aes192Decryptor {
                engine: AesSoftwareDangerousDecryptionEngine192(Aes192Decrypt::new())
            }
        }
    }

    #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
    pub fn new() -> Aes192Decryptor {
        fail!("Not yet implemented.")
    }
}

impl SymmetricCipher192 for Aes192Decryptor {
    fn set_key(&mut self, key: &[u8, ..24]) {
        match self.engine {
            AesNiDecryptionEngine192(ref mut engine) => {
                engine.set_key(key);
            },
            AesSoftwareDangerousDecryptionEngine192(ref mut engine) => {
                engine.set_key(key);
            }
        }
    }
}

impl BlockDecryptor128 for Aes192Decryptor {
    fn decrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        match self.engine {
            AesNiDecryptionEngine192(ref engine) => {
                return engine.decrypt_block(in);
            },
            AesSoftwareDangerousDecryptionEngine192(ref engine) => {
                return engine.decrypt_block(in);
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// AES - Default handlinger for 256 bit varient
////////////////////////////////////////////////////////////////////////////////////////////////////

enum AesEncryptionEngine256 {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    AesNiEncryptionEngine256(AesNi256Encryptor),
    AesSoftwareDangerousEncryptionEngine256(Aes256Encrypt)
}

enum AesDecryptionEngine256 {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    AesNiDecryptionEngine256(AesNi256Decryptor),
    AesSoftwareDangerousDecryptionEngine256(Aes256Decrypt)
}

struct Aes256Encryptor {
    engine: AesEncryptionEngine256
}

struct Aes256Decryptor {
    engine: AesDecryptionEngine256
}

impl Aes256Encryptor {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Aes256Encryptor {
        if (supports_aesni()) {
            Aes256Encryptor {
                engine: AesNiEncryptionEngine256(AesNi256Encryptor::new())
            }
        } else {
            Aes256Encryptor {
                engine: AesSoftwareDangerousEncryptionEngine256(Aes256Encrypt::new())
            }
        }
    }

    #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
    pub fn new() -> Aes256Encryptor {
        fail!("Not yet implemented.")
    }
}

impl SymmetricCipher256 for Aes256Encryptor {
    fn set_key(&mut self, key: &[u8, ..32]) {
        match self.engine {
            AesNiEncryptionEngine256(ref mut engine) => {
                engine.set_key(key);
            },
            AesSoftwareDangerousEncryptionEngine256(ref mut engine) => {
                engine.set_key(key);
            }
        }
    }
}

impl BlockEncryptor128 for Aes256Encryptor {
    fn encrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        match self.engine {
            AesNiEncryptionEngine256(ref engine) => {
                return engine.encrypt_block(in);
            },
            AesSoftwareDangerousEncryptionEngine256(ref engine) => {
                return engine.encrypt_block(in);
            }
        }
    }
}

impl Aes256Decryptor {
    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    pub fn new() -> Aes256Decryptor {
        if (supports_aesni()) {
            Aes256Decryptor {
                engine: AesNiDecryptionEngine256(AesNi256Decryptor::new())
            }
        } else {
            Aes256Decryptor {
                engine: AesSoftwareDangerousDecryptionEngine256(Aes256Decrypt::new())
            }
        }
    }

    #[cfg(not(target_arch = "x86"), not(target_arch = "x86_64"))]
    pub fn new() -> Aes256Decryptor {
        fail!("Not yet implemented.")
    }
}

impl SymmetricCipher256 for Aes256Decryptor {
    fn set_key(&mut self, key: &[u8, ..32]) {
        match self.engine {
            AesNiDecryptionEngine256(ref mut engine) => {
                engine.set_key(key);
            },
            AesSoftwareDangerousDecryptionEngine256(ref mut engine) => {
                engine.set_key(key);
            }
        }
    }
}

impl BlockDecryptor128 for Aes256Decryptor {
    fn decrypt_block(&self, in: &[u8, ..16]) -> [u8, ..16] {
        match self.engine {
            AesNiDecryptionEngine256(ref engine) => {
                return engine.decrypt_block(in);
            },
            AesSoftwareDangerousDecryptionEngine256(ref engine) => {
                return engine.decrypt_block(in);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use aes::*;
    use aesni::*;
    use aesdangerous::*;
    use aessafe::*;
    use symmetriccipher::*;
    use util::*;

    // Test vectors from:
    // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

    struct Test128 {
        key: [u8, ..16],
        data: [TestData, ..4]
    }

    struct Test192 {
        key: [u8, ..24],
        data: [TestData, ..4]
    }

    struct Test256 {
        key: [u8, ..32],
        data: [TestData, ..4]
    }

    struct TestData {
        plain: [u8, ..16],
        cipher: [u8, ..16]
    }

    // TODO: Remove me
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

    static tests128: [Test128, ..1] = [
        Test128 {
            key: [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
            data: [
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

    static tests192: [Test192, ..1] = [
        Test192 {
            key: [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
                  0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
            data: [
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

    static tests256: [Test256, ..1] = [
        Test256 {
            key: [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                  0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
            data: [
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

    fn run_test128
            <E: BlockEncryptor128 + SymmetricCipher128,
            D: BlockDecryptor128 + SymmetricCipher128>(
            enc: &mut E,
            dec: &mut D,
            test: &Test128) {
        enc.set_key(&test.key);
        dec.set_key(&test.key);
        for test.data.iter().advance() |data| {
            let tmp = enc.encrypt_block(&data.plain);
            assert!(tmp == data.cipher);
            let tmp = dec.decrypt_block(&data.cipher);
            assert!(tmp == data.plain);
        }
    }

    fn run_test192
            <E: BlockEncryptor128 + SymmetricCipher192,
            D: BlockDecryptor128 + SymmetricCipher192>(
            enc: &mut E,
            dec: &mut D,
            test: &Test192) {
        enc.set_key(&test.key);
        dec.set_key(&test.key);
        for test.data.iter().advance() |data| {
            let tmp = enc.encrypt_block(&data.plain);
            assert!(tmp == data.cipher);
            let tmp = dec.decrypt_block(&data.cipher);
            assert!(tmp == data.plain);
        }
    }

    fn run_test256
            <E: BlockEncryptor128 + SymmetricCipher256,
            D: BlockDecryptor128 + SymmetricCipher256>(
            enc: &mut E,
            dec: &mut D,
            test: &Test256) {
        enc.set_key(&test.key);
        dec.set_key(&test.key);
        for test.data.iter().advance() |data| {
            let tmp = enc.encrypt_block(&data.plain);
            assert!(tmp == data.cipher);
            let tmp = dec.decrypt_block(&data.cipher);
            assert!(tmp == data.plain);
        }
    }

    #[test]
    fn testAesDefault128() {
        for tests128.iter().advance() |t| {
            let mut enc = Aes128Encryptor::new();
            let mut dec = Aes128Decryptor::new();
            run_test128(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesDefault192() {
        for tests192.iter().advance() |t| {
            let mut enc = Aes192Encryptor::new();
            let mut dec = Aes192Decryptor::new();
            run_test192(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesDefault256() {
        for tests256.iter().advance() |t| {
            let mut enc = Aes256Encryptor::new();
            let mut dec = Aes256Decryptor::new();
            run_test256(&mut enc, &mut dec, t);
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn testAesNi128() {
        if (supports_aesni()) {
            for tests128.iter().advance() |t| {
                let mut enc = AesNi128Encryptor::new();
                let mut dec = AesNi128Decryptor::new();
                run_test128(&mut enc, &mut dec, t);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn testAesNi192() {
        if (supports_aesni()) {
            for tests192.iter().advance() |t| {
                let mut enc = AesNi192Encryptor::new();
                let mut dec = AesNi192Decryptor::new();
                run_test192(&mut enc, &mut dec, t);
            }
        }
    }

    #[cfg(target_arch = "x86")]
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn testAesNi256() {
        if (supports_aesni()) {
            for tests256.iter().advance() |t| {
                let mut enc = AesNi256Encryptor::new();
                let mut dec = AesNi256Decryptor::new();
                run_test256(&mut enc, &mut dec, t);
            }
        }
    }

    #[test]
    fn testAesDangerous128() {
        for tests128.iter().advance() |t| {
            let mut enc = Aes128Encrypt::new();
            let mut dec = Aes128Decrypt::new();
            run_test128(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesDangerous192() {
        for tests192.iter().advance() |t| {
            let mut enc = Aes192Encrypt::new();
            let mut dec = Aes192Decrypt::new();
            run_test192(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesDangerous256() {
        for tests256.iter().advance() |t| {
            let mut enc = Aes256Encrypt::new();
            let mut dec = Aes256Decrypt::new();
            run_test256(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesSafe128() {
        for tests128.iter().advance() |t| {
            let mut enc = AesSafe128Encrypt::new();
            let mut dec = AesSafe128Decrypt::new();
            run_test128(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesSafe192() {
        for tests192.iter().advance() |t| {
            let mut enc = AesSafe192Encrypt::new();
            let mut dec = AesSafe192Decrypt::new();
            run_test192(&mut enc, &mut dec, t);
        }
    }

    #[test]
    fn testAesSafe256() {
        for tests256.iter().advance() |t| {
            let mut enc = AesSafe256Encrypt::new();
            let mut dec = AesSafe256Decrypt::new();
            run_test256(&mut enc, &mut dec, t);
        }
    }
}
