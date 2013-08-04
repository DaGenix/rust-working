// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


macro_rules! impl_padded_modes(
    (
        $modname:ident,
        $block_size:expr,
        $FixedBuffer:ident,
        $BlockSize:ident,
        $EcbEncryptionWithNoPadding:ident,
        $EcbEncryptionWithPkcs7Padding:ident,
        $CbcEncryptionWithNoPadding:ident,
        $CbcEncryptionWithPkcs7Padding:ident,
        $CtrEncryptionMode:ident,

        $EncryptionBuffer:ident,
        $DecryptionBuffer:ident
    ) =>
    (
        pub mod $modname {
            use std::vec::bytes;

            use cryptoutil::*;
            use symmetriccipher::*;


            pub struct $EcbEncryptionWithNoPadding<A> {
                priv algo: A
            }

            impl <A: BlockEncryptor + $BlockSize> $EcbEncryptionWithNoPadding<A> {
                pub fn new(algo: A) -> $EcbEncryptionWithNoPadding<A> {
                    $EcbEncryptionWithNoPadding {
                        algo: algo
                    }
                }
            }

            impl <A> $BlockSize for $EcbEncryptionWithNoPadding<A>;

            impl <A: BlockEncryptor> PaddedEncryptionMode for $EcbEncryptionWithNoPadding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    self.algo.encrypt_block(input, tmp);
                    handler(tmp);
                }
                fn encrypt_final_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    self.encrypt_block(input, handler);
                }
            }


            pub struct $EcbEncryptionWithPkcs7Padding<A> {
                priv algo: A
            }

            impl <A: BlockEncryptor + $BlockSize> $EcbEncryptionWithPkcs7Padding<A> {
                pub fn new(algo: A) -> $EcbEncryptionWithPkcs7Padding<A> {
                    $EcbEncryptionWithPkcs7Padding {
                        algo: algo
                    }
                }
            }

            impl <A> $BlockSize for $EcbEncryptionWithPkcs7Padding<A>;

            impl <A: BlockEncryptor> PaddedEncryptionMode for $EcbEncryptionWithPkcs7Padding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    self.algo.encrypt_block(input, tmp);
                    handler(tmp);
                }
                fn encrypt_final_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    match input.len() % $block_size {
                        0 => {
                            self.encrypt_block(input, |d: &[u8]| { handler(d); });
                            let buff = [$block_size as u8, ..$block_size];
                            self.encrypt_block(buff, |d: &[u8]| { handler(d); });
                        },
                        _ => {
                            if (input.len() > $block_size) {
                                fail!();
                            }
                            let val = ($block_size - input.len()) as u8;
                            let mut buff = [0u8, ..$block_size];
                            for i in range(0, input.len()) {
                                buff[i] = input[i];
                            }
                            for i in range(input.len(), $block_size) {
                                buff[i] = val;
                            }
                            self.encrypt_block(buff, |d: &[u8]| { handler(d); });
                        }
                    }
                }
            }


            pub struct $CbcEncryptionWithNoPadding<A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size]
            }

            impl <A: BlockEncryptor + $BlockSize> $CbcEncryptionWithNoPadding<A> {
                pub fn new(algo: A, iv: &[u8]) -> $CbcEncryptionWithNoPadding<A> {
                    let mut m = $CbcEncryptionWithNoPadding {
                        algo: algo,
                        last_block: [0u8, ..$block_size]
                    };
                    if (iv.len() != $block_size) {
                        fail!();
                    }
                    // TODO - this would be more efficient, but seems to crash:
                    // bytes::copy_memory(m.last_block, iv, $block_size);
                    for i in range(0, $block_size) {
                        m.last_block[i] = iv[i];
                    }
                    return m;
                }
            }

            impl <A> $BlockSize for $CbcEncryptionWithNoPadding<A>;

            impl <A: BlockEncryptor> PaddedEncryptionMode for $CbcEncryptionWithNoPadding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    for i in range(0, $block_size) {
                        tmp[i] = self.last_block[i] ^ input[i];
                    }
                    self.algo.encrypt_block(tmp, self.last_block);
                    handler(self.last_block);
                }
                fn encrypt_final_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    self.encrypt_block(input, handler);
                }
            }


            pub struct $CbcEncryptionWithPkcs7Padding<A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size]
            }

            impl <A: BlockEncryptor + $BlockSize> $CbcEncryptionWithPkcs7Padding<A> {
                pub fn new(algo: A, iv: &[u8]) -> $CbcEncryptionWithPkcs7Padding<A> {
                    let mut m = $CbcEncryptionWithPkcs7Padding {
                        algo: algo,
                        last_block: [0u8, ..$block_size]
                    };
                    if (iv.len() != $block_size) {
                        fail!();
                    }
                    // TODO - this would be more efficient, but seems to crash:
                    // bytes::copy_memory(m.last_block, iv, $block_size);
                    for i in range(0, $block_size) {
                        m.last_block[i] = iv[i];
                    }
                    return m;
                }
            }

            impl <A> $BlockSize for $CbcEncryptionWithPkcs7Padding<A>;

            impl <A: BlockEncryptor> PaddedEncryptionMode for $CbcEncryptionWithPkcs7Padding<A> {
                fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let mut tmp = [0u8, ..$block_size];
                    for i in range(0, $block_size) {
                        tmp[i] = self.last_block[i] ^ input[i];
                    }
                    self.algo.encrypt_block(tmp, self.last_block);
                    handler(self.last_block);
                }

                fn encrypt_final_block(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    match input.len() % $block_size {
                        0 => {
                            self.encrypt_block(input, |d: &[u8]| { handler(d); });
                            let buff = [$block_size as u8, ..$block_size];
                            self.encrypt_block(buff, |d: &[u8]| { handler(d); });
                        },
                        _ => {
                            if (input.len() > $block_size) {
                                fail!();
                            }
                            let val = ($block_size - input.len()) as u8;
                            let mut buff = [0u8, ..$block_size];
                            for i in range(0, input.len()) {
                                buff[i] = input[i];
                            }
                            for i in range(input.len(), $block_size) {
                                buff[i] = val;
                            }
                            self.encrypt_block(buff, handler);
                        }
                    }
                }
            }


            struct $EncryptionBuffer <M> {
                mode: M,
                buffer: $FixedBuffer
            }

            impl <M: PaddedEncryptionMode + $BlockSize> $EncryptionBuffer<M> {
                fn new(mode: M) -> $EncryptionBuffer<M> {
                    $EncryptionBuffer {
                        mode: mode,
                        buffer: $FixedBuffer::new()
                    }
                }
            }

            impl <M: PaddedEncryptionMode> EncryptionBuffer for $EncryptionBuffer<M> {
                fn encrypt(&mut self, input: &[u8], handler: &fn(&[u8])) {
                    let func = |data: &[u8]| {
                        self.mode.encrypt_block(
                            data,
                            |x: &[u8]| { handler(x); })
                    };
                    self.buffer.input(input, func);
                }

                fn final(&mut self, handler: &fn(&[u8])) {
                    self.mode.encrypt_final_block(self.buffer.current_buffer(), handler);
                }
            }


            struct $CtrEncryptionMode <A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size],
                priv last_block_idx: uint,
                priv ctr: [u8, ..$block_size]
            }

            impl <A: BlockEncryptor> $CtrEncryptionMode<A> {
                pub fn new(algo: A, iv: &[u8]) -> $CtrEncryptionMode<A> {
                    let mut m = $CtrEncryptionMode {
                        algo: algo,
                        last_block: [0u8, ..$block_size],
                        last_block_idx: 0,
                        ctr: [0u8, ..$block_size]
                    };

                    let bs = $block_size;

                    bytes::copy_memory(m.ctr, iv, bs);
                    m.algo.encrypt_block(m.ctr, m.last_block);

                    return m;
                }
            }

            impl <A: BlockEncryptor> StreamEncryptor for $CtrEncryptionMode<A> {
                fn encrypt(&mut self, input: &[u8], out: &mut [u8]) {
                    let mut i = 0;
                    while i < input.len() {
                        if self.last_block_idx == $block_size {
                            // increment the counter
                            for i in range(0, $block_size) {
                                self.ctr[i] += 1;
                                if self.ctr[i] != 0 {
                                    break;
                                }
                            }

                            self.algo.encrypt_block(self.ctr, self.last_block);
                            self.last_block_idx = 0;
                        }
                        out[i] = self.last_block[self.last_block_idx] ^ input[i];
                        self.last_block_idx += 1;
                        i += 1;
                    }
                }
            }
        }
    )
)

impl_padded_modes!(
    padded_16, // mod name
    16, // block size
    FixedBuffer16, // FixedBuffer implementation to use
    BlockSize16, // Block size
    EcbEncryptionWithNoPadding16, // ecb w/ no padding mode name
    EcbEncryptionWithPkcs7Padding16, // ecb w/ pkcs#7 padding mode name
    CbcEncryptionWithNoPadding16, // cbc w/ no padding mode name
    CbcEncryptionWithPkcsPadding16, // cbc w/ no padding mode name
    CtrEncryptionMode16, // ctr mode

    EncryptionBuffer16, // EncryptionBuffer for 128 bit block size
    DecryptionBuffer16 // EncryptionBuffer for 128 bit block size
)

#[cfg(test)]
mod tests {
    use aes::*;
    use blockmodes::padded_16::*;
    use symmetriccipher::*;

    // Test vectors from:
    // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

    #[test]
    fn test_ctr_128() {
        let key: [u8, ..16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let iv: [u8, ..16] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff];
        let plain: [u8, ..16] = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];
        let cipher: [u8, ..16] = [0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce];

        let mut a = Aes128Encryptor::new();
        a.set_key(key);
        let mut m = CtrEncryptionMode16::new(a, iv);
        let mut tmp = [0u8, ..16];
        m.encrypt(plain, tmp);
        assert!(tmp == cipher);
    }
}
