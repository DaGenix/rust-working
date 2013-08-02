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
        $cast_to:ident,
        $FixedBuffer:ident,
        $BlockEncryptor:ident,
        $BlockDecryptor:ident,
        $PaddedEncryptionMode:ident,
        $PaddedDecryptionMode:ident,
        $EcbEncryptionWithNoPadding:ident,
        $EcbEncryptionWithPkcs7Padding:ident,
        $CbcEncryptionWithNoPadding:ident,
        $CbcEncryptionWithPkcs7Padding:ident,

        $EncryptionBuffer:ident
        $DecryptionBuffer:ident
    ) =>
    (
        mod $modname {
            use std::uint;

            use cryptoutil::*;
            use symmetriccipher::*;
            use util::*;


            pub struct $EcbEncryptionWithNoPadding<A> {
                priv algo: A
            }

            impl <A: $BlockEncryptor> $EcbEncryptionWithNoPadding<A> {
                pub fn new(algo: A) -> $EcbEncryptionWithNoPadding<A> {
                    $EcbEncryptionWithNoPadding {
                        algo: algo
                    }
                }
            }

            impl <A: $BlockEncryptor> $PaddedEncryptionMode for $EcbEncryptionWithNoPadding<A> {
                fn encrypt_block(&mut self, in: &[u8, ..$block_size], handler: &fn(&[u8])) {
                    let tmp = self.algo.encrypt_block(in);
                    handler(tmp);
                }
                fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
                    // TODO - check length?
                    self.encrypt_block($cast_to(in), handler);
                }
            }


            pub struct $EcbEncryptionWithPkcs7Padding<A> {
                priv algo: A
            }

            impl <A: $BlockEncryptor> $EcbEncryptionWithPkcs7Padding<A> {
                pub fn new(algo: A) -> $EcbEncryptionWithPkcs7Padding<A> {
                    $EcbEncryptionWithPkcs7Padding {
                        algo: algo
                    }
                }
            }

            impl <A: $BlockEncryptor> $PaddedEncryptionMode for $EcbEncryptionWithPkcs7Padding<A> {
                fn encrypt_block(&mut self, in: &[u8, ..$block_size], handler: &fn(&[u8])) {
                    let tmp = self.algo.encrypt_block(in);
                    handler(tmp);
                }
                fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
                    match in.len() % $block_size {
                        0 => {
                            self.encrypt_block($cast_to(in), |d: &[u8]| { handler(d); });
                            let buff = [$block_size as u8, ..$block_size];
                            self.encrypt_block(&buff, |d: &[u8]| { handler(d); });
                        },
                        _ => {
                            if (in.len() > $block_size) {
                                fail!();
                            }
                            let val = ($block_size - in.len()) as u8;
                            let mut buff = [0u8, ..$block_size];
                            for uint::range(0, in.len()) |i| {
                                buff[i] = in[i];
                            }
                            for uint::range(in.len(), $block_size) |i| {
                                buff[i] = val;
                            }
                            self.encrypt_block(&buff, |d: &[u8]| { handler(d); });
                        }
                    }
                }
            }


            pub struct $CbcEncryptionWithNoPadding<A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size]
            }

            impl <A: $BlockEncryptor> $CbcEncryptionWithNoPadding<A> {
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
                    for uint::range(0, $block_size) |i| {
                        m.last_block[i] = iv[i];
                    }
                    return m;
                }
            }

            impl <A: $BlockEncryptor> $PaddedEncryptionMode for $CbcEncryptionWithNoPadding<A> {
                fn encrypt_block(&mut self, in: &[u8, ..$block_size], handler: &fn(&[u8])) {
                    for uint::range(0, $block_size) |i| {
                        self.last_block[i] ^ in[i];
                    }
                    self.last_block = self.algo.encrypt_block(&self.last_block);
                    handler(self.last_block);
                }
                fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
                    self.encrypt_block($cast_to(in), handler);
                }
            }


            pub struct $CbcEncryptionWithPkcs7Padding<A> {
                priv algo: A,
                priv last_block: [u8, ..$block_size]
            }

            impl <A: $BlockEncryptor> $CbcEncryptionWithPkcs7Padding<A> {
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
                    for uint::range(0, $block_size) |i| {
                        m.last_block[i] = iv[i];
                    }
                    return m;
                }
            }

            impl <A: $BlockEncryptor> $PaddedEncryptionMode for $CbcEncryptionWithPkcs7Padding<A> {
                fn encrypt_block(&mut self, in: &[u8, ..$block_size], handler: &fn(&[u8])) {
                    for uint::range(0, $block_size) |i| {
                        self.last_block[i] ^ in[i];
                    }
                    self.last_block = self.algo.encrypt_block(&self.last_block);
                    handler(self.last_block);
                }
                fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
                    self.encrypt_block($cast_to(in), handler);
                }

                fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
                    match in.len() % $block_size {
                        0 => {
                            self.encrypt_block($cast_to(in), |d: &[u8]| { handler(d); });
                            let buff = [$block_size as u8, ..$block_size];
                            self.encrypt_block(&buff, |d: &[u8]| { handler(d); });
                        },
                        _ => {
                            if (in.len() > $block_size) {
                                fail!();
                            }
                            let val = ($block_size - in.len()) as u8;
                            let mut buff = [0u8, ..$block_size];
                            for uint::range(0, in.len()) |i| {
                                buff[i] = in[i];
                            }
                            for uint::range(in.len(), $block_size) |i| {
                                buff[i] = val;
                            }
                            let tmp = self.encrypt_block(&buff, handler);
                        }
                    }
                }
            }


            struct $EncryptionBuffer <M> {
                mode: M,
                buffer: $FixedBuffer
            }

            impl <M: $PaddedEncryptionMode> $EncryptionBuffer<M> {
                fn new(mode: M) -> $EncryptionBuffer<M> {
                    $EncryptionBuffer {
                        mode: mode,
                        buffer: $FixedBuffer::new()
                    }
                }
            }

            impl <M: $PaddedEncryptionMode> EncryptionBuffer for $EncryptionBuffer<M> {
                fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8])) {
                    let func = |data: &[u8]| {
                        self.mode.encrypt_block(
                            $cast_to(data),
                            |x: &[u8]| { handler(x); })
                    };
                    self.buffer.input(in, func);
                }

                fn final(&mut self, handler: &fn(&[u8])) {
                    self.mode.encrypt_final_block(self.buffer.current_buffer(), handler);
                }
            }
        }
    )
)

impl_padded_modes!(
    padded_128, // mod name
    16, // block size
    vec_to_array128, // function to convert a vector to a fixed length vector
    FixedBuffer16, // FixedBuffer implementation to use
    BlockEncryptor128, // name of the block encryption trait to use
    BlockDecryptor128, // name of the block decryption trait to use
    PaddedEncryptionMode128, // name of the padded encryption trait to use
    PaddedDecryptionMode128, // name of the padded decryption trait to use
    EcbEncryptionWithNoPadding128, // ecb w/ no padding mode name
    EcbEncryptionWithPkcs7Padding128, // ecb w/ pkcs#7 padding mode name
    CbcEncryptionWithNoPadding128, // cbc w/ no padding mode name
    CbcEncryptionWithPkcsPadding128, // cbc w/ no padding mode name

    EncryptionBuffer128 // EncryptionBuffer for 128 bit block size
    DecryptionBuffer128 // EncryptionBuffer for 128 bit block size
)
