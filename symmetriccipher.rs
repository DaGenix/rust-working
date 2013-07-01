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
use std::vec::bytes;

// Traits for algorithms that can function on a single
// block at a time.
pub trait SymmetricBlockEncryptor {
    fn init(&mut self, key: &[u8]);
    fn encrypt_block(&mut self, in: &[u8], out: &mut [u8]);
    fn key_size(&self) -> uint;
    fn block_size(&self) -> uint;
}
pub trait SymmetricBlockDecryptor {
    fn init(&mut self, key: &[u8]);
    fn decrypt_block(&mut self, in: &[u8], out: &mut [u8]);
    fn key_size(&self) -> uint;
    fn block_size(&self) -> uint;
}

trait Test {
    fn encrypt(&mut self, in: &[u8]) -> [u8, ..16];
}



trait Blocksize8 { }
trait Blocksize16 { }
trait Blocksize32 { }

/*

encrypts a single block of data at a time
* trait SymmetricBlockEncryptor
* trait SymmetricBlockDecryptor
* struct Aes
* struct Des
* struct ...

wraps an algorith
encrypts a single block at a time
NoPadding versions fail!() if the final block is partial
- encrypt_block() may return nothing
- encrypt_final_block() encrypts a partial block, may return 2*blocksize
* trait SymmetricPaddedEncryptionMode
* trait SymmetricPaddedDecryptionMode
* struct EcbModeWithNoPadding
* struct EcbModeWithCtsPadding
* struct EcbModeWithPkcs7Padding
* struct CbcModeWithNoPadding
* struct CbcModeWithCtsPadding
* struct CbcModeWithPkcs7Padding

wraps a padding
encrypts an input of arbitrary length and passes encrypted
data to a supplied closure as appropriate
* struct SymmetricEncryptionFilter
* struct SymmetricDecryptionFilter

encrypts an input of arbitrary length to an output
of the same size
* SymmetricStreamEncryptor
* SymmetricStreamDecryptor
* struct CtrMode
* struct CtsMode
* struct CfbMode
* struct OfbMode

*/

pub trait SymmetricPaddedEncryptionMode {
    priv fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]) -> uint;
    priv fn encrypt_final_block(&mut self, in: &[u8], out: &mut[u8]) -> uint;
}

struct EcbEncryptionWithNoPadding<A> {
    algo: A
}

impl <A: SymmetricBlockEncryptor> EcbEncryptionWithNoPadding<A> {
    pub fn new(algo: A) -> EcbEncryptionWithNoPadding<A> {
        EcbEncryptionWithNoPadding {
            algo: algo
        }
    }
}

impl <A: SymmetricBlockEncryptor> SymmetricPaddedEncryptionMode for EcbEncryptionWithNoPadding<A> {
    fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        self.algo.encrypt_block(in, out);
        return 16;
    }
    fn encrypt_final_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        if(in.len() != self.algo.block_size()) {
            fail!();
        }
        self.algo.encrypt_block(in, out);
        return 16;
    }
}

struct EcbEncryptionWithPkcs7Padding<A> {
    algo: A
}

impl <A: SymmetricBlockEncryptor> EcbEncryptionWithPkcs7Padding<A> {
    pub fn new(algo: A) -> EcbEncryptionWithPkcs7Padding<A> {
        EcbEncryptionWithPkcs7Padding {
            algo: algo
        }
    }
}

impl <A: SymmetricBlockEncryptor> SymmetricPaddedEncryptionMode for EcbEncryptionWithPkcs7Padding<A> {
    fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        self.algo.encrypt_block(in, out);
        return 16;
    }
    fn encrypt_final_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        match in.len() % 16 {
            0 => {
                self.algo.encrypt_block(in, out.mut_slice(0, 16));
                let buff = [16u8, ..16];
                self.algo.encrypt_block(buff, out.mut_slice(16, 32));
                return 32;
            },
            _ => {
                // TODO - prevent overlfow?
                let val = (16 - in.len()) as u8;
                let mut buff = [0u8, ..16];
                for uint::range(0, in.len()) |i| {
                    buff[i] = in[i];
                }
                for uint::range(in.len(), 16) |i| {
                    buff[i] = val;
                }
                self.algo.encrypt_block(buff, out);
                return 16;
            }
        }
    }
}

// struct EcbEncryptionWithCtsPadding<A> {
//     algo: A
// }
//


struct CbcEncryptionWithNoPadding<A> {
    algo: A,
    last_block: [u8, ..16]
}

impl <A: SymmetricBlockEncryptor> CbcEncryptionWithNoPadding<A> {
    pub fn new(algo: A, iv: &[u8]) -> CbcEncryptionWithNoPadding<A> {
        let mut m = CbcEncryptionWithNoPadding {
            algo: algo,
            last_block: [0u8, ..16]
        };
        bytes::copy_memory(m.last_block, iv, 16);
        return m;
    }
}

// fn cbc_encrypt_block<A: SymmetricBlockEncryptor>(
//         algo: &mut A,
//         uint: block_size,
//         in: &[u8],
//         last_block: &mut [u8],
//         out: &mut [u8]) {
//     for uint::range(0, block_size) |i| {
//         last_block[i] ^ in[i];
//     }
//     algo.encrypt_block(last_block, out);
//     bytes::copy_memory(last_block, out, block_size);
//     return block_size;
// }

impl <A: SymmetricBlockEncryptor> SymmetricPaddedEncryptionMode for CbcEncryptionWithNoPadding<A> {
    fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        for uint::range(0, 16) |i| {
            self.last_block[i] ^ in[i];
        }
        self.algo.encrypt_block(self.last_block, out);
        bytes::copy_memory(self.last_block, out, 16);
        return 16;
    }
    fn encrypt_final_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        if(in.len() != self.algo.block_size()) {
            fail!();
        }
        self.encrypt_block(in, out);
        return 16;
    }
}


struct CbcEncryptionWithPkcs7Padding<A> {
    algo: A,
    last_block: [u8, ..16]
}

impl <A: SymmetricBlockEncryptor> CbcEncryptionWithPkcs7Padding<A> {
    pub fn new(algo: A, iv: &[u8]) -> CbcEncryptionWithPkcs7Padding<A> {
        let mut m = CbcEncryptionWithPkcs7Padding {
            algo: algo,
            last_block: [0u8, ..16]
        };
        bytes::copy_memory(m.last_block, iv, 16);
        return m;
    }
}

impl <A: SymmetricBlockEncryptor> SymmetricPaddedEncryptionMode for CbcEncryptionWithPkcs7Padding<A> {
    fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        for uint::range(0, 16) |i| {
            self.last_block[i] ^ in[i];
        }
        self.algo.encrypt_block(self.last_block, out);
        bytes::copy_memory(self.last_block, out, 16);
        return 16;
    }
    fn encrypt_final_block(&mut self, in: &[u8], out: &mut[u8]) -> uint {
        match in.len() % 16 {
            0 => {
                self.encrypt_block(in, out.mut_slice(0, 16));
                let buff = [16u8, ..16];
                self.encrypt_block(buff, out.mut_slice(16, 32));
                return 32;
            },
            _ => {
                // TODO - prevent overlfow?
                let val = (16 - in.len()) as u8;
                let mut buff = [0u8, ..16];
                for uint::range(0, in.len()) |i| {
                    buff[i] = in[i];
                }
                for uint::range(in.len(), 16) |i| {
                    buff[i] = val;
                }
                self.encrypt_block(buff, out);
                return 16;
            }
        }
    }
}


// struct CbcEncryptionWithCtsPadding<A> {
//     algo: A
// }
//


pub trait SymmetricEncryptionFilter {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}


struct PaddedSymmetricEncryptionFilter <P> {
    padding: P,
    buff: [u8, ..16],
    buff_idx: uint
}

impl <P: SymmetricPaddedEncryptionMode> PaddedSymmetricEncryptionFilter<P> {
    fn new(padding: P) -> PaddedSymmetricEncryptionFilter<P> {
        PaddedSymmetricEncryptionFilter {
            padding: padding,
            buff: [0u8, ..16],
            buff_idx: 0
        }
    }
}

impl <P: SymmetricPaddedEncryptionMode> SymmetricEncryptionFilter for PaddedSymmetricEncryptionFilter<P> {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8])) {
        let mut out = [0u8, ..16];

        let mut i = 0;
        while self.buff_idx != 0 && i < in.len() {
            self.buff[self.buff_idx] = in[i];
            self.buff_idx += 1;
            if (self.buff_idx == 16) {
                self.buff_idx = 0;
            }
            i += 1;
        }

        if (self.buff_idx == 0) {
            let l = self.padding.encrypt_block(self.buff, out);
            handler(out.slice(0, l));
        }

        while in.len() - i > 16 {
            let l = self.padding.encrypt_block(in.slice(i, i + 16), out);
            handler(out.slice(0, l));
        }

        while i < in.len() {
            self.buff[self.buff_idx] = in[i];
            self.buff_idx += 1;
        }
    }

    fn final(&mut self, handler: &fn(&[u8])) {
        let mut out = [0u8, ..32];
        let l = self.padding.encrypt_final_block(self.buff.slice(0, self.buff_idx), out);
        handler(out.slice(0, l));
    }
}









/*
impl <M: > EncryptionPadding for Pkcs7EncryptionPadding<M> {
    fn encrypt_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
        let mut buff = [0u8, ..16];
        self.mode.encrypt_block(in, buff);
        handler(buff);
    }

    fn encrypt_final(&mut self, in: &[u8], handler: &fn(&[u8])) {
        let mut buff = [0u8, ..16];
        match in.len() % 16 {
            0 => {
                self.mode.encrypt_block(in, buff);
                handler(buff);
                for uint::range(0, 16) |i| {
                    buff[i] = 16;
                }
                self.mode.encrypt_block(in, buff);
                handler(buff);
            },
            _ => {
                // TODO - prevent overlfow?
                let val = (16 - in.len()) as u8;
                for uint::range(in.len(), 16) |i| {
                    buff[i] = val;
                }
                self.mode.encrypt_block(in, buff);
                handler(buff);
            }
        }
    }
}

struct CtsEncryptionPadding <M> {
    mode: M
}

trait BufferedBlockEncryption {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8]));
    fn encrypt_final(handler: &fn(&[u8]));
}
*/




// struct CfbMode<A> {
//     algo: A
// }
//
// struct OfbMode<A> {
//     algo: A
// }
//
// struct CtrMode<A> {
//     algo: A
// }

// Traits for working with a stream of data - may buffer data
// if less than a full block is available, depending on the
// mode being used.
// pub trait SymmetricStreamEncryptor {
//     fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8]));
// }
//
// pub trait SymmetricStreamDecryptor {
//
// }
