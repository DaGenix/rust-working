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

/*

encrypts a single block of data at a time
* trait SymmetricBlockEncryptionAlgorithm
* trait SymmetricBlockDecryptionAlgorithm
* struct Aes
* struct Des
* struct ...

wraps an algorith
encrypts a single block at a time
NoPadding versions fail!() if the final block is partial
- encrypt_block() may return nothing
- encrypt_final() encrypts a partial block, may return 2*blocksize
* trait SymmetricBlockEncryptionPadding
* trait SymmetricBlockDecryptionPadding
* struct EcbModeWithNoPadding
* struct EcbModeWithCtsPadding
* struct EcbModeWithPkcs7Padding
* struct CbcModeWithNoPadding
* struct CbcModeWithCtsPadding
* struct CbcModeWithPkcs7Padding

wraps a padding
encrypts an input of arbitrary length and passes encrypted
data to a supplied closure as appropriate
* struct BufferedSymmetricEncryptor
* struct BufferedSymmetricDecryptor

encrypts an input of arbitrary length to an output
of the same size
* SymmetricStreamEncryptor
* SymmetricStreamDecryptor
* struct CtrMode
* struct CtsMode
* struct CfbMode
* struct OfbMode

*/

pub trait SymmetricBlockEncryptionPadding {
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

impl <A: SymmetricBlockEncryptor> SymmetricBlockEncryptionPadding for EcbEncryptionWithNoPadding<A> {
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

// struct EcbEncryptionWithCtsPadding<A> {
//     algo: A
// }
//
// struct EcbEncryptionWithPkcs7Padding<A> {
//     algo: A
// }

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

impl <A: SymmetricBlockEncryptor> SymmetricBlockEncryptionPadding for CbcEncryptionWithNoPadding<A> {
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

// struct CbcEncryptionWithCtsPadding<A> {
//     algo: A
// }
//
// struct CbcEncryptionWithPkcs7Padding<A> {
//     algo: A
// }


pub trait BufferedSymmetricEncryptor {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}


struct PaddedEncryptionBuffer <P> {
    padding: P,
    buff: [u8, ..16],
    buff_idx: uint,
    out: [u8, ..32]
}

impl <P: SymmetricBlockEncryptionPadding> PaddedEncryptionBuffer<P> {
    fn new(padding: P) -> PaddedEncryptionBuffer<P> {
        PaddedEncryptionBuffer {
            padding: padding,
            buff: [0u8, ..16],
            buff_idx: 0,
            out: [0u8, ..32]
        }
    }
}

impl <P: SymmetricBlockEncryptionPadding> BufferedSymmetricEncryptor for PaddedEncryptionBuffer<P> {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8])) {
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
            let l = self.padding.encrypt_block(self.buff, self.out);
            handler(self.out.slice(0, l));
        }

        while in.len() - i > 16 {
            let l = self.padding.encrypt_block(in.slice(i, i + 16), self.out);
            handler(self.out.slice(0, l));
        }

        while i < in.len() {
            self.buff[self.buff_idx] = in[i];
            self.buff_idx += 1;
        }
    }

    fn final(&mut self, handler: &fn(&[u8])) {
        let l = self.padding.encrypt_final_block(self.buff.slice(0, self.buff_idx), self.out);
        handler(self.out.slice(0, l));
    }
}









/*
impl <M: SymmetricBlockEncryptionMode> EncryptionPadding for Pkcs7EncryptionPadding<M> {
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
