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

// Traits for modes - ECB, CBC, & PCBC. Other modes don't require this: CFB, OFB, or CTR Mode
// Depending on the mode, you may need to process data in full blocks
pub trait SymmetricBlockEncryptionMode {
    fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]);
}

struct EcbMode<A> {
    algo: A
}

impl <A: SymmetricBlockEncryptor> EcbMode<A> {
    fn new(algo: A) -> EcbMode<A> {
        EcbMode {
            algo: algo
        }
    }
}

impl <A: SymmetricBlockEncryptor> SymmetricBlockEncryptionMode for EcbMode<A> {
    fn encrypt_block(&mut self, in: &[u8], out: &mut[u8]) {
        let mut buff = [0u8, ..16];
        self.algo.encrypt_block(in, out);
    }
}

struct CbcModeBlocksize16<A> {
    algo: A,
    last_block: [u8, ..16]
}

impl <A: SymmetricBlockEncryptor> CbcModeBlocksize16<A> {
    pub fn new(algo: A, iv: &[u8]) -> CbcModeBlocksize16<A> {
        let mut m = CbcModeBlocksize16 {
            algo: algo,
            last_block: [0u8, ..16]
        };
        bytes::copy_memory(m.last_block, iv, 16);
        return m;
    }
}

impl <A: SymmetricBlockEncryptor> SymmetricBlockEncryptionMode for CbcModeBlocksize16<A> {
    fn encrypt_block(&mut self, in: &[u8], out: &mut [u8]) {
        for uint::range(0, 16) |i| {
            self.last_block[i] ^ in[i];
        }
        self.algo.encrypt_block(self.last_block, out);
        bytes::copy_memory(self.last_block, out, 16);
    }
}

trait EncryptionPadding {
    fn encrypt_block(&mut self, in: &[u8], handler: &fn(&[u8]));
    fn encrypt_final(&mut self, in: &[u8], handler: &fn(&[u8]));
}

struct Pkcs7EncryptionPadding <M> {
    mode: M
}

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





struct CfbMode<A> {
    algo: A
}

struct OfbMode<A> {
    algo: A
}

struct CtrMode<A> {
    algo: A
}

// Traits for working with a stream of data - may buffer data
// if less than a full block is available, depending on the
// mode being used.
pub trait SymmetricStreamEncryptor {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8]));
}

pub trait SymmetricStreamDecryptor {

}
