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
use std::cast::transmute;
use std::vec::bytes;


pub trait SymmetricKeyedCipher128 {
    fn init(&mut self, key: &[u8, ..16]);
}

pub trait SymmetricKeyedCipher192 {
    fn init(&mut self, key: &[u8, ..24]);
}

pub trait SymmetricKeyedCipher256 {
    fn init(&mut self, key: &[u8, ..32]);
}

pub trait SymmetricBlockEncryptor128 {
    fn encrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16];
}

pub trait SymmetricBlockDecryptor128 {
    fn decrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16];
}


pub fn vec_to_array128(in: &[u8]) -> &[u8, ..16] {
    if(in.len() != 16) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..16] = transmute(in.unsafe_ref(0));
        return tmp;
    }
}






// Traits for algorithms that can function on a single
// block at a time.
/*
pub trait SymmetricBlockEncryptor16 {
    fn encrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16];
}
pub trait SymmetricBlockDecryptor16 {
    fn decrypt_block(&mut self, in: &[u8, ..16]) -> [u8, ..16];
}

pub fn cast_to_16(in: &[u8]) -> &[u8, ..16] {
    if(in.len() != 16) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..16] = transmute(in.unsafe_ref(0));
        return tmp;
    }
}
*/

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


/*
pub trait SymmetricPaddedEncryptionMode16 {
    priv fn encrypt_block(&mut self, in: &[u8, ..16], handler: &fn(&[u8]));
    priv fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8]));
}

struct EcbEncryptionWithNoPadding<A> {
    algo: A
}

impl <A: SymmetricBlockEncryptor16> EcbEncryptionWithNoPadding<A> {
    pub fn new(algo: A) -> EcbEncryptionWithNoPadding<A> {
        EcbEncryptionWithNoPadding {
            algo: algo
        }
    }
}

impl <A: SymmetricBlockEncryptor16> SymmetricPaddedEncryptionMode16 for EcbEncryptionWithNoPadding<A> {
    fn encrypt_block(&mut self, in: &[u8, ..16], handler: &fn(&[u8])) {
        let tmp = self.algo.encrypt_block(in);
        handler(tmp);
    }
    fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
        self.encrypt_block(cast_to_16(in), handler);
    }
}


struct EcbEncryptionWithPkcs7Padding<A> {
    algo: A
}

impl <A: SymmetricBlockEncryptor16> EcbEncryptionWithPkcs7Padding<A> {
    pub fn new(algo: A) -> EcbEncryptionWithPkcs7Padding<A> {
        EcbEncryptionWithPkcs7Padding {
            algo: algo
        }
    }
}

impl <A: SymmetricBlockEncryptor16> SymmetricPaddedEncryptionMode16 for EcbEncryptionWithPkcs7Padding<A> {
    fn encrypt_block(&mut self, in: &[u8, ..16], handler: &fn(&[u8])) {
        let tmp = self.algo.encrypt_block(in);
        handler(tmp);
    }
    fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
        match in.len() % 16 {
            0 => {
                let tmp = self.algo.encrypt_block(cast_to_16(in));
                handler(tmp);
                let buff = [16u8, ..16];
                let tmp = self.algo.encrypt_block(&buff);
                handler(tmp);
            },
            _ => {
                if (in.len() > 16) {
                    fail!();
                }
                let val = (16 - in.len()) as u8;
                let mut buff = [0u8, ..16];
                for uint::range(0, in.len()) |i| {
                    buff[i] = in[i];
                }
                for uint::range(in.len(), 16) |i| {
                    buff[i] = val;
                }
                let tmp = self.algo.encrypt_block(&buff);
                handler(tmp);
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

impl <A: SymmetricBlockEncryptor16> CbcEncryptionWithNoPadding<A> {
    pub fn new(algo: A, iv: &[u8]) -> CbcEncryptionWithNoPadding<A> {
        let mut m = CbcEncryptionWithNoPadding {
            algo: algo,
            last_block: [0u8, ..16]
        };
        if (iv.len() != 16) {
            fail!();
        }
        bytes::copy_memory(m.last_block, iv, 16);
        return m;
    }
}

impl <A: SymmetricBlockEncryptor16> SymmetricPaddedEncryptionMode16 for CbcEncryptionWithNoPadding<A> {
    fn encrypt_block(&mut self, in: &[u8, ..16], handler: &fn(&[u8])) {
        for uint::range(0, 16) |i| {
            self.last_block[i] ^ in[i];
        }
        self.last_block = self.algo.encrypt_block(&self.last_block);
        handler(self.last_block);
    }
    fn encrypt_final_block(&mut self, in: &[u8], handler: &fn(&[u8])) {
        self.encrypt_block(cast_to_16(in), handler);
    }
}
*/

/*

struct CbcEncryptionWithPkcs7Padding<A> {
    algo: A,
    last_block: [u8, ..16]
}

impl <A: SymmetricBlockEncryptor16> CbcEncryptionWithPkcs7Padding<A> {
    pub fn new(algo: A, iv: &[u8]) -> CbcEncryptionWithPkcs7Padding<A> {
        let mut m = CbcEncryptionWithPkcs7Padding {
            algo: algo,
            last_block: [0u8, ..16]
        };
        bytes::copy_memory(m.last_block, iv, 16);
        return m;
    }
}

impl <A: SymmetricBlockEncryptor16> SymmetricPaddedEncryptionMode for CbcEncryptionWithPkcs7Padding<A> {
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

*/

// struct CbcEncryptionWithCtsPadding<A> {
//     algo: A
// }
//

/*
pub trait SymmetricEncryptionFilter {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}


struct PaddedSymmetricEncryptionFilter16 <P> {
    padding: P,
    buff: [u8, ..16],
    buff_idx: uint
}

impl <P: SymmetricPaddedEncryptionMode16> PaddedSymmetricEncryptionFilter16<P> {
    fn new(padding: P) -> PaddedSymmetricEncryptionFilter16<P> {
        PaddedSymmetricEncryptionFilter16 {
            padding: padding,
            buff: [0u8, ..16],
            buff_idx: 0
        }
    }
}

impl <P: SymmetricPaddedEncryptionMode16> SymmetricEncryptionFilter for PaddedSymmetricEncryptionFilter16<P> {
    fn encrypt(&mut self, in: &[u8], handler: &fn(&[u8])) {
        // TODO - I don't think any of this code is right
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
            self.padding.encrypt_block(&self.buff, |x: &[u8]| { handler(x); });
        }

        while in.len() - i > 16 {
            self.padding.encrypt_block(cast_to_16(in.slice(i, i + 16)), |x: &[u8]| { handler(x); });
        }

        while i < in.len() {
            self.buff[self.buff_idx] = in[i];
            self.buff_idx += 1;
        }
    }

    fn final(&mut self, handler: &fn(&[u8])) {
        self.padding.encrypt_final_block(self.buff.slice(0, self.buff_idx), handler);
    }
}

*/





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
