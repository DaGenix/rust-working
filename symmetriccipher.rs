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

pub use blockmodes::*;

/*
pub trait SymmetricCipher128
pub trait SymmetricCipher192
pub trait SymmetricCipher256

pub trait BlockEncryptor128
pub trait BlockDecryptor128

pub trait PaddedEncryptionMode128
pub trait PaddedDecryptionMode128
struct EcbEncryptionWithNoPadding128
struct EcbEncryptionWithCtsPadding128
struct EcbEncryptionWithPkcs7Padding128
struct CbcEncryptionWithNoPadding128
struct CbcEncryptionWithCtsPadding128
struct CbcEncryptionWithPkcs7Padding128

pub trait EncryptionBuffer
pub trait DecryptionBuffer
struct PaddedEncryptionBuffer128
struct PaddedDecryptionBuffer128
struct StreamEncryptionBuffer
struct StreamDecryptionBuffer

pub trait StreamEncryptor
pub trait StreamDecryptor
struct CtrMode
struct CtsMode
struct CfbMode
struct OfbMode

*/

pub trait BlockSize16 { }

/// Trait for a Symmetric Cipher algorithm
pub trait SymmetricCipher {
    fn set_key(&mut self, key: &[u8]);
//    fn key_size(&self) -> uint;
}

/// Trait for a Cipher that can encrypt a block of data
pub trait BlockEncryptor {
    fn encrypt_block(&self, input: &[u8], output: &mut [u8]);
//    fn block_size(&self) -> uint;
}

/// Trait for a Cipher that can decrypt a block of data
pub trait BlockDecryptor {
    fn decrypt_block(&self, input: &[u8], output: &mut [u8]);
//    fn block_size(&self) -> uint;
}

/// Trait for a block cipher mode of operation that requires padding the end of the stream
pub trait PaddedEncryptionMode {
    fn encrypt_block(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn encrypt_final_block(&mut self, input: &[u8], handler: &fn(&[u8]));
}

/// Trait for a block cipher mode of operation that requires padding the end of the stream
pub trait PaddedDecryptionMode {
    fn decrypt_block(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn decrypt_final_block(&mut self, input: &[u8], handler: &fn(&[u8]));
}

/// Trait for an object that buffers data to encrypt until there is a full block
pub trait EncryptionBuffer {
    fn encrypt(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}

/// Trait for an object that buffers data to decrypt until there is a full block
pub trait DecryptionBuffer {
    fn decrypt(&mut self, input: &[u8], handler: &fn(&[u8]));
    fn final(&mut self, handler: &fn(&[u8]));
}

/// Trait for an encryptor that can operate on byte streams
pub trait StreamEncryptor {
    fn encrypt(&mut self, input: &[u8], out: &mut [u8]);
}

/// Trait for a decryptor that can operate on byte streams
pub trait StreamDecryptor {
    fn decrypt(&mut self, input: &[u8], out: &mut [u8]);
}
