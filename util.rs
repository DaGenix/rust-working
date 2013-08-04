// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cast::transmute;
use std::num::Zero;
use std::ops::BitOr;
use std::uint;

/*

pub fn vec_to_array64<'s>(input: &'s [u8]) -> &'s [u8, ..8] {
    if(input.len() != 8) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..8] = transmute(input.unsafe_ref(0));
        return tmp;
    }
}

pub fn vec_to_array128<'s>(input: &'s [u8]) -> &'s [u8, ..16] {
    if(input.len() != 16) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..16] = transmute(input.unsafe_ref(0));
        return tmp;
    }
}

pub fn vec_to_array192<'s>(input: &'s [u8]) -> &'s [u8, ..24] {
    if(input.len() != 24) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..24] = transmute(input.unsafe_ref(0));
        return tmp;
    }
}

pub fn vec_to_array256<'s>(input: &'s [u8]) -> &'s [u8, ..32] {
    if(input.len() != 32) {
        fail!();
    }
    unsafe {
        let tmp: &[u8, ..32] = transmute(input.unsafe_ref(0));
        return tmp;
    }
}
*/

/*

// ConstantTimeCompare returns 1 iff the two equal length slices, x
// and y, have equal contents. The time taken is a function of the length of
// the slices and is independent of the contents.
// Taken from Go's subtle module
fn constant_time_compare(x: &[u8], y: &[u8]) -> int {
    let mut v = 0u8;

    // TODO: use zip iterator?
    // TODO: What if x and y are of differnt lengths?
    for uint::range(0, x.len()) |i| {
        v |= x[i] ^ y[i];
    }

//    return ConstantTimeByteEq(v, 0)
    return 0;
}


// ConstantTimeSelect returns x if v is 1 and y if v is 0.
// Its behavior is undefined if v takes any other value.
fn constant_time_select(v, x, y int) int { return ^(v-1)&x | (v-1)&y }


// ConstantTimeByteEq returns 1 if x == y and 0 otherwise.
func ConstantTimeByteEq(x, y uint8) int {
        z := ^(x ^ y)
        z &= z >> 4
        z &= z >> 2
        z &= z >> 1

        return int(z)
}

// ConstantTimeEq returns 1 if x == y and 0 otherwise.
func ConstantTimeEq(x, y int32) int {
        z := ^(x ^ y)
        z &= z >> 16
        z &= z >> 8
        z &= z >> 4
        z &= z >> 2
        z &= z >> 1

        return int(z & 1)
}

// ConstantTimeCopy copies the contents of y into x iff v == 1. If v == 0, x is left unchanged.
// Its behavior is undefined if v takes any other value.
func ConstantTimeCopy(v int, x, y []byte) {
        xmask := byte(v - 1)
        ymask := byte(^(v - 1))
        for i := 0; i < len(x); i++ {
                x[i] = x[i]&xmask | y[i]&ymask
        }
        return
}
*/


// This should go in either 'sys' or 'os'
#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
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

#[cfg(target_arch = "x86")]
#[cfg(target_arch = "x86_64")]
pub fn supports_aesni() -> bool {
    let (_, _, c, _) = cpuid(1);
    return (c & 0x02000000) != 0;
}
