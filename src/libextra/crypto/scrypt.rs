// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::vec;
use std::vec::MutableCloneableVector;

use cryptoutil::{read_u32v_le, write_u32_le};
use hmac::Hmac;
use mac::Mac;
use pbkdf2::pbkdf2;
use sha2::Sha256;


// Perform a number of rounds of the salsa20 core function.
fn salsa20_x(output: &mut [u8], input: &[u8], rounds: uint) {
    fn rot(a: u32, b: uint) -> u32 {
        return (a << b) | (a >> (32 - b));
    }

    assert!(rounds % 2 == 0);

    let mut x = [0u32, ..16];
    let mut y = [0u32, ..16];

    read_u32v_le(x, input);
    y.copy_from(x);

    do (rounds / 2).times() {
        x[0x4] ^= rot(x[0x0] + x[0xc], 7);
        x[0x8] ^= rot(x[0x4] + x[0x0], 9);
        x[0xc] ^= rot(x[0x8] + x[0x4], 13);
        x[0x0] ^= rot(x[0xc] + x[0x8], 18);
        x[0x9] ^= rot(x[0x5] + x[0x1], 7);
        x[0xd] ^= rot(x[0x9] + x[0x5], 9);
        x[0x1] ^= rot(x[0xd] + x[0x9], 13);
        x[0x5] ^= rot(x[0x1] + x[0xd], 18);
        x[0xe] ^= rot(x[0xa] + x[0x6], 7);
        x[0x2] ^= rot(x[0xe] + x[0xa], 9);
        x[0x6] ^= rot(x[0x2] + x[0xe], 13);
        x[0xa] ^= rot(x[0x6] + x[0x2], 18);
        x[0x3] ^= rot(x[0xf] + x[0xb], 7);
        x[0x7] ^= rot(x[0x3] + x[0xf], 9);
        x[0xb] ^= rot(x[0x7] + x[0x3], 13);
        x[0xf] ^= rot(x[0xb] + x[0x7], 18);
        x[0x1] ^= rot(x[0x0] + x[0x3], 7);
        x[0x2] ^= rot(x[0x1] + x[0x0], 9);
        x[0x3] ^= rot(x[0x2] + x[0x1], 13);
        x[0x0] ^= rot(x[0x3] + x[0x2], 18);
        x[0x6] ^= rot(x[0x5] + x[0x4], 7);
        x[0x7] ^= rot(x[0x6] + x[0x5], 9);
        x[0x4] ^= rot(x[0x7] + x[0x6], 13);
        x[0x5] ^= rot(x[0x4] + x[0x7], 18);
        x[0xb] ^= rot(x[0xa] + x[0x9], 7);
        x[0x8] ^= rot(x[0xb] + x[0xa], 9);
        x[0x9] ^= rot(x[0x8] + x[0xb], 13);
        x[0xa] ^= rot(x[0x9] + x[0x8], 18);
        x[0xc] ^= rot(x[0xf] + x[0xe], 7);
        x[0xd] ^= rot(x[0xc] + x[0xf], 9);
        x[0xe] ^= rot(x[0xd] + x[0xc], 13);
        x[0xf] ^= rot(x[0xe] + x[0xd], 18);
    }

    // TODO - write_u32v_le()?
    for j in range(0u, 16) {
        write_u32_le(output.mut_slice(j * 4, j * 4 + 4), x[j] + y[j]);
    }
}

fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    fn xor64(x: &[u8], y: &[u8]) -> [u8, ..64] {
        let mut out = [0u8, ..64];
        for i in range(0, 64) {
            out[i] = x[i] ^ y[i];
        }
        return out;
    }

    assert!(input.len() == output.len());
    assert!(input.len() % 128 == 0);

    let r = input.len() / 128;

    let mut x = [0u8, ..64];
    x.copy_from(input.slice_from((2 * r - 1) * 64));

    for i in range(0, 2 * r) {
        let t = xor64(x, input.slice(i * 64, i * 64 + 64));
        salsa20_x(x, t, 8);
        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            ((i - 1) / 2) * 64 + r * 64
        };
        output.mut_slice(pos, pos + 64).copy_from(x);
    }
}

fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: uint) {
    fn read_u32_le(x: &[u8]) -> u32 {
        let mut out = [0u32];
        read_u32v_le(out, x);
        return out[0];
    }

    fn xor(x: &[u8], y: &[u8], t: &mut [u8]) {
        assert!(x.len() == y.len());
        for i in range(0, t.len()) {
            t[i] = x[i] ^ y[i];
        }
    }

    let len = b.len();

    for i in range(0, n) {
        let tmp = v.mut_slice(i * len, (i + 1) * len);
        tmp.copy_from(b);
        scrypt_block_mix(tmp, b);
    }

    do n.times() {
        let j = read_u32_le(b.slice(len - 64, len - 60)) & ((n - 1) as u32);
        xor(b, v.slice((j as uint) * len, ((j + 1) as uint) * len), t);
        scrypt_block_mix(t, b);
    }
}


pub fn scrypt(password: &[u8], salt: &[u8], n: uint, r: uint, p: uint, output: &mut [u8]) {
    let mut mac = Hmac::new(Sha256::new(), password);

    let mut b = vec::from_elem(p * r * 128, 0u8);
    pbkdf2(&mut mac, salt, 1, b);

    let mut v = vec::from_elem(n * r * 128, 0u8);
    let mut t = vec::from_elem(r * 128, 0u8);

    for i in range(0, p) {
        let s = b.mut_slice(i * r * 128, (i + 1) * r * 128);
        scrypt_ro_mix(s, v, t, n);
    }

    pbkdf2(&mut mac, b, 1, output);
}

#[cfg(test)]
#[test]
fn test_scrypt_ro_mix() {
    let input: [u8, ..128] = [
        0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4,
        0x10, 0x8c, 0xf5, 0xab, 0xe9, 0x12, 0xff, 0xdd,
        0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e,
        0x82, 0x04, 0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad,
        0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8, 0x7b,
        0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29,
        0x09, 0x4f, 0x01, 0x84, 0x63, 0x95, 0x74, 0xf3,
        0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,
        0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22,
        0x6c, 0x25, 0xb5, 0x4d, 0xa8, 0x63, 0x70, 0xfb,
        0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb,
        0x8f, 0xfc, 0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0,
        0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5, 0xfe,
        0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b,
        0x7f, 0x4d, 0x1c, 0xad, 0x6a, 0x52, 0x3c, 0xda,
        0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89 ];
    let expected: [u8, ..128] = [
        0x79, 0xcc, 0xc1, 0x93, 0x62, 0x9d, 0xeb, 0xca,
        0x04, 0x7f, 0x0b, 0x70, 0x60, 0x4b, 0xf6, 0xb6,
        0x2c, 0xe3, 0xdd, 0x4a, 0x96, 0x26, 0xe3, 0x55,
        0xfa, 0xfc, 0x61, 0x98, 0xe6, 0xea, 0x2b, 0x46,
        0xd5, 0x84, 0x13, 0x67, 0x3b, 0x99, 0xb0, 0x29,
        0xd6, 0x65, 0xc3, 0x57, 0x60, 0x1f, 0xb4, 0x26,
        0xa0, 0xb2, 0xf4, 0xbb, 0xa2, 0x00, 0xee, 0x9f,
        0x0a, 0x43, 0xd1, 0x9b, 0x57, 0x1a, 0x9c, 0x71,
        0xef, 0x11, 0x42, 0xe6, 0x5d, 0x5a, 0x26, 0x6f,
        0xdd, 0xca, 0x83, 0x2c, 0xe5, 0x9f, 0xaa, 0x7c,
        0xac, 0x0b, 0x9c, 0xf1, 0xbe, 0x2b, 0xff, 0xca,
        0x30, 0x0d, 0x01, 0xee, 0x38, 0x76, 0x19, 0xc4,
        0xae, 0x12, 0xfd, 0x44, 0x38, 0xf2, 0x03, 0xa0,
        0xe4, 0xe1, 0xc4, 0x7e, 0xc3, 0x14, 0x86, 0x1f,
        0x4e, 0x90, 0x87, 0xcb, 0x33, 0x39, 0x6a, 0x68,
        0x73, 0xe8, 0xf9, 0xd2, 0x53, 0x9a, 0x4b, 0x8e ];
    let n = 16;
    let mut result = [0u8, ..128];
    result.copy_from(input);
    let mut v = vec::from_elem(result.len() * n, 0u8);
    let mut t = vec::from_elem(128, 0u8);
    scrypt_ro_mix(result, v, t, n);
    assert!(result == expected);
}

#[cfg(test)]
#[test]
fn test_scrypt_block_mix() {
    let input: [u8, ..128] = [
        0xf7, 0xce, 0x0b, 0x65, 0x3d, 0x2d, 0x72, 0xa4,
        0x10, 0x8c, 0xf5, 0xab, 0xe9, 0x12, 0xff, 0xdd,
        0x77, 0x76, 0x16, 0xdb, 0xbb, 0x27, 0xa7, 0x0e,
        0x82, 0x04, 0xf3, 0xae, 0x2d, 0x0f, 0x6f, 0xad,
        0x89, 0xf6, 0x8f, 0x48, 0x11, 0xd1, 0xe8, 0x7b,
        0xcc, 0x3b, 0xd7, 0x40, 0x0a, 0x9f, 0xfd, 0x29,
        0x09, 0x4f, 0x01, 0x84, 0x63, 0x95, 0x74, 0xf3,
        0x9a, 0xe5, 0xa1, 0x31, 0x52, 0x17, 0xbc, 0xd7,
        0x89, 0x49, 0x91, 0x44, 0x72, 0x13, 0xbb, 0x22,
        0x6c, 0x25, 0xb5, 0x4d, 0xa8, 0x63, 0x70, 0xfb,
        0xcd, 0x98, 0x43, 0x80, 0x37, 0x46, 0x66, 0xbb,
        0x8f, 0xfc, 0xb5, 0xbf, 0x40, 0xc2, 0x54, 0xb0,
        0x67, 0xd2, 0x7c, 0x51, 0xce, 0x4a, 0xd5, 0xfe,
        0xd8, 0x29, 0xc9, 0x0b, 0x50, 0x5a, 0x57, 0x1b,
        0x7f, 0x4d, 0x1c, 0xad, 0x6a, 0x52, 0x3c, 0xda,
        0x77, 0x0e, 0x67, 0xbc, 0xea, 0xaf, 0x7e, 0x89 ];
    let expected: [u8, ..128] = [
        0xa4, 0x1f, 0x85, 0x9c, 0x66, 0x08, 0xcc, 0x99,
        0x3b, 0x81, 0xca, 0xcb, 0x02, 0x0c, 0xef, 0x05,
        0x04, 0x4b, 0x21, 0x81, 0xa2, 0xfd, 0x33, 0x7d,
        0xfd, 0x7b, 0x1c, 0x63, 0x96, 0x68, 0x2f, 0x29,
        0xb4, 0x39, 0x31, 0x68, 0xe3, 0xc9, 0xe6, 0xbc,
        0xfe, 0x6b, 0xc5, 0xb7, 0xa0, 0x6d, 0x96, 0xba,
        0xe4, 0x24, 0xcc, 0x10, 0x2c, 0x91, 0x74, 0x5c,
        0x24, 0xad, 0x67, 0x3d, 0xc7, 0x61, 0x8f, 0x81,
        0x20, 0xed, 0xc9, 0x75, 0x32, 0x38, 0x81, 0xa8,
        0x05, 0x40, 0xf6, 0x4c, 0x16, 0x2d, 0xcd, 0x3c,
        0x21, 0x07, 0x7c, 0xfe, 0x5f, 0x8d, 0x5f, 0xe2,
        0xb1, 0xa4, 0x16, 0x8f, 0x95, 0x36, 0x78, 0xb7,
        0x7d, 0x3b, 0x3d, 0x80, 0x3b, 0x60, 0xe4, 0xab,
        0x92, 0x09, 0x96, 0xe5, 0x9b, 0x4d, 0x53, 0xb6,
        0x5d, 0x2a, 0x22, 0x58, 0x77, 0xd5, 0xed, 0xf5,
        0x84, 0x2c, 0xb9, 0xf1, 0x4e, 0xef, 0xe4, 0x25 ];
    let mut result = [0u8, ..128];
    scrypt_block_mix(input, result);
    assert!(result == expected);
}

#[cfg(test)]
#[test]
fn test_salsa20_8() {
    let input: [u8, ..64] = [
        0x7e, 0x87, 0x9a, 0x21, 0x4f, 0x3e, 0xc9, 0x86,
        0x7c, 0xa9, 0x40, 0xe6, 0x41, 0x71, 0x8f, 0x26,
        0xba, 0xee, 0x55, 0x5b, 0x8c, 0x61, 0xc1, 0xb5,
        0x0d, 0xf8, 0x46, 0x11, 0x6d, 0xcd, 0x3b, 0x1d,
        0xee, 0x24, 0xf3, 0x19, 0xdf, 0x9b, 0x3d, 0x85,
        0x14, 0x12, 0x1e, 0x4b, 0x5a, 0xc5, 0xaa, 0x32,
        0x76, 0x02, 0x1d, 0x29, 0x09, 0xc7, 0x48, 0x29,
        0xed, 0xeb, 0xc6, 0x8d, 0xb8, 0xb8, 0xc2, 0x5e ];
    let expected: [u8, ..64] = [
        0xa4, 0x1f, 0x85, 0x9c, 0x66, 0x08, 0xcc, 0x99,
        0x3b, 0x81, 0xca, 0xcb, 0x02, 0x0c, 0xef, 0x05,
        0x04, 0x4b, 0x21, 0x81, 0xa2, 0xfd, 0x33, 0x7d,
        0xfd, 0x7b, 0x1c, 0x63, 0x96, 0x68, 0x2f, 0x29,
        0xb4, 0x39, 0x31, 0x68, 0xe3, 0xc9, 0xe6, 0xbc,
        0xfe, 0x6b, 0xc5, 0xb7, 0xa0, 0x6d, 0x96, 0xba,
        0xe4, 0x24, 0xcc, 0x10, 0x2c, 0x91, 0x74, 0x5c,
        0x24, 0xad, 0x67, 0x3d, 0xc7, 0x61, 0x8f, 0x81 ];
    let mut result = [0u8, ..64];

    salsa20_x(result, input, 8);

    assert!(result == expected);
}

#[cfg(test)]
mod test {
    use std::vec;

    use scrypt::scrypt;


    struct Test {
        password: ~str,
        salt: ~str,
        n: uint,
        r: uint,
        p: uint,
        expected: ~[u8]
    }


    fn tests() -> ~[Test] {
        return ~[
            Test {
                password: ~"",
                salt: ~"",
                n: 16,
                r: 1,
                p: 1,
                expected: ~[
                    0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20,
                    0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97,
                    0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8,
                    0xdf, 0xdf, 0xfa, 0x3f, 0xed, 0xe2, 0x14, 0x42,
                    0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8,
                    0x32, 0x6a, 0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17,
                    0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
                    0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06 ]
            },
            Test {
                password: ~"password",
                salt: ~"NaCl",
                n: 1024,
                r: 8,
                p: 16,
                expected: ~[
                    0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00,
                    0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe,
                    0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30,
                    0xe7, 0x73, 0x76, 0x63, 0x4b, 0x37, 0x31, 0x62,
                    0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88,
                    0x6f, 0xf1, 0x09, 0x27, 0x9d, 0x98, 0x30, 0xda,
                    0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
                    0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40 ]
            },
            Test {
                password: ~"pleaseletmein",
                salt: ~"SodiumChloride",
                n: 16384,
                r: 8,
                p: 1,
                expected: ~[
                    0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48,
                    0x46, 0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb,
                    0xfd, 0xa8, 0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e,
                    0xa9, 0xb5, 0x43, 0xf6, 0x54, 0x5d, 0xa1, 0xf2,
                    0xd5, 0x43, 0x29, 0x55, 0x61, 0x3f, 0x0f, 0xcf,
                    0x62, 0xd4, 0x97, 0x05, 0x24, 0x2a, 0x9a, 0xf9,
                    0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65, 0x1e, 0x40,
                    0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58, 0x87 ]
            },
// Too slow!
            Test {
                password: ~"pleaseletmein",
                salt: ~"SodiumChloride",
                n: 1048576,
                r: 8,
                p: 1,
                expected: ~[
                    0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae,
                    0xad, 0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81,
                    0xec, 0x56, 0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d,
                    0xab, 0xe5, 0xee, 0x98, 0x20, 0xad, 0xaa, 0x47,
                    0x8e, 0x56, 0xfd, 0x8f, 0x4b, 0xa5, 0xd0, 0x9f,
                    0xfa, 0x1c, 0x6d, 0x92, 0x7c, 0x40, 0xf4, 0xc3,
                    0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9, 0x52, 0xfb,
                    0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41, 0xa4 ]
            }
        ];
    }

    #[test]
    fn test_scrypt() {
        let tests = tests();
        for t in tests.iter() {
            let mut result = vec::from_elem(t.expected.len(), 0u8);
            scrypt(t.password.as_bytes(), t.salt.as_bytes(), t.n, t.r, t.p, result);
            assert!(result == t.expected);
        }
    }
}
