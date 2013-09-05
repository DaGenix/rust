// Copyright 2012-2013 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/*!
 * This module implements the PBKDF2 Key Derivation Function as specified by
 * http://tools.ietf.org/html/rfc2898.
 */

use std::vec;

use cryptoutil::write_u32_be;
use mac::Mac;

// Calculate a block of the output of size equal to the output_bytes of the underlying Mac function
// mac - The Mac function to use
// salt - the salt value to use
// c - the iteration count
// idx - the 1 based index of the block
// scratch - a temporary variable the same length as the block
// block - the block of the output to calculate
fn calculate_block<M: Mac>(
        mac: &mut M,
        salt: &[u8],
        c: uint,
        idx: u32,
        scratch: &mut [u8],
        block: &mut [u8]) {
    // Perform the 1st iteration. The output goes directly into block
    mac.input(salt);
    let mut idx_buf = [0u8, ..4];
    write_u32_be(idx_buf, idx);
    mac.input(idx_buf);
    mac.raw_result(block);
    mac.reset();

    // Perform the 2nd iteration. The input comes from block and is output into scratch. scratch is
    // then exclusive-or added into block. After all this, the input to the next step is now in
    // scratch and block is left to just accumulate the exclusive-of sum of remaining iterations.
    if c > 1 {
        mac.input(block);
        mac.raw_result(scratch);
        mac.reset();
        for i in range(0, scratch.len()) {
            block[i] ^= scratch[i];
        }
    }

    // Perform all remaining iterations
    for _ in range(2, c) {
        mac.input(scratch);
        mac.raw_result(scratch);
        mac.reset();
        for i in range(0, scratch.len()) {
            block[i] ^= scratch[i];
        }
    }
}

/**
 * Execute the PBKDF2 Key Derivation Function. The Scrypt Key Derivation Function generally provides
 * better security, so, applications that do not have a requirement to use PBKDF2 specifically
 * should consider using that function instead.
 *
 * # Arguments
 * * mac - The Pseudo Random Function to use.
 * * salt - The salt value to use.
 * * c - The iteration count. Users should carefully determine this value as it is the primary
 *       factor in determining the security of the derived key.
 * * output - The output buffer to fill with the derived key value.
 *
 */
pub fn pbkdf2<M: Mac>(mac: &mut M, salt: &[u8], c: uint, output: &mut [u8]) {
    assert!(c > 0);

    let os = mac.output_bytes();

    // A temporary storage array needed by calculate_block. This is really only necessary if c > 1.
    // Most users of pbkdf2 should use a value much larger than 1, so, this allocation should almost
    // always be necessary. A big exception is Scrypt. However, this allocation is unlikely to be
    // the bottleneck in Scrypt performance.
    let mut scratch = vec::from_elem(os, 0u8);

    let mut idx: u32 = 0;
    let mut pos: uint = 0;
    while pos < output.len() {
        if idx == Bounded::max_value() {
            fail!("PBKDF2 size limit exceeded.");
        } else {
            // The block index starts at 1, so this is supposed to run on the first execution.
            idx += 1;
        }
        let remaining = output.len() - pos;
        if remaining >= os {
            calculate_block(mac, salt, c, idx, scratch, output.mut_slice(pos, pos + os));
            pos += os;
        } else {
            let mut tmp = vec::from_elem(os, 0u8);
            calculate_block(mac, salt, c, idx, scratch, tmp);
            vec::bytes::copy_memory(output.mut_slice_from(pos), tmp, remaining);
            break;
        }
    }
}

#[cfg(test)]
mod test {
    use std::vec;

    use pbkdf2::pbkdf2;
    use hmac::Hmac;
    use sha1::Sha1;

    struct Test {
        password: ~[u8],
        salt: ~[u8],
        c: uint,
        expected: ~[u8]
    }

    // Test vectors from http://tools.ietf.org/html/rfc6070. The 4th test vector is omitted because
    // it takes too long to run.

    fn tests() -> ~[Test] {
        return ~[
            Test {
                password: "password".as_bytes().to_owned(),
                salt: "salt".as_bytes().to_owned(),
                c: 1,
                expected: ~[
                    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
                    0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
                    0x2f, 0xe0, 0x37, 0xa6 ]
            },
            Test {
                password: "password".as_bytes().to_owned(),
                salt: "salt".as_bytes().to_owned(),
                c: 2,
                expected: ~[
                    0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
                    0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
                    0xd8, 0xde, 0x89, 0x57 ]
            },
            Test {
                password: "password".as_bytes().to_owned(),
                salt: "salt".as_bytes().to_owned(),
                c: 4096,
                expected: ~[
                    0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
                    0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
                    0x65, 0xa4, 0x29, 0xc1 ]
            },
            Test {
                password: "passwordPASSWORDpassword".as_bytes().to_owned(),
                salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes().to_owned(),
                c: 4096,
                expected: ~[
                    0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
                    0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
                    0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70, 0x38 ]
            },
            Test {
                password: ~[112, 97, 115, 115, 0, 119, 111, 114, 100],
                salt: ~[115, 97, 0, 108, 116],
                c: 4096,
                expected: ~[
                    0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
                    0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3 ]
            }
        ];
    }

    #[test]
    fn test_pbkdf2() {
        let tests = tests();
        for t in tests.iter() {
            let mut mac = Hmac::new(Sha1::new(), t.password);
            let mut result = vec::from_elem(t.expected.len(), 0u8);
            pbkdf2(&mut mac, t.salt, t.c, result);
            assert!(result == t.expected);
        }
    }
}
