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

use cryptoutil::write_u32_be;
use mac::Mac;


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

    // Perform all following iterations
    for _ in range(2, c) {
        mac.input(scratch);
        mac.raw_result(scratch);
        mac.reset();
        for i in range(0, scratch.len()) {
            block[i] ^= scratch[i];
        }
    }
}

pub fn pbkdf2<M: Mac>(mac: &mut M, salt: &[u8], c: uint, output: &mut [u8]) {
    // TODO - ignoring check that output is not too long
    assert!(c > 0);

    let os = mac.output_bytes();
    let mut scratch = vec::from_elem(os, 0u8);

    let mut pos: uint = 0;
    while pos * os < output.len() {
        let idx = (pos + 1) as u32;
        if pos * os + os < output.len() {
            calculate_block(mac, salt, c, idx, scratch, output.mut_slice(pos * os, pos * os + os));
        } else {
            let mut tmp = vec::from_elem(os, 0u8);
            calculate_block(mac, salt, c, idx, scratch, tmp);
            let remaining = output.len() - pos * os;
            vec::bytes::copy_memory(output.mut_slice_from(pos * os), tmp, remaining);
        }
        pos += 1;
    }
}


#[cfg(test)]
mod test {
    use std::vec;

    use pbkdf2::pbkdf2;
    use hmac::Hmac;
    use sha1::Sha1;

    fn from_str(input: &str) -> ~[u8] {
        use std::u8;
        use std::uint;
        let mut out: ~[u8] = ~[];
        do uint::range_step(0, input.len(), 2) |i| {
            out.push(u8::from_str_radix(input.slice(i, i+2), 16).unwrap());
            true
        };
        return out;
    }

    struct Test {
        password: ~[u8],
        salt: ~[u8],
        c: uint,
        expected: ~[u8]
    }

    fn tests() -> ~[Test] {
        return ~[
            Test {
                password: "password".as_bytes().to_owned(),
                salt: "salt".as_bytes().to_owned(),
                c: 1,
                expected: from_str("0c60c80f961f0e71f3a9b524af6012062fe037a6")
            },
            Test {
                password: "password".as_bytes().to_owned(),
                salt: "salt".as_bytes().to_owned(),
                c: 2,
                expected: from_str("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957")
            },
            Test {
                password: "password".as_bytes().to_owned(),
                salt: "salt".as_bytes().to_owned(),
                c: 4096,
                expected: from_str("4b007901b765489abead49d926f721d065a429c1")
            },
// This takes too long
//             Test {
//                 password: "password".as_bytes().to_owned(),
//                 salt: "salt".as_bytes().to_owned(),
//                 c: 16777216,
//                 expected: from_str("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984")
//             },
            Test {
                password: "passwordPASSWORDpassword".as_bytes().to_owned(),
                salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes().to_owned(),
                c: 4096,
                expected: from_str("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038")
            },
            Test {
                password: ~[112, 97, 115, 115, 0, 119, 111, 114, 100],
                salt: ~[115, 97, 0, 108, 116],
                c: 4096,
                expected: from_str("56fa6aa75548099dcc37d7f03425e0c3")
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
