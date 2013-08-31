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

use digest::Digest;
use mac::{Mac, MacResult};


/// TMP
pub struct Hmac<D> {
    priv digest: D,
    priv i_key: ~[u8],
    priv o_key: ~[u8],
    priv finished: bool
}

fn derive_key(key: &mut [u8], mask: u8) {
    for i in range(0, key.len()) {
        key[i] ^= mask;
    }
}

fn expand_key<D: Digest>(digest: &mut D, key: &[u8]) -> ~[u8] {
    let bs = digest.block_size();
    let mut expanded_key = vec::from_elem(bs, 0u8);
    if key.len() <= bs {
        vec::bytes::copy_memory(expanded_key, key, key.len());
        for i in range(key.len(), expanded_key.len()) {
            expanded_key[i] = 0;
        }
    } else {
        let output_size = digest.output_bytes();
        digest.input(key);
        digest.result(expanded_key.mut_slice_to(output_size));
        digest.reset();
        for i in range(output_size, expanded_key.len()) {
            expanded_key[i] = 0;
        }
    }
    return expanded_key;
}

fn create_keys<D: Digest>(digest: &mut D, key: &[u8]) -> (~[u8], ~[u8]) {
    let mut i_key = expand_key(digest, key);
    let mut o_key = i_key.clone();
    derive_key(i_key, 0x36);
    derive_key(o_key, 0x5c);
    return (i_key, o_key);
}

impl <D: Digest> Hmac<D> {
    /// TMP
    pub fn new(mut digest: D, key: &[u8]) -> Hmac<D> {
        let (i_key, o_key) = create_keys(&mut digest, key);
        digest.input(i_key);
        return Hmac {
            digest: digest,
            i_key: i_key,
            o_key: o_key,
            finished: false
        }
    }

    /// TMP
    pub fn reset_key(&mut self, key: &[u8]) {
        self.digest.reset();
        let (i_key, o_key) = create_keys(&mut self.digest, key);
        self.i_key = i_key;
        self.o_key = o_key;
        self.digest.input(self.i_key);
        self.finished = false;
    }
}

impl <D: Digest> Mac for Hmac<D> {
    fn input(&mut self, data: &[u8]) {
        assert!(!self.finished);
        self.digest.input(data);
    }

    fn reset(&mut self) {
        self.digest.reset();
        self.digest.input(self.i_key);
        self.finished = false;
    }

    fn result(&mut self) -> MacResult {
        let output_size = self.digest.output_bytes();
        let mut code = vec::from_elem(output_size, 0u8);

        self.raw_result(code);

        return MacResult::new_from_owned(code);
    }

    fn raw_result(&mut self, output: &mut [u8]) {
        if !self.finished {
            self.digest.result(output);

            self.digest.reset();
            self.digest.input(self.o_key);
            self.digest.input(output);

            self.finished = true;
        }

        self.digest.result(output);
    }

    fn output_bytes(&self) -> uint { self.digest.output_bytes() }
}


#[cfg(test)]
mod test {
    use mac::{Mac, MacResult};
    use hmac::Hmac;
    use digest::Digest;
    use md5::Md5;
    use sha1::Md5;
    use sha2::Sha256;

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

    #[test]
    fn test_hmac_md5() {
        let mut hmac = Hmac::new(Md5::new(), "key".as_bytes());
        hmac.input("The quick brown fox jumps over the lazy dog".as_bytes());
        let result = hmac.result();
        let expected = MacResult::new_from_owned(from_str("80070713463e7749b90c2dc24911e275"));
        assert!(result == expected);
    }
}
