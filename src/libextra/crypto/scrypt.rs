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
 * This module implements the Scrypt key derivation function as specified in [1].
 *
 * # References
 * [1] - C. Percival. Stronger Key Derivation Via Sequential Memory-Hard Functions.
 *       http://www.tarsnap.com/scrypt/scrypt.pdf
 */

// There are a variety of places that we need to cast a u32 to a uint. The implementation is
// #[cfg]ed to not compile on platforms where that isn't safe for all values. A more elegant
// solution would be to check if its safe for the particular values of interest, although that would
// be more complicated.

use std::rand::{IsaacRng, RngUtil};
use std::vec;
use std::vec::MutableCloneableVector;

use base64;
use base64::{FromBase64, ToBase64};
use cryptoutil::{read_u32v_le, read_u32_le, write_u32_le, fixed_time_eq};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

// The maximum amount of memory to allocate. This is somewhat arbitrarily chosen, but 1GB should be
// plently for the forseable future.
static MAX_MEM: u32 = 1 << 30;

// The salsa20/8 core function.
fn salsa20_8(input: &[u8], output: &mut [u8]) {
    fn rot(a: u32, b: uint) -> u32 {
        return (a << b) | (a >> (32 - b));
    }

    let mut x = [0u32, ..16];
    read_u32v_le(x, input);

    let rounds = 8;

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

    for i in range(0u, 16) {
        write_u32_le(
            output.mut_slice(i * 4, (i + 1) * 4),
            x[i] + read_u32_le(input.slice(i * 4, (i + 1) * 4)));
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for i in range(0, output.len()) {
        output[i] = x[i] ^ y[i];
    }
}

// Execute the BlockMix operation
// input - the input vector. The length must be a multiple of 128.
// output - the output vector. Must be the same length as input.
fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    let mut x = [0u8, ..64];
    x.copy_from(input.slice_from(input.len() - 64));

    let mut t = [0u8, ..64];

    for i in range(0, input.len() / 64) {
        xor(x, input.slice(i * 64, (i + 1) * 64), t);
        salsa20_8(t, x);
        let pos = if i % 2 == 0 { (i / 2) * 64 } else { (i / 2) * 64 + input.len() / 2 };
        output.mut_slice(pos, pos + 64).copy_from(x);
    }
}

// Execute the ROMix operation in-place.
// b - the data to operate on
// v - a temporary variable to store the vector V
// t - a temporary variable to store the result of the xor
// n - the scrypt parameter N
fn scrypt_ro_mix(b: &mut [u8], v: &mut [u8], t: &mut [u8], n: u32) {
    fn integerify(x: &[u8], n: u32) -> u32 {
        // n is a power of 2, so n - 1 gives us a bitmask that we can use to perform a calculation
        // mod n using a simple bitwise and.
        let mask = n - 1;
        return read_u32_le(x.slice(x.len() - 64, x.len() - 60)) & mask;
    }

    let len = b.len();

    for i in range(0, n as uint) {
        let tmp = v.mut_slice(i * len, (i + 1) * len);
        tmp.copy_from(b);
        scrypt_block_mix(tmp, b);
    }

    do (n as uint).times() {
        let j = integerify(b, n);
        // j as uint won't overflow since we've already check that values mod n fit into a uint.
        xor(b, v.slice((j as uint) * len, ((j + 1) as uint) * len), t);
        scrypt_block_mix(t, b);
    }
}

/**
 * The Scrypt parameter values.
 */
#[cfg(target_word_size = "32")]
#[cfg(target_word_size = "64")]
pub struct ScryptParams {
    priv log_n: u32,
    priv r: u32,
    priv p: u32
}

#[cfg(target_word_size = "32")]
#[cfg(target_word_size = "64")]
impl ScryptParams {
    /**
     * Create a new instance of the ScryptParams.
     *
     * # Arguments
     *
     * * log_n - The log2 of the Scrypt parameter N
     * * r - The Scrypt parameter r
     * * p - The Scrypt parameter p
     *
     */
    pub fn new(log_n: u32, r: u32, p: u32) -> ScryptParams {
        // The scrypt_simple() and scrypt_check() functions depend on the types of the parameters
        // and some of the checks here. Don't allow a wider range of parameters without checking
        // that those functions will still work.

        assert!(r > 0);
        assert!(p > 0);
        assert!(log_n > 0 && log_n < 32);

        // check: n < 2^(128 * r / 8)
        assert!(log_n < 128 * r / 8);

        // check: p <= ((2^32-1) * 32) / (128 * r)
        // It takes a bit of re-arranging to get the check above into this form, but, it is indeed
        // the same.
        assert!((r as u64) * (p as u64) < (1 << 30));

        // Check that we won't attempt to allocate too much memory (or get an integer overflow while
        // trying to).
        // We know that p * r won't overflow from the previous checks.
        assert!(p * r <= MAX_MEM / 128);
        assert!(r <= MAX_MEM / 128 >> log_n);

        return ScryptParams {
            log_n: log_n,
            r: r,
            p: p
        };
    }
}

/**
 * The scrypt key derivation function.
 *
 * # Arguments
 *
 * * password - The password to process as a byte vector
 * * salt - The salt value to use as a byte vector
 * * params - The ScryptParams to use
 * * output - The resulting derived key is returned in this byte vector.
 *
 */
#[cfg(target_word_size = "32")]
#[cfg(target_word_size = "64")]
pub fn scrypt(password: &[u8], salt: &[u8], params: &ScryptParams, output: &mut [u8]) {
    // check output.len() > 0 && output.len() <= (2^32 - 1) * 32
    assert!(output.len() > 0 && output.len() / 32 <= 0xffffffff);

    let n = (1 << params.log_n);
    let r = params.r;
    let p = params.p;

    let mut mac = Hmac::new(Sha256::new(), password);

    let mut b = vec::from_elem((p * r * 128) as uint, 0u8);
    pbkdf2(&mut mac, salt, 1, b);

    let mut v = vec::from_elem((n * r * 128) as uint, 0u8);
    let mut t = vec::from_elem((r * 128) as uint, 0u8);

    for i in range(0, p as uint) {
        let s = b.mut_slice(i * (r as uint) * 128, (i + 1) * (r as uint) * 128);
        scrypt_ro_mix(s, v, t, n);
    }

    pbkdf2(&mut mac, b, 1, output);
}

/**
 * scrypt_simple is a helper function that should be sufficient for the majority of cases where
 * an application needs to use Scrypt to hash a password for storage. The result is a ~str that
 * contains the parameters used as part of its encoding. The scrypt_check function may be used on
 * a password to check if it is equal to a hashed value.
 *
 * # Format
 *
 * The format of the output is a modified version of the Modular Crypt Format (? ref) that encodes
 * algorithm used and the parameter values. If all parameter values can each fit within a single
 * byte, a compact format is used (format 0). However, if any value cannot, an expanded format where
 * the r and p parameters are encoded using 4 bytes (format 1) is used. Both formats use a 128-bit
 * salt and a 256-bit hash. The format is indicated as "rscrypt" which is short for "Rust Scrypt
 * format."
 *
 * $rscrypt$<format>$<base64(log_n,r,p)>$<base64(salt)>$<based64(hash)>$
 *
 * # Arguments
 *
 * * password - The password to process as a str
 * * params - The ScryptParams to use
 *
 */
#[cfg(target_word_size = "32")]
#[cfg(target_word_size = "64")]
pub fn scrypt_simple(password: &str, params: &ScryptParams) -> ~str {
    let mut rng = IsaacRng::new();

    // 128-bit salt
    let salt = rng.gen_bytes(16);

    // 256-bit derived key
    let mut dk = [0u8, ..32];

    scrypt(password.as_bytes(), salt, params, dk);

    let mut result = ~"$rscrypt$";
    if params.r < 256 && params.p < 256 {
        result.push_str("0$");
        let mut tmp = [0u8, ..3];
        tmp[0] = params.log_n as u8;
        tmp[1] = params.r as u8;
        tmp[2] = params.p as u8;
        result.push_str(tmp.slice_to(tmp.len()).to_base64(base64::STANDARD));
    } else {
        result.push_str("1$");
        let mut tmp = [0u8, ..9];
        tmp[0] = params.log_n as u8;
        write_u32_le(tmp.mut_slice(1, 5), params.r);
        write_u32_le(tmp.mut_slice(5, 9), params.p);
        result.push_str(tmp.slice_to(tmp.len()).to_base64(base64::STANDARD));
    }
    result.push_char('$');
    result.push_str(salt.slice_to(salt.len()).to_base64(base64::STANDARD));
    result.push_char('$');
    result.push_str(dk.slice_to(dk.len()).to_base64(base64::STANDARD));
    result.push_char('$');

    return result;
}

/**
 * scrypt_check compares a password against the result of a previous call to scrypt_simple and
 * returns true if the passed in password hashes to the same value.
 *
 * # Arguments
 *
 * * password - The password to process as a str
 * * hashed_value - A string representing a hashed password returned by scrypt_simple()
 *
 */
#[cfg(target_word_size = "32")]
#[cfg(target_word_size = "64")]
pub fn scrypt_check(password: &str, hashed_value: &str) -> Result<bool, &'static str> {
    static ERR_STR: &'static str = "Hash is not in Rust Scrypt format.";

    let mut iter = hashed_value.split_iter('$');

    // Check that there are no characters before the first "$"
    match iter.next() {
        Some(x) => if x != "" { return Err(ERR_STR); },
        None => return Err(ERR_STR)
    }

    // Check the name
    match iter.next() {
        Some(t) => if t != "rscrypt" { return Err(ERR_STR); },
        None => return Err(ERR_STR)
    }

    // Parse format - currenlty only version 0 (compact) and 1 (expanded) are supported
    let params: ScryptParams;
    match iter.next() {
        Some(fstr) => {
            // Parse the parameters - the size of them depends on the if we are using the compact or
            // expanded format
            let pvec = match iter.next() {
                Some(pstr) => match pstr.from_base64() {
                    Ok(x) => x,
                    Err(_) => return Err(ERR_STR)
                },
                None => return Err(ERR_STR)
            };
            match fstr {
                "0" => {
                    if pvec.len() != 3 { return Err(ERR_STR); }
                    let log_n = pvec[0] as u32;
                    let r = pvec[1] as u32;
                    let p = pvec[2] as u32;
                    params = ScryptParams::new(log_n, r, p);
                }
                "1" => {
                    if pvec.len() != 9 { return Err(ERR_STR); }
                    let log_n = pvec[0] as u32;
                    let mut pval = [0u32, ..2];
                    read_u32v_le(pval, pvec.slice(1, 9));
                    params = ScryptParams::new(log_n, pval[0], pval[1]);
                }
                _ => return Err(ERR_STR)
            }
        }
        None => return Err(ERR_STR)
    }

    // Salt
    let salt = match iter.next() {
        Some(sstr) => match sstr.from_base64() {
            Ok(salt) => salt,
            Err(_) => return Err(ERR_STR)
        },
        None => return Err(ERR_STR)
    };
    if salt.len() != 16 {
        return Err(ERR_STR);
    }

    // Hashed value
    let hash = match iter.next() {
        Some(hstr) => match hstr.from_base64() {
            Ok(hash) => hash,
            Err(_) => return Err(ERR_STR)
        },
        None => return Err(ERR_STR)
    };
    if hash.len() != 32 {
        return Err(ERR_STR);
    }

    // Make sure that the input ends with a "$"
    match iter.next() {
        Some(x) => if x != "" { return Err(ERR_STR); },
        None => return Err(ERR_STR)
    }

    // Make sure there is no trailing data after the final "$"
    match iter.next() {
        Some(_) => return Err(ERR_STR),
        None => { }
    }

    let mut output = vec::from_elem(hash.len(), 0u8);
    scrypt(password.as_bytes(), salt, &params, output);

    // Be careful here - its important that the comparison be done using a fixed time equality
    // check. Otherwise an adversary that can measure how long this step takes can learn about the
    // hashed value which would allow them to mount an offline brute force attack against the
    // hashed password.
    return Ok(fixed_time_eq(output, hash));
}

#[cfg(test, target_word_size = "32")]
#[cfg(test, target_word_size = "64")]
mod test {
    use std::vec;

    use scrypt::{scrypt, scrypt_simple, scrypt_check, ScryptParams};

    struct Test {
        password: ~str,
        salt: ~str,
        log_n: u32,
        r: u32,
        p: u32,
        expected: ~[u8]
    }

    // Test vectors from [1]. The last test vector is omitted because it takes too long to run.

    fn tests() -> ~[Test] {
        return ~[
            Test {
                password: ~"",
                salt: ~"",
                log_n: 4,
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
                log_n: 10,
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
                log_n: 14,
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
        ];
    }

    #[test]
    fn test_scrypt() {
        let tests = tests();
        for t in tests.iter() {
            let mut result = vec::from_elem(t.expected.len(), 0u8);
            let params = ScryptParams::new(t.log_n, t.r, t.p);
            scrypt(t.password.as_bytes(), t.salt.as_bytes(), &params, result);
            assert!(result == t.expected);
        }
    }

    fn test_scrypt_simple(log_n: u32, r: u32, p: u32) {
        let password = "password";

        let params = ScryptParams::new(log_n, r, p);
        let out1 = scrypt_simple(password, &params);
        let out2 = scrypt_simple(password, &params);

        // This just makes sure that a salt is being applied. It doesn't verify that that salt is
        // cryptographically strong, however.
        assert!(out1 != out2);

        match scrypt_check(password, out1) {
            Ok(r) => assert!(r),
            Err(_) => fail!()
        }
        match scrypt_check(password, out2) {
            Ok(r) => assert!(r),
            Err(_) => fail!()
        }

        match scrypt_check("wrong", out1) {
            Ok(r) => assert!(!r),
            Err(_) => fail!()
        }
        match scrypt_check("wrong", out2) {
            Ok(r) => assert!(!r),
            Err(_) => fail!()
        }
    }

    #[test]
    fn test_scrypt_simple_compact() {
        // These parameters are intentionally very weak - the goal is to make the test run quickly!
        test_scrypt_simple(7, 8, 1);
    }

    #[test]
    fn test_scrypt_simple_expanded() {
        // These parameters are intentionally very weak - the goal is to make the test run quickly!
        test_scrypt_simple(3, 1, 256);
    }
}
