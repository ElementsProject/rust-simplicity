// Rust Simplicity Library
// Written in 2020 by
//   Andrew Poelstra <apoelstra@blockstream.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Commitment Merkle Roots
//!
//! Tagged SHA256 hashes used for computing CMRs
//!

/// A 32-byte zero string
pub const ZERO_32: [u8; 32] = [0; 32];

/// A collection of tagged hash types
pub mod hash_engine {
    use bitcoin_hashes::sha256;

    /// Tagged hash used by `iden`
    pub fn iden() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0x58, 0x97, 0xf9, 0x5d, 0xe2, 0x1f, 0xaf, 0x1e,
                0x3e, 0x4a, 0xab, 0x12, 0x78, 0x06, 0x6a, 0x73,
                0xb2, 0x6b, 0x27, 0xac, 0x8a, 0x25, 0x6c, 0x5c,
                0xc3, 0x7c, 0x73, 0xc9, 0x6e, 0x29, 0xe1, 0x6a,
            ]),
            64,
        )
    }

    /// Tagged hash used by `comp`
    pub fn comp() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0x85, 0x61, 0xcb, 0x37, 0xd5, 0x8d, 0xfb, 0x60,
                0xe0, 0xa1, 0x0b, 0x94, 0xef, 0xbf, 0x95, 0x52,
                0x7c, 0xe7, 0x97, 0x32, 0x15, 0xe8, 0x82, 0x6f,
                0x46, 0x15, 0xfc, 0x5f, 0xae, 0xff, 0x5c, 0xe9,
            ]),
            64,
        )
    }

    /// Tagged hash used by `unit`
    pub fn unit() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0xd7, 0x23, 0x08, 0x3c, 0xff, 0x3c, 0x75, 0xe2,
                0x9f, 0x29, 0x67, 0x07, 0xec, 0xf2, 0x75, 0x03,
                0x38, 0xf1, 0x00, 0x59, 0x1c, 0x86, 0xe0, 0xc7,
                0x17, 0x17, 0xf8, 0x07, 0xff, 0x3c, 0xf6, 0x9d,
            ]),
            64,
        )
    }

    /// Tagged hash used by `injl`
    pub fn injl() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0x78, 0x72, 0xdb, 0xd3, 0x46, 0x97, 0xe9, 0xc4,
                0x26, 0x4e, 0xad, 0x6d, 0xc1, 0xc3, 0x6b, 0x0e,
                0x85, 0xe2, 0x5b, 0x56, 0x17, 0x00, 0x4e, 0x8a,
                0xd4, 0xac, 0x2a, 0x38, 0x15, 0x93, 0xae, 0xeb,
            ]),
            64,
        )
    }

    /// Tagged hash used by `injr`
    pub fn injr() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0x0e, 0xb0, 0x0b, 0x89, 0x20, 0x77, 0x61, 0x23,
                0x2f, 0x16, 0x8d, 0xff, 0xcd, 0x8f, 0xda, 0xf9,
                0xeb, 0x15, 0xa2, 0x0e, 0xcf, 0x4f, 0x68, 0xa2,
                0xde, 0x52, 0x03, 0x24, 0x2f, 0xe2, 0xa0, 0xd6,
            ]),
            64,
        )
    }

    /// Tagged hash used by `case`
    pub fn case() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0xd4, 0x91, 0xf7, 0x3a, 0x5c, 0xc0, 0x88, 0x4a,
                0xb4, 0xef, 0xca, 0x12, 0x33, 0x79, 0x8b, 0x31,
                0xba, 0x62, 0x86, 0x96, 0x20, 0x5a, 0x81, 0xe7,
                0x67, 0x56, 0x27, 0x2d, 0xdb, 0xd3, 0xdf, 0xfb,
            ]),
            64,
        )
    }

    /// Tagged hash used by `pair`
    pub fn pair() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0xf8, 0x86, 0x2e, 0x70, 0xe0, 0x7c, 0xe3, 0xc2,
                0x27, 0x63, 0xdf, 0xbf, 0x7e, 0x7c, 0xbd, 0x27,
                0x8e, 0xad, 0xbb, 0xa4, 0x35, 0x5f, 0x64, 0x4e,
                0x1c, 0x91, 0xc0, 0xe8, 0xe8, 0x24, 0x8d, 0xb7,
            ]),
            64,
        )
    }

    /// Tagged hash used by `take`
    pub fn take() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0x3a, 0x5a, 0xfe, 0x9e, 0xaf, 0x9f, 0x65, 0x16,
                0x77, 0x63, 0x27, 0x7f, 0x37, 0x28, 0x82, 0xb6,
                0x6d, 0x76, 0xc9, 0xc7, 0x90, 0x8d, 0x89, 0xb1,
                0x75, 0x3f, 0x40, 0xaa, 0x0e, 0xae, 0xe9, 0x82,
            ]),
            64,
        )
    }

    /// Tagged hash used by `drop`
    pub fn drop() -> sha256::HashEngine {
        sha256::HashEngine::from_midstate(
            sha256::Midstate::from_inner([
                0xcd, 0xc7, 0x50, 0x2a, 0xef, 0x55, 0x84, 0x38,
                0x9e, 0xf3, 0x38, 0x5c, 0x11, 0x2c, 0x3b, 0x51,
                0x9c, 0x3d, 0xbd, 0xd6, 0xc9, 0x6c, 0xaf, 0x74,
                0xeb, 0x85, 0x5b, 0x5e, 0x56, 0x14, 0x2c, 0xfc,
            ]),
            64,
        )
    }
}

