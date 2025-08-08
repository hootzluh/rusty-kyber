#![allow(dead_code)]

// Common parameters
pub const N: usize = 256;
pub const Q: i32 = 3329;
pub const Q_INV: i32 = 62209; // -1/Q mod 2^16

// -- Default to Kyber512 parameters, unless feature is set
#[cfg(feature = "kyber768")]
pub use kyber768::*;
#[cfg(feature = "kyber1024")]
pub use kyber1024::*;

// Fallback: If neither feature is set, use kyber512
#[cfg(all(not(feature = "kyber768"), not(feature = "kyber1024")))]
pub use kyber512::*;

// Your previous submodules (unchanged)
pub mod kyber512 {
    pub const K: usize = 2;
    pub const ETA1: i32 = 3;
    pub const ETA2: i32 = 2;
    pub const DU: usize = 10;
    pub const DV: usize = 4;
    pub const POLY_BYTES: usize = 384;
    pub const POLY_VEC_BYTES: usize = K * POLY_BYTES;
    pub const POLY_COMPRESSED_BYTES: usize = 128;
    pub const POLY_VEC_COMPRESSED_BYTES: usize = K * 320;
    pub const SECRET_KEY_BYTES: usize = POLY_VEC_BYTES;
    pub const PUBLIC_KEY_BYTES: usize = POLY_VEC_BYTES + 32;
    pub const CIPHERTEXT_BYTES: usize = POLY_VEC_COMPRESSED_BYTES + POLY_COMPRESSED_BYTES;
    pub const SHARED_SECRET_BYTES: usize = 32;
}

pub mod kyber768 {
    pub const K: usize = 3;
    pub const ETA1: i32 = 2;
    pub const ETA2: i32 = 2;
    pub const DU: usize = 10;
    pub const DV: usize = 4;
    pub const POLY_BYTES: usize = 384;
    pub const POLY_VEC_BYTES: usize = K * POLY_BYTES;
    pub const POLY_COMPRESSED_BYTES: usize = 128;
    pub const POLY_VEC_COMPRESSED_BYTES: usize = K * 320;
    pub const SECRET_KEY_BYTES: usize = POLY_VEC_BYTES;
    pub const PUBLIC_KEY_BYTES: usize = POLY_VEC_BYTES + 32;
    pub const CIPHERTEXT_BYTES: usize = POLY_VEC_COMPRESSED_BYTES + POLY_COMPRESSED_BYTES;
    pub const SHARED_SECRET_BYTES: usize = 32;
}

pub mod kyber1024 {
    pub const K: usize = 4;
    pub const ETA1: i32 = 2;
    pub const ETA2: i32 = 2;
    pub const DU: usize = 11;
    pub const DV: usize = 5;
    pub const POLY_BYTES: usize = 384;
    pub const POLY_VEC_BYTES: usize = K * POLY_BYTES;
    pub const POLY_COMPRESSED_BYTES: usize = 160;
    pub const POLY_VEC_COMPRESSED_BYTES: usize = K * 352;
    pub const SECRET_KEY_BYTES: usize = POLY_VEC_BYTES;
    pub const PUBLIC_KEY_BYTES: usize = POLY_VEC_BYTES + 32;
    pub const CIPHERTEXT_BYTES: usize = POLY_VEC_COMPRESSED_BYTES + POLY_COMPRESSED_BYTES;
    pub const SHARED_SECRET_BYTES: usize = 32;
}
