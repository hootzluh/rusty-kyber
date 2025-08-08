use crate::params::{N, Q};
use crate::poly::Poly;
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};
use sha3::digest::{Update, XofReader, ExtendableOutput};

// Centered Binomial Distribution
pub fn cbd(buf: &[u8], poly: &mut Poly) {
    for i in 0..N / 4 {
        let t = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
        let mut d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for j in 0..4 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            poly.coeffs[4 * i + j] = a - b;
        }
    }
}

pub fn poly_compress(poly: &Poly, buf: &mut [u8]) {
    let mut t = [0u8; 8];
    let mut k = 0;
    for i in 0..N / 8 {
        for j in 0..8 {
            t[j] = ((((poly.coeffs[8 * i + j] as u32) << 4) + (Q as u32 / 2)) / (Q as u32) & 0xF) as u8;
        }
        buf[k] = t[0] | (t[1] << 4);
        buf[k + 1] = t[2] | (t[3] << 4);
        buf[k + 2] = t[4] | (t[5] << 4);
        buf[k + 3] = t[6] | (t[7] << 4);
        k += 4;
    }
}

pub fn poly_decompress(buf: &[u8], poly: &mut Poly) {
    let mut k = 0;
    for i in 0..N / 2 {
        let t0 = buf[k] & 0x0F;
        let t1 = buf[k] >> 4;
        k += 1;
        poly.coeffs[2 * i] = (((t0 as u32) * (Q as u32) + 8) >> 4) as i16;
        poly.coeffs[2 * i + 1] = (((t1 as u32) * (Q as u32) + 8) >> 4) as i16;
    }
}

// Serialize a polynomial to bytes
pub fn poly_to_bytes(poly: &Poly, buf: &mut [u8]) {
    let mut t = [0i16; 8];
    for i in 0..N / 8 {
        for j in 0..8 {
            t[j] = poly.coeffs[8 * i + j];
        }
        buf[13 * i..13 * i + 13].copy_from_slice(&poly_tobytes_round(t));
    }
}

// Deserialize a polynomial from bytes
pub fn poly_from_bytes(buf: &[u8], poly: &mut Poly) {
    for i in 0..N / 8 {
        poly.coeffs[8 * i..8 * i + 8].copy_from_slice(&poly_frombytes_round(
            &buf[13 * i..13 * i + 13].try_into().unwrap(),
        ));
    }
}

fn poly_tobytes_round(p: [i16; 8]) -> [u8; 13] {
    let mut r = [0u8; 13];
    r[0] = (p[0] & 0xff) as u8;
    r[1] = ((p[0] >> 8) | (p[1] << 5)) as u8;
    r[2] = ((p[1] >> 3) & 0xff) as u8;
    r[3] = ((p[1] >> 11) | (p[2] << 2)) as u8;
    r[4] = ((p[2] >> 6) | (p[3] << 7)) as u8;
    r[5] = ((p[3] >> 1) & 0xff) as u8;
    r[6] = ((p[3] >> 9) | (p[4] << 4)) as u8;
    r[7] = ((p[4] >> 4) & 0xff) as u8;
    r[8] = ((p[4] >> 12) | (p[5] << 1)) as u8;
    r[9] = ((p[5] >> 7) | (p[6] << 6)) as u8;
    r[10] = ((p[6] >> 2) & 0xff) as u8;
    r[11] = ((p[6] >> 10) | (p[7] << 3)) as u8;
    r[12] = (p[7] >> 5) as u8;
    r
}

fn poly_frombytes_round(p: &[u8; 13]) -> [i16; 8] {
    let mut r = [0i16; 8];
    r[0] = (p[0] as i16) | ((p[1] as i16 & 0x1f) << 8);
    r[1] = (p[1] >> 5) as i16 | ((p[2] as i16) << 3) | ((p[3] as i16 & 0x03) << 11);
    r[2] = (p[3] >> 2) as i16 | ((p[4] as i16 & 0x7f) << 6);
    r[3] = (p[4] >> 7) as i16 | ((p[5] as i16) << 1) | ((p[6] as i16 & 0x0f) << 9);
    r[4] = (p[6] >> 4) as i16 | ((p[7] as i16) << 4) | ((p[8] as i16 & 0x01) << 12);
    r[5] = (p[8] >> 1) as i16 | ((p[9] as i16 & 0x3f) << 7);
    r[6] = (p[9] >> 6) as i16 | ((p[10] as i16) << 2) | ((p[11] as i16 & 0x07) << 10);
    r[7] = (p[11] >> 3) as i16 | ((p[12] as i16 & 0xff) << 5);
    r
}

// H: SHA3-256
pub fn h(data: &[u8], out: &mut [u8]) {
    let mut hasher = Sha3_256::new();
    sha3::digest::Update::update(&mut hasher, data);
    out.copy_from_slice(&hasher.finalize());
}

// G: SHA3-512
pub fn g(data: &[u8], out: &mut [u8]) {
    let mut hasher = Sha3_512::new();
    sha3::digest::Update::update(&mut hasher, data);
    out.copy_from_slice(&hasher.finalize());
}

// PRF: SHAKE256
pub fn prf(data: &[u8], out_len: usize, out: &mut [u8]) {
    let mut hasher = Shake256::default();
    sha3::digest::Update::update(&mut hasher, data);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut out[..out_len]);
}

// KDF: SHAKE256
pub fn kdf(data: &[u8], out: &mut [u8]) {
    let mut hasher = Shake256::default();
    sha3::digest::Update::update(&mut hasher, data);
    let mut reader = hasher.finalize_xof();
    reader.read(out);
}

// XOF: SHAKE128
pub fn xof(data: &[u8], out_len: usize, out: &mut [u8]) {
    let mut hasher = Shake128::default();
    sha3::digest::Update::update(&mut hasher, data);
    let mut reader = hasher.finalize_xof();
    reader.read(&mut out[..out_len]);
}

// Sample a polynomial in NTT domain
pub fn sample_ntt(xof_out: &[u8], poly: &mut Poly) {
    let mut i = 0;
    let mut j = 0;
    while j < N {
        let t1 = xof_out[i] as u16;
        let t2 = xof_out[i + 1] as u16;
        let t3 = xof_out[i + 2] as u16;
        i += 3;

        let d1 = t1 | (t2 << 8);
        let d2 = (t2 >> 4) | (t3 << 4);

        if d1 < 3329 {
            poly.coeffs[j] = d1 as i16;
            j += 1;
        }
        if j < N && d2 < 3329 {
            poly.coeffs[j] = d2 as i16;
            j += 1;
        }
    }
}
