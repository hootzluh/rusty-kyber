use crate::params::{K, SECRET_KEY_BYTES, CIPHERTEXT_BYTES, POLY_VEC_BYTES, POLY_BYTES};
use crate::poly::Poly;
use crate::utils::{poly_to_bytes, poly_from_bytes};

pub fn indcpa_dec(
    sk: &[u8; SECRET_KEY_BYTES],
    ct: &[u8; CIPHERTEXT_BYTES],
    msg: &mut [u8; 32],
) {
    let mut bp = [Poly::new(); K];
    let mut sk_poly = [Poly::new(); K];
    let mut mp = Poly::new();
    let mut v = Poly::new();

    for i in 0..K {
        poly_from_bytes(&ct[i * POLY_BYTES..], &mut bp[i]);
        poly_from_bytes(&sk[i * POLY_BYTES..], &mut sk_poly[i]);
    }
    poly_from_bytes(&ct[POLY_VEC_BYTES..], &mut v);

    for i in 0..K {
        bp[i].ntt();
    }

    // Matrix-vector multiplication
    for i in 0..K {
        let mut tmp = sk_poly[i];
        tmp.pointwise_mul(&bp[i]);
        mp.add(&tmp);
    }

    mp.inv_ntt();
    mp.sub(&v);

    poly_to_bytes(&mp, msg);
}
