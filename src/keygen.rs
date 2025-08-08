use crate::params::{K, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, POLY_BYTES};
use crate::poly::Poly;
use crate::utils::{xof, prf, g, sample_ntt, cbd, poly_to_bytes};
use rand_core::{RngCore, CryptoRng};

pub fn indcpa_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &mut [u8; PUBLIC_KEY_BYTES],
    sk: &mut [u8; SECRET_KEY_BYTES],
) {
    let mut seed = [0u8; 64];
    rng.fill_bytes(&mut seed);

    let mut g_out = [0u8; 64];
    g(&seed[..32], &mut g_out);
    let (rho, sigma) = g_out.split_at(32);

    let mut a = [[Poly::new(); K]; K];
    for i in 0..K {
        for j in 0..K {
            let mut xof_out = [0u8; 672];
            let mut seed_a = [0u8; 34];
            seed_a[..32].copy_from_slice(rho);
            seed_a[32] = i as u8;
            seed_a[33] = j as u8;
            xof(&seed_a, xof_out.len(), &mut xof_out);
            sample_ntt(&xof_out, &mut a[i][j]);
        }
    }

    let mut s = [Poly::new(); K];
    let mut e = [Poly::new(); K];
    let mut nonce = 0;
    for i in 0..K {
        let mut prf_out = [0u8; 128];
        prf(sigma, nonce, &mut prf_out);
        cbd(&prf_out, &mut s[i]);
        nonce += 1;
    }
    for i in 0..K {
        let mut prf_out = [0u8; 128];
        prf(sigma, nonce, &mut prf_out);
        cbd(&prf_out, &mut e[i]);
        nonce += 1;
    }

    for i in 0..K {
        s[i].ntt();
        e[i].ntt();
    }

    let mut pk_poly = [Poly::new(); K];
    for i in 0..K {
        for j in 0..K {
            let mut tmp = a[i][j];
            tmp.pointwise_mul(&s[j]);
            pk_poly[i].add(&tmp);
        }
        pk_poly[i].add(&e[i]);
        pk_poly[i].inv_ntt();
    }

    for i in 0..K {
        poly_to_bytes(&pk_poly[i], &mut pk[i * POLY_BYTES..]);
    }
    pk[K * POLY_BYTES..].copy_from_slice(rho);

    for i in 0..K {
        poly_to_bytes(&s[i], &mut sk[i * POLY_BYTES..]);
    }
}
