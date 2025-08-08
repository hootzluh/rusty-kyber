use crate::params::{K, PUBLIC_KEY_BYTES, CIPHERTEXT_BYTES, POLY_VEC_BYTES, POLY_BYTES, POLY_COMPRESSED_BYTES};
use crate::poly::Poly;
use crate::utils::{xof, prf, cbd, poly_to_bytes, poly_from_bytes, sample_ntt, poly_compress, poly_decompress};

pub fn indcpa_enc(
    pk: &[u8; PUBLIC_KEY_BYTES],
    msg: &[u8; 32],
    coins: &[u8; 32],
    ct: &mut [u8; CIPHERTEXT_BYTES],
) {
    let mut pk_poly = [Poly::new(); K];
    let mut r = [Poly::new(); K];
    let mut e1 = [Poly::new(); K];
    let mut e2 = Poly::new();
    let mut t = [Poly::new(); K];
    let mut u = [Poly::new(); K];
    let mut v = Poly::new();

    let rho = &pk[POLY_VEC_BYTES..];
    for i in 0..K {
        poly_from_bytes(&pk[i * POLY_BYTES..], &mut pk_poly[i]);
        t[i] = pk_poly[i];
        t[i].ntt();
    }

    let mut nonce = 0;
    for i in 0..K {
        let mut prf_out = [0u8; 128];
        prf(coins, nonce, &mut prf_out);
        cbd(&prf_out, &mut r[i]);
        nonce += 1;
    }
    for i in 0..K {
        let mut prf_out = [0u8; 128];
        prf(coins, nonce, &mut prf_out);
        cbd(&prf_out, &mut e1[i]);
        nonce += 1;
    }
    let mut prf_out = [0u8; 128];
    prf(coins, nonce, &mut prf_out);
    cbd(&prf_out, &mut e2);

    for i in 0..K {
        r[i].ntt();
    }

    let mut at = [[Poly::new(); K]; K];
    for i in 0..K {
        for j in 0..K {
            let mut xof_out = [0u8; 672];
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            seed[32] = j as u8;
            seed[33] = i as u8;
            xof(&seed, xof_out.len(), &mut xof_out);
            sample_ntt(&xof_out, &mut at[i][j]);
        }
    }

    for i in 0..K {
        for j in 0..K {
            let mut tmp = at[i][j];
            tmp.pointwise_mul(&r[j]);
            u[i].add(&tmp);
        }
        u[i].inv_ntt();
        u[i].add(&e1[i]);
    }

    for i in 0..K {
        let mut tmp = t[i];
        tmp.pointwise_mul(&r[i]);
        v.add(&tmp);
    }
    v.inv_ntt();
    v.add(&e2);

    let mut msg_poly = Poly::new();
    poly_from_bytes(msg, &mut msg_poly);
    v.add(&msg_poly);

    let mut u_bytes = [0u8; K * POLY_COMPRESSED_BYTES];
    for i in 0..K {
        poly_compress(&u[i], &mut u_bytes[i * POLY_COMPRESSED_BYTES..]);
    }
    let mut v_bytes = [0u8; POLY_COMPRESSED_BYTES];
    poly_compress(&v, &mut v_bytes);

    ct[..u_bytes.len()].copy_from_slice(&u_bytes);
    ct[u_bytes.len()..].copy_from_slice(&v_bytes);
}
