use crate::params::{PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, CIPHERTEXT_BYTES, SHARED_SECRET_BYTES};
use crate::keygen::indcpa_keypair;
use crate::encaps::indcpa_enc;
use crate::decaps::indcpa_dec;
use crate::utils::{h, g, kdf};
use rand_core::{RngCore, CryptoRng};

pub fn keygen<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &mut [u8; PUBLIC_KEY_BYTES],
    sk: &mut [u8; SECRET_KEY_BYTES],
) {
    indcpa_keypair(rng, pk, sk);
    let mut h_pk = [0u8; 32];
    h(pk, &mut h_pk);
    sk[SECRET_KEY_BYTES - 64..SECRET_KEY_BYTES - 32].copy_from_slice(pk);
    sk[SECRET_KEY_BYTES - 32..].copy_from_slice(&h_pk);
}

pub fn encaps<R: RngCore + CryptoRng>(
    rng: &mut R,
    pk: &[u8; PUBLIC_KEY_BYTES],
    ss: &mut [u8; SHARED_SECRET_BYTES],
    ct: &mut [u8; CIPHERTEXT_BYTES],
) {
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);

    let mut h_pk = [0u8; 32];
    h(pk, &mut h_pk);

    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m);
    g_in[32..].copy_from_slice(&h_pk);
    let mut g_out = [0u8; 64];
    g(&g_in, &mut g_out);
    let (k, coins) = g_out.split_at(32);

    indcpa_enc(pk, &m, coins.try_into().unwrap(), ct);

    let mut kdf_in = [0u8; 64];
    kdf_in[..32].copy_from_slice(k);
    kdf_in[32..].copy_from_slice(ct);
    kdf(&kdf_in, ss);
}

pub fn decaps(
    sk: &[u8; SECRET_KEY_BYTES],
    ct: &[u8; CIPHERTEXT_BYTES],
    ss: &mut [u8; SHARED_SECRET_BYTES],
) {
    let mut m = [0u8; 32];
    indcpa_dec(sk, ct, &mut m);

    let pk = &sk[SECRET_KEY_BYTES - 64..SECRET_KEY_BYTES - 32];
    let h_pk = &sk[SECRET_KEY_BYTES - 32..];

    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m);
    g_in[32..].copy_from_slice(h_pk);
    let mut g_out = [0u8; 64];
    g(&g_in, &mut g_out);
    let (k, coins) = g_out.split_at(32);

    let mut ct2 = [0u8; CIPHERTEXT_BYTES];
    indcpa_enc(pk.try_into().unwrap(), &m, coins.try_into().unwrap(), &mut ct2);

    let mut kdf_in = [0u8; 64];
    if ct == &ct2 {
        kdf_in[..32].copy_from_slice(k);
        kdf_in[32..].copy_from_slice(ct);
    } else {
        kdf_in[..32].copy_from_slice(&sk[SECRET_KEY_BYTES - 96..SECRET_KEY_BYTES - 64]);
        kdf_in[32..].copy_from_slice(ct);
    }
    kdf(&kdf_in, ss);
}
