use std::fs::File;
use std::io::{BufRead, BufReader};
use hex;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::path::Path;

macro_rules! generate_kat_test {
    ($name:ident, $kyber_mod:ident, $kat_file:expr) => {
        #[test]
        fn $name() {
            use rusty_kyber::$kyber_mod::*;
            use rusty_kyber::params::$kyber_mod as kyber_params;

            let base_path = Path::new(env!("CARGO_MANIFEST_DIR"));
            let kat_path = base_path.join($kat_file);
            let file = File::open(kat_path).unwrap();
            let reader = BufReader::new(file);

            let mut seed = [0u8; 48];
            let mut pk_kat = [0u8; kyber_params::PUBLIC_KEY_BYTES];
            let mut sk_kat = [0u8; kyber_params::SECRET_KEY_BYTES];
            let mut ct_kat = [0u8; kyber_params::CIPHERTEXT_BYTES];
            let mut ss_kat = [0u8; kyber_params::SHARED_SECRET_BYTES];

            for line in reader.lines() {
                let line = line.unwrap();
                let parts: Vec<&str> = line.split(" = ").collect();
                if parts.len() == 2 {
                    match parts[0] {
                        "seed" => seed.copy_from_slice(&hex::decode(parts[1]).unwrap()),
                        "pk" => pk_kat.copy_from_slice(&hex::decode(parts[1]).unwrap()),
                        "sk" => sk_kat.copy_from_slice(&hex::decode(parts[1]).unwrap()),
                        "ct" => ct_kat.copy_from_slice(&hex::decode(parts[1]).unwrap()),
                        "ss" => {
                            ss_kat.copy_from_slice(&hex::decode(parts[1]).unwrap());

                            let mut rng = ChaCha20Rng::from_seed(seed[..32].try_into().unwrap());
                            let (pk, sk): (PublicKey, SecretKey) = keypair(&mut rng);
                            assert_eq!(pk_kat, pk.as_bytes());
                            assert_eq!(sk_kat, sk.as_bytes());

                            let (ct, ss): (Ciphertext, SharedSecret) = encaps(&mut rng, &pk);
                            assert_eq!(ct_kat, ct.as_bytes());
                            assert_eq!(ss_kat, ss.as_bytes());

                            let ss2: SharedSecret = decaps(&sk, &ct);
                            assert_eq!(ss_kat, ss2.as_bytes());
                        }
                        _ => (),
                    }
                }
            }
        }
    };
}

#[cfg(feature = "kyber512")]
generate_kat_test!(kyber512_kat, kyber512, "KAT/kyber512.rsp");
#[cfg(feature = "kyber768")]
generate_kat_test!(kyber768_kat, kyber768, "tests/kat_vectors/kyber768.rsp");
#[cfg(feature = "kyber1024")]
generate_kat_test!(kyber1024_kat, kyber1024, "tests/kat_vectors/kyber1024.rsp");
