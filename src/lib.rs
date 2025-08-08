pub mod params;
pub mod poly;
pub mod ntt;
pub mod utils;
pub mod kem;
pub mod keygen;
pub mod encaps;
pub mod decaps;

#[cfg(feature = "kyber512")]
pub use kyber512::{
    keypair, encaps, decaps, PublicKey, SecretKey, Ciphertext, SharedSecret,
};
#[cfg(feature = "kyber768")]
pub use kyber768::{
    keypair, encaps, decaps, PublicKey, SecretKey, Ciphertext, SharedSecret,
};
#[cfg(feature = "kyber1024")]
pub use kyber1024::{
    keypair, encaps, decaps, PublicKey, SecretKey, Ciphertext, SharedSecret,
};

#[cfg(feature = "kyber512")]
pub mod kyber512 {
    use super::*;
    use crate::params::kyber512 as kyber_params;
    use zeroize::Zeroize;
    use rand_core::{RngCore, CryptoRng};

    #[derive(Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicKey([u8; kyber_params::PUBLIC_KEY_BYTES]);

    #[derive(Clone, Copy, Zeroize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SecretKey([u8; kyber_params::SECRET_KEY_BYTES]);

    #[derive(Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Ciphertext([u8; kyber_params::CIPHERTEXT_BYTES]);

    #[derive(Clone, Copy, Zeroize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SharedSecret([u8; kyber_params::SHARED_SECRET_BYTES]);

    impl From<[u8; kyber_params::PUBLIC_KEY_BYTES]> for PublicKey {
        fn from(bytes: [u8; kyber_params::PUBLIC_KEY_BYTES]) -> Self {
            PublicKey(bytes)
        }
    }

    impl From<PublicKey> for [u8; kyber_params::PUBLIC_KEY_BYTES] {
        fn from(pk: PublicKey) -> Self {
            pk.0
        }
    }

    impl PublicKey {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::SECRET_KEY_BYTES]> for SecretKey {
        fn from(bytes: [u8; kyber_params::SECRET_KEY_BYTES]) -> Self {
            SecretKey(bytes)
        }
    }

    impl From<SecretKey> for [u8; kyber_params::SECRET_KEY_BYTES] {
        fn from(sk: SecretKey) -> Self {
            sk.0
        }
    }

    impl SecretKey {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::CIPHERTEXT_BYTES]> for Ciphertext {
        fn from(bytes: [u8; kyber_params::CIPHERTEXT_BYTES]) -> Self {
            Ciphertext(bytes)
        }
    }

    impl From<Ciphertext> for [u8; kyber_params::CIPHERTEXT_BYTES] {
        fn from(ct: Ciphertext) -> Self {
            ct.0
        }
    }

    impl Ciphertext {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::SHARED_SECRET_BYTES]> for SharedSecret {
        fn from(bytes: [u8; kyber_params::SHARED_SECRET_BYTES]) -> Self {
            SharedSecret(bytes)
        }
    }

    impl From<SharedSecret> for [u8; kyber_params::SHARED_SECRET_BYTES] {
        fn from(ss: SharedSecret) -> Self {
            ss.0
        }
    }

    impl SharedSecret {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    pub fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> (PublicKey, SecretKey) {
        let mut pk = [0u8; kyber_params::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; kyber_params::SECRET_KEY_BYTES];
        kem::keygen(rng, &mut pk, &mut sk);
        (PublicKey(pk), SecretKey(sk))
    }

    pub fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &PublicKey,
    ) -> (Ciphertext, SharedSecret) {
        let mut ct = [0u8; kyber_params::CIPHERTEXT_BYTES];
        let mut ss = [0u8; kyber_params::SHARED_SECRET_BYTES];
        kem::encaps(rng, &pk.0, &mut ss, &mut ct);
        (Ciphertext(ct), SharedSecret(ss))
    }

    pub fn decaps(
        sk: &SecretKey,
        ct: &Ciphertext,
    ) -> SharedSecret {
        let mut ss = [0u8; kyber_params::SHARED_SECRET_BYTES];
        kem::decaps(&sk.0, &ct.0, &mut ss);
        SharedSecret(ss)
    }
}

#[cfg(feature = "kyber768")]
pub mod kyber768 {
    use super::*;
    use crate::params::kyber768 as kyber_params;
    use zeroize::Zeroize;
    use rand_core::{RngCore, CryptoRng};

    #[derive(Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicKey([u8; kyber_params::PUBLIC_KEY_BYTES]);

    #[derive(Clone, Copy, Zeroize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SecretKey([u8; kyber_params::SECRET_KEY_BYTES]);

    #[derive(Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Ciphertext([u8; kyber_params::CIPHERTEXT_BYTES]);

    #[derive(Clone, Copy, Zeroize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SharedSecret([u8; kyber_params::SHARED_SECRET_BYTES]);

    impl From<[u8; kyber_params::PUBLIC_KEY_BYTES]> for PublicKey {
        fn from(bytes: [u8; kyber_params::PUBLIC_KEY_BYTES]) -> Self {
            PublicKey(bytes)
        }
    }

    impl From<PublicKey> for [u8; kyber_params::PUBLIC_KEY_BYTES] {
        fn from(pk: PublicKey) -> Self {
            pk.0
        }
    }

    impl PublicKey {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::SECRET_KEY_BYTES]> for SecretKey {
        fn from(bytes: [u8; kyber_params::SECRET_KEY_BYTES]) -> Self {
            SecretKey(bytes)
        }
    }

    impl From<SecretKey> for [u8; kyber_params::SECRET_KEY_BYTES] {
        fn from(sk: SecretKey) -> Self {
            sk.0
        }
    }

    impl SecretKey {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::CIPHERTEXT_BYTES]> for Ciphertext {
        fn from(bytes: [u8; kyber_params::CIPHERTEXT_BYTES]) -> Self {
            Ciphertext(bytes)
        }
    }

    impl From<Ciphertext> for [u8; kyber_params::CIPHERTEXT_BYTES] {
        fn from(ct: Ciphertext) -> Self {
            ct.0
        }
    }

    impl Ciphertext {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::SHARED_SECRET_BYTES]> for SharedSecret {
        fn from(bytes: [u8; kyber_params::SHARED_SECRET_BYTES]) -> Self {
            SharedSecret(bytes)
        }
    }

    impl From<SharedSecret> for [u8; kyber_params::SHARED_SECRET_BYTES] {
        fn from(ss: SharedSecret) -> Self {
            ss.0
        }
    }

    impl SharedSecret {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    pub fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> (PublicKey, SecretKey) {
        let mut pk = [0u8; kyber_params::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; kyber_params::SECRET_KEY_BYTES];
        kem::keygen(rng, &mut pk, &mut sk);
        (PublicKey(pk), SecretKey(sk))
    }

    pub fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &PublicKey,
    ) -> (Ciphertext, SharedSecret) {
        let mut ct = [0u8; kyber_params::CIPHERTEXT_BYTES];
        let mut ss = [0u8; kyber_params::SHARED_SECRET_BYTES];
        kem::encaps(rng, &pk.0, &mut ss, &mut ct);
        (Ciphertext(ct), SharedSecret(ss))
    }

    pub fn decaps(
        sk: &SecretKey,
        ct: &Ciphertext,
    ) -> SharedSecret {
        let mut ss = [0u8; kyber_params::SHARED_SECRET_BYTES];
        kem::decaps(&sk.0, &ct.0, &mut ss);
        SharedSecret(ss)
    }
}

#[cfg(feature = "kyber1024")]
pub mod kyber1024 {
    use super::*;
    use crate::params::kyber1024 as kyber_params;
    use zeroize::Zeroize;
    use rand_core::{RngCore, CryptoRng};

    #[derive(Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct PublicKey([u8; kyber_params::PUBLIC_KEY_BYTES]);

    #[derive(Clone, Copy, Zeroize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SecretKey([u8; kyber_params::SECRET_KEY_BYTES]);

    #[derive(Clone, Copy)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Ciphertext([u8; kyber_params::CIPHERTEXT_BYTES]);

    #[derive(Clone, Copy, Zeroize)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct SharedSecret([u8; kyber_params::SHARED_SECRET_BYTES]);

    impl From<[u8; kyber_params::PUBLIC_KEY_BYTES]> for PublicKey {
        fn from(bytes: [u8; kyber_params::PUBLIC_KEY_BYTES]) -> Self {
            PublicKey(bytes)
        }
    }

    impl From<PublicKey> for [u8; kyber_params::PUBLIC_KEY_BYTES] {
        fn from(pk: PublicKey) -> Self {
            pk.0
        }
    }

    impl PublicKey {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::SECRET_KEY_BYTES]> for SecretKey {
        fn from(bytes: [u8; kyber_params::SECRET_KEY_BYTES]) -> Self {
            SecretKey(bytes)
        }
    }

    impl From<SecretKey> for [u8; kyber_params::SECRET_KEY_BYTES] {
        fn from(sk: SecretKey) -> Self {
            sk.0
        }
    }

    impl SecretKey {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::CIPHERTEXT_BYTES]> for Ciphertext {
        fn from(bytes: [u8; kyber_params::CIPHERTEXT_BYTES]) -> Self {
            Ciphertext(bytes)
        }
    }

    impl From<Ciphertext> for [u8; kyber_params::CIPHERTEXT_BYTES] {
        fn from(ct: Ciphertext) -> Self {
            ct.0
        }
    }

    impl Ciphertext {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    impl From<[u8; kyber_params::SHARED_SECRET_BYTES]> for SharedSecret {
        fn from(bytes: [u8; kyber_params::SHARED_SECRET_BYTES]) -> Self {
            SharedSecret(bytes)
        }
    }

    impl From<SharedSecret> for [u8; kyber_params::SHARED_SECRET_BYTES] {
        fn from(ss: SharedSecret) -> Self {
            ss.0
        }
    }

    impl SharedSecret {
        pub fn as_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    pub fn keypair<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> (PublicKey, SecretKey) {
        let mut pk = [0u8; kyber_params::PUBLIC_KEY_BYTES];
        let mut sk = [0u8; kyber_params::SECRET_KEY_BYTES];
        kem::keygen(rng, &mut pk, &mut sk);
        (PublicKey(pk), SecretKey(sk))
    }

    pub fn encaps<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &PublicKey,
    ) -> (Ciphertext, SharedSecret) {
        let mut ct = [0u8; kyber_params::CIPHERTEXT_BYTES];
        let mut ss = [0u8; kyber_params::SHARED_SECRET_BYTES];
        kem::encaps(rng, &pk.0, &mut ss, &mut ct);
        (Ciphertext(ct), SharedSecret(ss))
    }

    pub fn decaps(
        sk: &SecretKey,
        ct: &Ciphertext,
    ) -> SharedSecret {
        let mut ss = [0u8; kyber_params::SHARED_SECRET_BYTES];
        kem::decaps(&sk.0, &ct.0, &mut ss);
        SharedSecret(ss)
    }
}
