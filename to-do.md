# rusty-kyber: Implementation Tracker

Status legend: [x] done, [ ] todo, [~] partial/in-progress

## Core primitives
- [ ] Pure-Rust Keccak/SHAKE XOF (SHAKE128/256)
- [ ] Uniform/centered binomial samplers (η=2/3)
- [ ] Polynomial ring type, add/sub/reduce
- [ ] NTT and InvNTT (core, native schedule)
- [ ] NTT pointwise multiply
- [ ] Montgomery reduction (mod q)
- [ ] Barrett reduction, modular arithmetic
- [ ] Compression/decompression of polynomials (compression factors)
- [ ] Matrix expansion A (from rho, per-level)
- [ ] Decomposition helpers: power2round, decompose, hint

## Packing/encoding
- [ ] Pack/unpack polynomials (4/5/10/11/12/13 bits)
- [ ] Pack/unpack public key (seedA || polyvec)
- [ ] Pack/unpack secret key (polyvec)
- [ ] Pack/unpack ciphertext
- [ ] Shared secret encode/decode

## KEM ops
- [ ] RNG integration (`rand_core`, `OsRng`)
- [ ] KeyGen: sample s, e, expand matrix, encode keys
- [ ] Encaps: generate random coins, encrypt, encode ct/ss
- [ ] Decaps: decrypt, validate, return ss

## KATs and testing
- [ ] KAT parser (NIST .rsp, byte-for-byte)
- [ ] End-to-end KATs (all three security levels)
- [ ] 100% unit/integration coverage
- [ ] Fuzz tests (packing/decoding, kem ops)

## API and ergonomics
- [ ] Public API structs (PublicKey, SecretKey, Ciphertext, SharedSecret)
- [ ] Serde derive for all public types
- [ ] Zeroize on SecretKey drop
- [ ] Finalize API: keygen/encaps/decaps (levels, context variants)
- [ ] Feature flags: std/no_std, per-level enable

## Portability and builds
- [ ] no_std readiness (feature-gated)
- [ ] wasm32 build/test
- [ ] Embedded targets (ARM64) build/test
- [ ] Reproducible builds

## Performance
- [ ] Benches (criterion) for keygen/encaps/decaps/NTT
- [ ] Micro-optimizations (NTT, poly arithmetic, batching)

## Security and auditability
- [ ] forbid(unsafe_code) baseline
- [ ] Constant-time audit (KEM ops, NTT)
- [ ] Side-channel notes; optional masking/hardening

## Docs & distribution
- [ ] README.md: overview, build, usage, security notes
- [ ] Rustdoc for every public API/type
- [ ] Licenses (MIT/Apache-2.0)
- [ ] Crates.io readiness, versioning, CI

---
