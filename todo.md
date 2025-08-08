# To-Do List for `rusty-kyber`

## Core Implementation
- [x] Implement `params.rs` with constants for all security levels.
- [x] Implement `poly.rs` with polynomial arithmetic.
- [x] Implement `ntt.rs` with Number Theoretic Transform.
- [x] Implement `utils.rs` with serialization, hashing, and sampling functions.
- [x] Implement `keygen.rs` with IND-CPA key generation.
- [x] Implement `encaps.rs` with IND-CPA encapsulation.
- [x] Implement `decaps.rs` with IND-CPA decapsulation.
- [x] Implement `kem.rs` with KEM key generation, encapsulation, and decapsulation.
- [x] Implement `lib.rs` with the public API.

## Testing
- [ ] Pass all official NIST Kyber KATs at all security levels.
- [ ] Achieve 100% unit/integration test coverage.
- [ ] Implement fuzz tests.

## Build and Distribution
- [ ] Verify `no_std` builds.
- [ ] Verify WASM builds.
- [x] Add `LICENSE-MIT` and `LICENSE-APACHE`.
- [ ] Prepare for `crates.io` publication.

## Documentation
- [ ] Write Rustdoc for every public API/type.
- [ ] Write crate docs with usage and security notes.
- [ ] Update `README.md` with build instructions.

## Finalization
- [ ] Delete the `PQClean` directory.
