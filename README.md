# mx.crypto

Olm + Megolm cryptographic ratchet primitives for Matrix, wrapping
[`vodozemac`](https://github.com/matrix-org/vodozemac) (Matrix.org's
pure-Rust crypto crate). Pairs with
[`mx.api`](https://github.com/cornball-ai/mx.api), which handles HTTP
transport.

mx.crypto is crypto only. It does not make HTTP calls, does not
canonicalise JSON, and does not implement cross-signing or SAS
verification (yet).

## Install

Requires a working Rust toolchain (`cargo`, `rustc >= 1.85`).
On Ubuntu: `sudo apt install rustc cargo`. On macOS: `brew install rust`.
Or `rustup` from <https://rustup.rs>.

```r
# GitHub only for now; not on CRAN yet.
remotes::install_github("cornball-ai/mx.crypto")
```

## Quick start: encrypt then decrypt

```r
library(mx.crypto)

# Two devices want to talk
alice <- mxc_account_new()
bob   <- mxc_account_new()

# Bob publishes a one-time key
mxc_account_generate_one_time_keys(bob, 1L)
bob_otks <- mxc_account_one_time_keys(bob)
bob_idk  <- mxc_account_identity_keys(bob)

# Alice opens an Olm session to Bob using one of Bob's OTKs
sess_a <- mxc_olm_create_outbound(
    alice,
    peer_curve25519 = bob_idk$curve25519,
    peer_otk        = bob_otks[[1]]
)

# Alice encrypts; the first message is a pre-key (type 0)
ct <- mxc_olm_encrypt(sess_a, charToRaw("hello"))

# Bob accepts the pre-key, builds the matching inbound session, and
# decrypts in one step
result <- mxc_olm_create_inbound(
    bob,
    peer_curve25519 = mxc_account_identity_keys(alice)$curve25519,
    prekey_b64      = ct$body
)
mxc_account_mark_published(bob)
rawToChar(result$plaintext)
#> [1] "hello"
```

## Verifying homeserver-supplied keys

Real Matrix flows pull device keys and one-time keys from a homeserver
that you cannot fully trust. Verify before you use them:

```r
# After mx.api::mx_keys_query(...) returns a device_keys entry:
keys <- mxc_verify_device_keys(
    device_keys = dk,
    expected_user_id = "@alice:example.org",
    expected_device_id = "ALICEDEV"
)
# `keys` is list(curve25519 = "...", ed25519 = "..."), only present if
# the device's self-signature checked out and its algorithms list
# advertises Olm + Megolm.

# After mx.api::mx_keys_claim(...) returns a signed OTK:
otk <- mxc_verify_one_time_key(
    algorithm_key_id   = "signed_curve25519:AAAA",
    key_object         = signed_otk_obj,
    signing_ed25519    = keys$ed25519,
    expected_user_id   = "@alice:example.org",
    expected_device_id = "ALICEDEV"
)
# `otk` is the verified curve25519 OTK string, ready to feed into
# mxc_olm_create_outbound().
```

Both helpers fail closed: any structural problem, signer mismatch, or
signature-bytes mismatch raises a clear error.
**Identity pinning** (TOFU on first contact + cross-signing) lives
above this layer.

## Status

**0.2.0** (GitHub `main`, 2026-05-13). Not on CRAN yet.

- 0.1.0 was the initial release, GitHub-only.
- 0.2.0 adds `mxc_ed25519_verify` and the two `mxc_verify_*` helpers,
  fixes a latent memory-safety bug in `mxc_olm_create_outbound`
  (`SessionCreationError` is now propagated to R rather than silently
  encoded as a `Session` external pointer), and ships an audit
  vignette + `SECURITY.md`. See `NEWS.md` for the full changelog.

Tested on Ubuntu 24.04 and macOS via the GitHub Actions r-ci workflow,
plus a live homeserver round-trip exercise at
`inst/integration/e2e_demo.R`.

## Security

- `SECURITY.md` (repo root) covers the threat model, the pinned
  vodozemac version, pickle hygiene, and known limitations.
- `vignette("security-audit", package = "mx.crypto")` walks the
  2026-05 audit against the Soatok disclosure, with reproducers and
  fixes.
- Vulnerability reports: email **troy@cornball.ai**.

## License

MIT or Apache 2.0, at your option. The bundled `vodozemac` crate is
Apache 2.0; see `inst/NOTICE` and `inst/AUTHORS` for attribution of all
vendored Rust crates.
