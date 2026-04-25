# mx.encrypt

Olm + Megolm cryptographic ratchet primitives for Matrix, wrapping
`vodozemac` (Matrix.org's pure-Rust crypto crate). Pairs with
[`mx.api`](https://github.com/cornball-ai/mx.api), which handles HTTP
transport.

mx.encrypt is crypto only. It does not make HTTP calls, does not
canonicalise JSON, and does not implement room-key requests,
cross-signing, or SAS verification (yet).

## Install

Requires a working Rust toolchain (`cargo`, `rustc >= 1.85`).
On Ubuntu: `sudo apt install rustc cargo`. On macOS: `brew install rust`.
Or `rustup` from <https://rustup.rs>.

```r
install.packages("mx.encrypt")
```

From source:

```r
install.packages("mx.encrypt", type = "source")
```

## Quick start

```r
library(mx.encrypt)

# Two devices want to talk
alice <- mxe_account_new()
bob   <- mxe_account_new()

# Bob publishes a one-time key
mxe_account_generate_one_time_keys(bob, 1L)
bob_otks <- mxe_account_one_time_keys(bob)
bob_idk  <- mxe_account_identity_keys(bob)

# Alice starts an Olm session to Bob using one of Bob's OTKs
sess_a <- mxe_olm_create_outbound(alice,
                                  peer_curve25519 = bob_idk$curve25519,
                                  peer_otk        = bob_otks[[1]])

# Alice encrypts a Megolm session key (pretend) and sends it via Olm
ct <- mxe_olm_encrypt(sess_a, charToRaw("hello"))

# Bob receives the prekey message, builds the matching session
result <- mxe_olm_create_inbound(bob,
                                 peer_curve25519 = mxe_account_identity_keys(alice)$curve25519,
                                 prekey_b64      = ct$body)
mxe_account_mark_published(bob)
rawToChar(result$plaintext)
#> "hello"
```

## Status

0.1.0 — initial release, GitHub only until CRAN submission. Tested on
Ubuntu 24.04 and macOS.

## License

MIT or Apache 2.0, at your option. The bundled `vodozemac` crate is
Apache 2.0; see `inst/NOTICE` and `inst/AUTHORS` for attribution of all
vendored Rust crates.
