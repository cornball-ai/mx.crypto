# cran-comments.md

## Submission summary

Minor release, 0.2.2 -> 0.3.0. It adds two exports and fixes one bug.
No export was removed or renamed and no existing signature changed.

* New: `mxc_attachment_encrypt()` and `mxc_attachment_decrypt()`
  implement Matrix v2 attachment encryption (AES-256-CTR with a fresh
  key and nonce per file, SHA-256 verified before decryption). Both are
  pure functions over raw vectors; they perform no HTTP requests and
  write no files.
* Fix: `mxc_olm_create_inbound()` and `mxc_olm_decrypt()` rejected Olm
  message bodies encoded as unpadded base64, which is what current
  Matrix clients built on 'vodozemac' send. Both now accept padded and
  unpadded bodies.

## Bundled Rust crates

`src/rust/Cargo.toml` now names `aes` 0.8.4, `ctr` 0.9.2, and `rand`
0.8 as direct dependencies. `aes` and `rand` were already vendored as
dependencies of 'vodozemac'. `ctr` 0.9.2 is the one crate new to
`src/rust/vendor.tar.xz`; it is a RustCrypto crate under
MIT OR Apache-2.0, credited in `inst/AUTHORS`. The source tarball is
5.7 MB, about the size of 0.2.2.

## Test environments

* local: Ubuntu 24.04, R 4.6.1, rustc 1.97.1
* GitHub Actions (ubuntu-latest, macos-latest) via r-ci, R-release
* r-universe reusable build: Linux x86_64 and arm64, Windows x86_64
  and arm64, macOS arm64 and Intel, and Wasm, across R-release,
  R-devel, and R-oldrel
* win-builder R-release (R 4.6.2): Status: OK

## R CMD check --as-cran results

```
Status: 1 NOTE
```

### NOTE: rustc release-profile compile flag

```
* checking compilation flags used ... NOTE
Compilation used the following non-portable flag(s):
  '-mno-omit-leaf-frame-pointer'
```

Emitted by `rustc`'s release profile and outside the package's control.
This is the same NOTE 0.2.0 through 0.2.2 were accepted with, and the
same one other Rust-using CRAN packages (e.g. `salso`) carry. The other
flags that appear in this NOTE on some hosts (`-Wdate-time`,
`-Werror=format-security`, `-Wformat`) are R's own Debian-style
hardening defaults passing through unchanged.

## Reverse dependencies

Three CRAN packages list 'mx.crypto' in Suggests: 'mx.client',
'chat.api', and 'corteza'. I maintain all three. I checked the CRAN
source of each against 0.3.0:

* 'mx.client' 0.2.1: OK
* 'chat.api' 0.1.0: OK
* 'corteza' 0.7.1: 2562 of 2563 tests pass. The one failure
  (`test_cli_helpers.R`, a default model name) occurs identically on
  my machine with 'mx.crypto' 0.2.2.2 installed, and 'corteza' makes no
  calls to 'mx.crypto'.

## SystemRequirements

Unchanged: `Cargo (Rust's package manager), rustc (>= 1.85)`. The MSRV
matches `vodozemac`'s upstream `rust-version`. `tools/configure.R`
checks the rustc version before invoking cargo and fails fast with a
clear message if MSRV is unmet.

## Build behaviour

Unchanged from 0.2.2:

* `tools/configure.R` extracts `src/rust/vendor.tar.xz` to
  `src/rust/vendor/`, writes `src/rust/.cargo/config.toml` (capped at
  `jobs = 2` per CRAN policy), and points `CARGO_HOME` at a
  package-local directory so cargo never writes to `~/.cargo`.
* No network access is required at build time.
* No `.so` is shipped; the static library is built from vendored
  sources and linked into the package shared object.
* `cleanup` removes all generated build artefacts.

## Licensing

Unchanged from 0.2.2. The bundled `vodozemac` crate is Apache-2.0;
attribution is in `inst/AUTHORS` and `inst/NOTICE`. The R package is
dual-licensed `MIT + file LICENSE | Apache License 2.0`. `Authors@R`
credits `cornball.ai` (cph), `The Matrix.org Foundation C.I.C.`
(ctb, cph) for the vendored crate, and a generic entry for the
transitive crate authors named in their own `Cargo.toml` files.
