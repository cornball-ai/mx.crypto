# cran-comments.md

## Submission summary

This is a new submission. mx.crypto is an R wrapper around the
`vodozemac` Rust crate (Matrix.org), exposing Olm and Megolm
cryptographic ratchet primitives. It pairs with the existing CRAN
package `mx.api`, which handles Matrix HTTP transport.

This is also my first CRAN submission of a Rust-using package. I've
followed the cargo-framework / salso layout that the CRAN reviewers
have accepted from David Dahl's packages. Happy to adjust anything
the reviewer would prefer different.

## Test environments

* local: Ubuntu 24.04, R 4.5.3, rustc 1.91.1 (via apt)
* GitHub Actions (ubuntu-latest, macos-latest) via r-ci, R-release,
  rustc 1.85 (rustup minimal toolchain)
* win-builder R-devel and R-release (`tinypkgr::check_win_devel()`)

## R CMD check --as-cran results

```
Status: 2 NOTEs
```

### NOTE 1: New submission, tarball size

```
* checking CRAN incoming feasibility ... NOTE
Maintainer: 'Troy Hernandez <troy@cornball.ai>'
New submission
```

The tarball weighs ~5.7 MB, dominated by `src/rust/vendor.tar.xz`
(~5.4 MB) which is the xz-compressed vendored Rust dependencies of
`vodozemac`. This is the standard layout for cargo-framework
Rust-on-CRAN packages (e.g. `salso`). Vendoring is required because
`cargo` cannot reach the internet during the CRAN build.

### NOTE 2: rustc release-profile compile flag

```
* checking compilation flags used ... NOTE
Compilation used the following non-portable flag(s):
  '-mno-omit-leaf-frame-pointer'
```

This flag is emitted by `rustc`'s release profile and is outside the
package's control. It is the same NOTE that other Rust-using CRAN
packages (e.g. `salso`) ship with. The other flags that show up in
this NOTE on some hosts (`-Wdate-time`, `-Werror=format-security`,
`-Wformat`) are R's own Debian-style hardening defaults that pass
through unchanged.

## SystemRequirements

`Cargo (Rust's package manager), rustc (>= 1.85)`. The MSRV matches
`vodozemac`'s upstream `rust-version` field. `tools/configure.R`
verifies the rustc version before invoking cargo and fails fast if
MSRV is unmet, so users see a clear error rather than a cryptic build
failure.

## Build behaviour

* `tools/configure.R` extracts `src/rust/vendor.tar.xz` to
  `src/rust/vendor/`, writes `src/rust/.cargo/config.toml` (capped at
  `jobs = 2` per CRAN policy), and points `CARGO_HOME` to a
  package-local directory so cargo never writes to `~/.cargo`.
* `cleanup` removes all generated build artefacts.
* No network access is required at build time.
* No `.so` is shipped; the static library is built from vendored
  sources and linked into the package shared object.
* No scripts run outside the package directory.

## Security audit

Before submission I walked an audit against
[Soatok's 2026-02 disclosure of cryptographic issues in vodozemac](https://soatok.blog/2026/02/17/cryptographic-issues-in-matrixs-rust-library-vodozemac/).
The headline finding (non-contributory Diffie-Hellman acceptance) was
already fixed upstream in vodozemac 0.10.0; the audit also caught a
latent memory-safety bug in `mxc_olm_create_outbound` (swallowed
`SessionCreationError`) and added the missing ed25519 signature
verification surface so callers can validate homeserver-supplied
device-keys and one-time keys before using them. The audit
walkthrough ships as `vignette("security-audit")` so the reasoning
is reviewable. `SECURITY.md` (excluded from the tarball) gives the
GitHub-facing summary.

## Reverse dependencies

None on CRAN.

## Notes for the CRAN team

* The bundled `vodozemac` crate is Apache-2.0 licensed; full
  attribution is in `inst/AUTHORS` and `inst/NOTICE`. The R package
  itself is dual-licensed `MIT + file LICENSE | Apache License 2.0`.
* `Authors@R` includes `cornball.ai` (cph) for the package
  copyright, `The Matrix.org Foundation C.I.C.` (ctb, cph) for the
  vendored crate, and a generic "Authors of the dependency Rust
  crates" (ctb) for transitive crate authors named in their
  individual `Cargo.toml` files.
* `Suggests: mx.api (>= 0.2.0)` is satisfied by mx.api 0.2.0
  (submitted in parallel; needed only by `mxc_verify_device_keys()`
  / `mxc_verify_one_time_key()` for the canonical-JSON encoder, and
  by the integration script under `inst/integration/`).
