# cran-comments.md

## Submission summary

This is a new submission. mx.crypto is an R wrapper around the
`vodozemac` Rust crate (Matrix.org), exposing Olm and Megolm
cryptographic ratchet primitives. It pairs with the existing CRAN
package `mx.api`, which handles Matrix HTTP transport.

## Test environments

* local: Ubuntu 24.04, R 4.5.x, rustc 1.91.1
* GitHub Actions ci.yaml: Ubuntu-latest and macOS-latest, R-release,
  rustc 1.85.0 (rustup minimal toolchain)

## R CMD check --as-cran results

```
Status: 2 NOTEs
```

### NOTE 1: New submission, tarball size

```
* checking CRAN incoming feasibility ... NOTE
Maintainer: 'Troy Hernandez <troy@cornball.ai>'
New submission
Size of tarball: ~5.7 MB
```

The tarball is dominated by `src/rust/vendor.tar.xz` (~5.4 MB), the
xz-compressed vendored Rust dependencies of `vodozemac`. This is the
standard layout for cargo-framework Rust-on-CRAN packages (e.g.,
`salso`). Vendoring is required because cargo cannot reach the
internet during CRAN build.

### NOTE 2: rustc release-profile compile flag

```
* checking compilation flags used ... NOTE
Compilation used the following non-portable flag(s):
  '-mno-omit-leaf-frame-pointer'
```

This flag is emitted by `rustc`'s release profile and is outside the
package's control. It is the same NOTE that other Rust-using CRAN
packages (e.g., `salso`) ship with.

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
* No `.so`, no helper binaries, no scripts are run outside the
  package directory.

## Reverse dependencies

None (new package).

## Notes for the CRAN team

* The bundled `vodozemac` crate is Apache-2.0 licensed; full
  attribution is in `inst/AUTHORS` and `inst/NOTICE`. The R package
  itself is dual-licensed `MIT + file LICENSE | Apache License 2.0`.
* The `Authors@R` field includes `cornball.ai` (cph) for the package
  copyright and `The Matrix.org Foundation C.I.C.` (ctb, cph) for the
  vendored crate, plus a generic "Authors of the dependency Rust
  crates" (ctb) for transitive crate authors.
