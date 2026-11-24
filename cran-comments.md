# cran-comments.md

## Submission summary

Patch release, 0.3.0 -> 0.3.1, in response to the CRAN check problems
on 0.3.0 (deadline 2026-12-01). Both changes are to the build only.
No R code, export, or signature changed.

* Fix: the r-devel Linux, Fedora, and M1mac checks reported that the
  vendored 'proc-macro-error2' 2.0.1 "contains code that will be
  rejected by a future version of Rust". The bundled 'matrix-pickle'
  and 'matrix-pickle-derive' crates move from 0.2.2 to 0.2.3, which no
  longer depend on it. 'proc-macro-error2' and 'proc-macro-error-attr2'
  are gone from `src/rust/vendor.tar.xz` and `Cargo.lock`.
* Fix: from rustc 1.100.0 the Rust standard library on Windows calls
  `WaitOnAddress` and `WakeByAddressSingle`/`WakeByAddressAll`.
  `src/Makevars.win` now links `-lsynchronization`; without it the
  Rtools link fails on the newest stable Rust.

## Test environments

* local: Ubuntu 24.04, R 4.6.1, rustc 1.97.1, `R CMD check --as-cran`
  including the PDF manual
* local: the vendored crates built with rustc 1.100.0-nightly;
  `cargo report future-incompatibilities` reports nothing
* GitHub Actions: macOS and Ubuntu on stable rustc, Ubuntu on rustc
  1.85 (the MSRV), and Windows (Rtools 4.5) on rustc 1.100.0. Each leg
  fails on any warning in the install log, not only the ones
  R CMD check reports.
* r-universe: Linux x86_64 and arm64, Windows x86_64 and arm64, macOS
  arm64 and Intel, and Wasm, across R-release, R-devel, and R-oldrel
* win-builder R-devel (2026-11-17 r90926 ucrt) and R-release (4.6.2),
  both rustc 1.92.0: Status: OK. These ran on 0.3.0.2, whose sources
  match 0.3.1; only DESCRIPTION, NEWS.md, and this file changed since.

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
This is the same NOTE 0.2.0 through 0.3.0 were accepted with, and the
same one other Rust-using CRAN packages (e.g. `salso`) carry.

## Reverse dependencies

Three CRAN packages list 'mx.crypto' in Suggests: 'mx.client',
'chat.api', and 'corteza'. I maintain all three. This release changes
no R code, so their behaviour against 'mx.crypto' is unchanged from
0.3.0.

## SystemRequirements

Unchanged: `Cargo (Rust's package manager), rustc (>= 1.85)`.
`tools/configure.R` checks the rustc version before invoking cargo and
fails fast with a clear message if the minimum is unmet.

## Build behaviour

Unchanged from 0.3.0:

* `tools/configure.R` extracts `src/rust/vendor.tar.xz` to
  `src/rust/vendor/`, writes `src/rust/.cargo/config.toml` (capped at
  `jobs = 2` per CRAN policy), and points `CARGO_HOME` at a
  package-local directory so cargo never writes to `~/.cargo`.
* No network access is required at build time.
* No `.so` is shipped; the static library is built from vendored
  sources and linked into the package shared object.
* `cleanup` removes all generated build artefacts.

## Licensing

Unchanged from 0.3.0. The bundled `vodozemac` crate is Apache-2.0;
attribution is in `inst/AUTHORS` and `inst/NOTICE`. The R package is
dual-licensed `MIT + file LICENSE | Apache License 2.0`. `Authors@R`
credits `cornball.ai` (cph), `The Matrix.org Foundation C.I.C.`
(ctb, cph) for the vendored crate, and a generic entry for the
transitive crate authors named in their own `Cargo.toml` files.
