# cran-comments.md

## Submission summary

Patch release, 0.2.0 -> 0.2.1. One user-visible change: it fixes the
build on Windows ARM64.

`tools/configure.R` previously decided whether to pass `--target` to
cargo by inspecting the host triple, and when it did cross-compile it
hard-coded `x86_64-pc-windows-gnu`. On the aarch64 Windows toolchain
that is the wrong target and the build fails. It now always passes
`--target` on Windows and selects the triple from the running R:

* `aarch64-pc-windows-gnullvm` when `R.version$platform` is aarch64
* `x86_64-pc-windows-gnullvm` when `R_COMPILED_BY` reports clang
* `i686-pc-windows-gnu` on 32-bit
* `x86_64-pc-windows-gnu` otherwise

The patch is from Jeroen Ooms (GitHub #3), who hit it building the CRAN
mirror universe. No R-level API change, no new or removed exports, and
no reverse dependencies on CRAN.

## Test environments

* local: Ubuntu 24.04, R 4.5.3, rustc 1.91.1
* GitHub Actions (ubuntu-latest, macos-latest) via r-ci, R-release
* r-universe reusable build: 15 configurations covering Linux x86_64
  and arm64, Windows x86_64 and arm64, macOS arm64 and Intel, and
  Wasm, across R-release, R-devel, and R-oldrel, including the two
  Windows arm64 legs this release exists to fix.
* win-builder R-devel

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
This is the same NOTE 0.2.0 was accepted with, and the same one other
Rust-using CRAN packages (e.g. `salso`) carry. The other flags that
appear in this NOTE on some hosts (`-Wdate-time`,
`-Werror=format-security`, `-Wformat`) are R's own Debian-style
hardening defaults passing through unchanged.

## SystemRequirements

Unchanged: `Cargo (Rust's package manager), rustc (>= 1.85)`. The MSRV
matches `vodozemac`'s upstream `rust-version`. `tools/configure.R`
checks the rustc version before invoking cargo and fails fast with a
clear message if MSRV is unmet.

## Build behaviour

Unchanged from 0.2.0:

* `tools/configure.R` extracts `src/rust/vendor.tar.xz` to
  `src/rust/vendor/`, writes `src/rust/.cargo/config.toml` (capped at
  `jobs = 2` per CRAN policy), and points `CARGO_HOME` at a
  package-local directory so cargo never writes to `~/.cargo`.
* No network access is required at build time.
* No `.so` is shipped; the static library is built from vendored
  sources and linked into the package shared object.
* `cleanup` removes all generated build artefacts.

## Licensing

Unchanged from 0.2.0. The bundled `vodozemac` crate is Apache-2.0;
attribution is in `inst/AUTHORS` and `inst/NOTICE`. The R package is
dual-licensed `MIT + file LICENSE | Apache License 2.0`. `Authors@R`
credits `cornball.ai` (cph), `The Matrix.org Foundation C.I.C.`
(ctb, cph) for the vendored crate, and a generic entry for the
transitive crate authors named in their own `Cargo.toml` files.
