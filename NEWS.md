# mx.crypto 0.2.0.1

* `tools/configure.R` now always passes `--target` on Windows and picks
  the triple from the running R: `aarch64-pc-windows-gnullvm` on ARM64,
  `x86_64-pc-windows-gnullvm` for clang-compiled R, `i686-pc-windows-gnu`
  on 32-bit, `x86_64-pc-windows-gnu` otherwise. Fixes the build on
  Windows ARM64. Thanks to Jeroen Ooms (#3).
* CI: Linux leg uses the `rapt` backend for r2u binary installs.
* CI: added an opt-in `r-universe` workflow covering Windows ARM64,
  Linux ARM64, macOS Intel, and Wasm. Runs weekly, on demand, and on
  pull requests touching `src/` or `tools/configure.R`.

# mx.crypto 0.2.0

* **HIGH** (security): `mxc_olm_create_outbound()` now propagates
  vodozemac's `SessionCreationError` instead of silently encoding a
  `Result` as a `Session` external pointer. The previous behavior
  meant a non-contributory Diffie-Hellman key (Soatok 2026-02
  disclosure, fixed in vodozemac 0.10.0 itself) returned a corrupt
  pointer that produced undefined behavior on use.
* New: `mxc_ed25519_verify()`, `mxc_verify_device_keys()`,
  `mxc_verify_one_time_key()` so callers can validate
  homeserver-supplied device-keys and signed one-time keys before
  using them. Hostile-fixture tests cover every rejection branch.
* New: `SECURITY.md` (threat model, pinned dependency status, pickle
  hygiene, known limitations).
* New: vignette `security-audit` walking the audit findings.
* DESCRIPTION: `mx.api (>= 0.1.0.1)` and `simplermarkdown` added to
  `Suggests`; `VignetteBuilder: simplermarkdown`.

# mx.crypto 0.1.0

* Initial release.
* Wraps the 'vodozemac' Rust crate (Matrix.org) for Olm + Megolm.
* Account: identity keys, one-time keys, fallback keys, signing,
  pickle / unpickle.
* Olm sessions: outbound and inbound creation, encrypt, decrypt,
  pickle / unpickle.
* Megolm group sessions: outbound (sender) and inbound (receiver)
  creation, encrypt, decrypt, pickle / unpickle.
* Pure crypto only; HTTP transport lives in the 'mx.api' package.
* Out of scope for 0.1.0: room-key requests / forwarded keys,
  cross-signing, SAS verification.
