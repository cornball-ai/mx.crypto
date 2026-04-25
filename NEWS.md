# mx.encrypt 0.1.0

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
