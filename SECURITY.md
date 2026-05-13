# Security

## Reporting

Email **troy@cornball.ai** with anything that looks like a vulnerability.
Please do not file a public GitHub issue first.

## Threat model

`mx.crypto` is a primitives wrapper around vodozemac. It assumes:

- A homeserver may be malicious. Anything that comes back from
  `/keys/query`, `/keys/claim`, or `/sync` is untrusted until verified.
- A remote device may be compromised. Signed material can satisfy
  structural checks but originate from the wrong identity. Identity
  pinning (TOFU + cross-signing) belongs to a higher layer.
- A buggy or hostile peer can ship malformed ciphertext or pre-key
  messages. `mx.crypto` fails closed: errors propagate, no partial
  state mutation, no ambiguous return values.

## Pinned dependency

| Component | Version | Status |
|---|---|---|
| vodozemac | 0.10.0 | Contains the fix for the Soatok 2026-02 disclosure of non-contributory Diffie-Hellman acceptance. Verified in the vendored source at `src/types/curve25519.rs`. |

The full audit walkthrough is in `vignettes/security-audit.Rmd`.

## What this package validates

- ed25519 signatures via `mxc_ed25519_verify` (uses vodozemac's
  `verify_strict` — laxer fuzzing paths are not compiled in).
- Device-keys structural + self-signature consistency via
  `mxc_verify_device_keys`.
- Signed one-time keys via `mxc_verify_one_time_key`.

## What this package does NOT validate

- **Identity pinning.** `mxc_verify_device_keys` returns the ed25519
  key the device claims for itself; it does not check that key
  against any pre-known trust store. Pin identities at a higher
  layer.
- **Cross-signing.** Master / self / user signing keys are out of
  scope.
- **SAS verification.** Out of scope.
- **Replay across pickles.** Restoring a stale pickle is the caller's
  responsibility to detect.

## Pickle hygiene

`mxc_*_pickle()` encrypts state under a caller-supplied 32-byte raw
key. vodozemac's pickle format uses a deterministic IV. Practical
implications:

- Use **one pickle key per Account / Session.** Reusing one key across
  many unrelated pickles can leak ordering / equality information.
- Derive the key with a KDF from a passphrase you actually have.
  Don't pass a passphrase directly.
- Treat the pickle blob like any other ciphertext: at-rest storage,
  no plaintext logging.

## Known limitations (tracked, not yet fixed here)

- Olm v1 MAC (Soatok's downgrade finding): the wire-format MAC
  versioning lives below `mx.crypto`. Track the upstream v2 migration.
- The `e2e_demo.R` integration script currently does NOT call
  `mxc_verify_device_keys` / `mxc_verify_one_time_key` in its
  broadcast loop. That follow-up is captured in the vignette
  (section 11). New callers should always call the verify helpers
  before opening sessions.

## Bumping vodozemac

When pulling a new vodozemac into the vendor tarball, re-read
`vignettes/security-audit.Rmd` section 2 and confirm the
contributory-DH check and strict-Ed25519 default are still in place.
Add a `NEWS.md` line noting the bump.
