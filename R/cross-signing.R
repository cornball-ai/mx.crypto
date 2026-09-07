# Cross-signing needs independent Ed25519 keypairs for the master,
# self-signing and user-signing roles. vodozemac's Account is the package's
# existing audited Ed25519 signer and encrypted-pickle carrier, so these
# wrappers deliberately expose only that part of it. The unused Curve25519
# identity is an implementation detail and never leaves this layer.

#' Create a durable Ed25519 signing key
#'
#' Creates a key suitable for a Matrix cross-signing role. Persist it with
#' [mxc_signing_key_pickle()]; the private material never needs to be exposed
#' as a string or raw vector.
#'
#' @return An opaque signing-key handle.
#' @export
mxc_signing_key_new <- function() {
  mxc_account_new()
}

#' Read a signing key's public Ed25519 key
#'
#' @param key A signing-key handle.
#' @return Unpadded base64 Ed25519 public key.
#' @export
mxc_signing_key_public <- function(key) {
  mxc_account_identity_keys(key)$ed25519
}

#' Sign canonical JSON with a signing key
#'
#' @param key A signing-key handle.
#' @param canonical_json A canonical JSON character string.
#' @return Unpadded base64 Ed25519 signature.
#' @export
mxc_signing_key_sign <- function(key, canonical_json) {
  mxc_account_sign(key, canonical_json)
}

#' Encrypt and pickle a signing key
#'
#' Uses the same vodozemac pickle encryption as an Olm account. Although the
#' carrier also contains an unused Curve25519 identity, only the Ed25519 key
#' is part of the signing-key contract.
#'
#' @param key A signing-key handle.
#' @param pickle_key A 32-byte raw encryption key.
#' @return Encrypted base64 pickle.
#' @export
mxc_signing_key_pickle <- function(key, pickle_key) {
  mxc_account_pickle(key, pickle_key)
}

#' Restore an encrypted signing key pickle
#'
#' @param blob An encrypted pickle from [mxc_signing_key_pickle()].
#' @param pickle_key The same 32-byte raw encryption key.
#' @return An opaque signing-key handle.
#' @export
mxc_signing_key_unpickle <- function(blob, pickle_key) {
  mxc_account_unpickle(blob, pickle_key)
}
