#' Create a new Olm Account
#'
#' Creates a fresh device identity. Holds long-lived curve25519 / ed25519
#' identity keys and a one-time-key pool. The returned object is an
#' external pointer; persist it with [mxc_account_pickle].
#'
#' @return An external pointer to a vodozemac Account.
#' @examples
#' acct <- mxc_account_new()
#' mxc_account_identity_keys(acct)
#' @export
mxc_account_new <- function() {
  .Call(.mxc_account_new)
}

#' Public identity keys for an Account
#'
#' Returns the device's two public keys: curve25519 (Olm sender / identity
#' key, used to start sessions) and ed25519 (signing / fingerprint key).
#' Both are unpadded base64 strings, ready for `/keys/upload`.
#'
#' @param account An Account from [mxc_account_new] or [mxc_account_unpickle].
#' @return A named list with `curve25519` and `ed25519` strings.
#' @examples
#' k <- mxc_account_identity_keys(mxc_account_new())
#' k$curve25519
#' @export
mxc_account_identity_keys <- function(account) {
  .Call(.mxc_account_identity_keys, account)
}

#' Sign canonical JSON with the Account's ed25519 key
#'
#' The caller must canonicalise the JSON per the Matrix spec
#' (UTF-8, sorted keys, no whitespace, no insignificant data) before
#' passing it in. mx.crypto does not canonicalise; mx.api will.
#'
#' @param account An Account.
#' @param canonical_json A character string containing canonical JSON.
#' @return Unpadded base64 ed25519 signature.
#' @examples
#' acct <- mxc_account_new()
#' sig <- mxc_account_sign(acct, '{"hello":"world"}')
#' @export
mxc_account_sign <- function(account, canonical_json) {
  .Call(.mxc_account_sign, account, as.character(canonical_json))
}

#' Generate one-time keys
#'
#' Adds `n` curve25519 one-time keys to the Account's pool. Call
#' [mxc_account_one_time_keys] to read them out for upload, then
#' [mxc_account_mark_published] once the homeserver has accepted them.
#'
#' @param account An Account.
#' @param n Number of OTKs to generate.
#' @return Invisible NULL; mutates `account` in place.
#' @examples
#' acct <- mxc_account_new()
#' mxc_account_generate_one_time_keys(acct, 5L)
#' @export
mxc_account_generate_one_time_keys <- function(account, n) {
  invisible(.Call(.mxc_account_generate_one_time_keys, account, as.integer(n)))
}

#' Read pending one-time keys
#'
#' Returns OTKs that have been generated but not yet marked as published.
#' Each value is a curve25519 public key; the caller should sign each
#' with [mxc_account_sign] and upload as `signed_curve25519:<key_id>`.
#'
#' @param account An Account.
#' @return Named list mapping `key_id` to `curve25519_pub` (both
#'   unpadded base64 strings).
#' @examples
#' acct <- mxc_account_new()
#' mxc_account_generate_one_time_keys(acct, 5L)
#' otks <- mxc_account_one_time_keys(acct)
#' @export
mxc_account_one_time_keys <- function(account) {
  .Call(.mxc_account_one_time_keys, account)
}

#' Mark current one-time keys as published
#'
#' Call after the homeserver has accepted a `/keys/upload` containing
#' the keys returned by [mxc_account_one_time_keys]. Future calls to
#' that function will not re-include them.
#'
#' @param account An Account.
#' @return Invisible NULL; mutates `account`.
#' @export
mxc_account_mark_published <- function(account) {
  invisible(.Call(.mxc_account_mark_published, account))
}

#' Generate and return a fallback key
#'
#' Generates a fallback curve25519 key, which the homeserver hands out
#' when an OTK pool is exhausted. Returns the freshly generated key.
#' Calling it again rotates the previous fallback.
#'
#' @param account An Account.
#' @return Named list with `key_id` and `curve25519` (both base64).
#' @export
mxc_account_fallback_key <- function(account) {
  .Call(.mxc_account_fallback_key, account)
}

#' Pickle an Account to an encrypted blob
#'
#' Serialises the Account's state and encrypts it under a 32-byte key.
#' Restore with [mxc_account_unpickle]. Pickle after every state change
#' that you want to survive a restart (OTK generation, fallback key
#' rotation, mark-published).
#'
#' @param account An Account.
#' @param key A `raw` vector of length 32. The caller is responsible for
#'   key derivation; use a KDF on a passphrase, do not pass a passphrase.
#' @return Base64 string containing the encrypted pickle.
#' @export
mxc_account_pickle <- function(account, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxc_account_pickle, account, key)
}

#' Restore an Account from an encrypted pickle
#'
#' @param blob A base64 string produced by [mxc_account_pickle].
#' @param key The 32-byte key the pickle was encrypted under.
#' @return An Account external pointer.
#' @export
mxc_account_unpickle <- function(blob, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxc_account_unpickle, as.character(blob), key)
}
