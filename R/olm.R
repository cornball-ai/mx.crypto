#' Start an outbound Olm session
#'
#' Use a peer's published curve25519 identity key + one of their signed
#' one-time keys to bootstrap a 1:1 ratchet. The first ciphertext from
#' this session is a pre-key message (`type = 0`).
#'
#' @param account The local Account.
#' @param peer_curve25519 Peer's curve25519 identity key (base64).
#' @param peer_otk Peer's one-time key (base64).
#' @return An Olm Session external pointer.
#' @export
mxe_olm_create_outbound <- function(account, peer_curve25519, peer_otk) {
  .Call(
    .mxe_olm_create_outbound,
    account,
    as.character(peer_curve25519),
    as.character(peer_otk)
  )
}

#' Build an inbound Olm session from a pre-key message
#'
#' Consumes the matching one-time key from the local Account. The result
#' has the new Session and the decrypted plaintext of the pre-key
#' message; subsequent messages on this session use [mxe_olm_decrypt].
#'
#' @param account The local Account (will be mutated: an OTK is consumed).
#' @param peer_curve25519 Sender's curve25519 identity key (base64).
#' @param prekey_b64 Body of the pre-key message (base64).
#' @return Named list: `session` (external pointer) and `plaintext` (raw).
#' @export
mxe_olm_create_inbound <- function(account, peer_curve25519, prekey_b64) {
  .Call(
    .mxe_olm_create_inbound,
    account,
    as.character(peer_curve25519),
    as.character(prekey_b64)
  )
}

#' Encrypt a message on an Olm session
#'
#' @param session An Olm Session.
#' @param plaintext A `raw` vector.
#' @return Named list: `type` (`0L` pre-key, `1L` normal) and `body` (base64).
#' @export
mxe_olm_encrypt <- function(session, plaintext) {
  if (!is.raw(plaintext)) {
    stop("'plaintext' must be a raw vector")
  }
  .Call(.mxe_olm_encrypt, session, plaintext)
}

#' Decrypt a message on an Olm session
#'
#' @param session An Olm Session.
#' @param type Message type: `0L` for pre-key, `1L` for normal.
#' @param body Ciphertext (base64).
#' @return A `raw` vector of plaintext bytes.
#' @export
mxe_olm_decrypt <- function(session, type, body) {
  .Call(
    .mxe_olm_decrypt,
    session,
    as.integer(type),
    as.character(body)
  )
}

#' Pickle an Olm session
#'
#' Pickle after every encrypt/decrypt to keep the ratchet state on disk.
#'
#' @param session An Olm Session.
#' @param key 32-byte raw vector.
#' @return Base64 string.
#' @export
mxe_olm_session_pickle <- function(session, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxe_olm_session_pickle, session, key)
}

#' Restore an Olm session from a pickle
#'
#' @param blob Base64 string produced by [mxe_olm_session_pickle].
#' @param key 32-byte raw vector.
#' @return An Olm Session external pointer.
#' @export
mxe_olm_session_unpickle <- function(blob, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxe_olm_session_unpickle, as.character(blob), key)
}
