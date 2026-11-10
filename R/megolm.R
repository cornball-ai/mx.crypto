#' Create an outbound Megolm group session
#'
#' The sender side of a Megolm ratchet. Use [mxc_megolm_outbound_info]
#' to read out the `session_key` that must be shared (over Olm) with
#' each recipient device, and [mxc_megolm_encrypt] to encrypt room
#' messages. Rotate (create a new one) on membership changes or after
#' your chosen number-of-messages / time threshold.
#'
#' @return An outbound GroupSession external pointer.
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' mxc_megolm_outbound_info(gs)$session_id
#' @export
mxc_megolm_outbound_new <- function() {
  .Call(.mxc_megolm_outbound_new)
}

#' Inspect an outbound group session
#'
#' Returns the `session_id`, current `session_key` (the value to ship
#' via `m.room_key` to recipient devices), and `message_index`.
#'
#' @param gs An outbound GroupSession.
#' @return Named list: `session_id` (str), `session_key` (str),
#'   `message_index` (int).
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' info <- mxc_megolm_outbound_info(gs)
#' info$message_index
#' # Ship info$session_key to each recipient device in m.room_key
#' igs <- mxc_megolm_inbound_new(info$session_key)
#' @export
mxc_megolm_outbound_info <- function(gs) {
  .Call(.mxc_megolm_outbound_info, gs)
}

#' Encrypt a room message
#'
#' @param gs An outbound GroupSession.
#' @param plaintext A `raw` vector. The caller is responsible for
#'   producing the canonical JSON event body.
#' @return Base64 ciphertext (the `ciphertext` field of `m.room.encrypted`).
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
#' rawToChar(mxc_megolm_decrypt(igs, ct)$plaintext)
#' @export
mxc_megolm_encrypt <- function(gs, plaintext) {
  if (!is.raw(plaintext)) {
    stop("'plaintext' must be a raw vector")
  }
  .Call(.mxc_megolm_encrypt, gs, plaintext)
}

#' Pickle an outbound group session
#'
#' @param gs An outbound GroupSession.
#' @param key 32-byte raw vector.
#' @return Base64 string.
#' @examples
#' key <- as.raw(1:32)
#' gs <- mxc_megolm_outbound_new()
#' blob <- mxc_megolm_outbound_pickle(gs, key)
#' gs2 <- mxc_megolm_outbound_unpickle(blob, key)
#' @export
mxc_megolm_outbound_pickle <- function(gs, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxc_megolm_outbound_pickle, gs, key)
}

#' Restore an outbound group session from a pickle
#'
#' @param blob Base64 string.
#' @param key 32-byte raw vector.
#' @return An outbound GroupSession external pointer.
#' @examples
#' key <- as.raw(1:32)
#' gs <- mxc_megolm_outbound_new()
#' blob <- mxc_megolm_outbound_pickle(gs, key)
#' gs2 <- mxc_megolm_outbound_unpickle(blob, key)
#' identical(mxc_megolm_outbound_info(gs2)$session_id,
#'           mxc_megolm_outbound_info(gs)$session_id)
#' @export
mxc_megolm_outbound_unpickle <- function(blob, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxc_megolm_outbound_unpickle, as.character(blob), key)
}

#' Build an inbound Megolm session from a shared session_key
#'
#' Constructs the receiver-side ratchet using the `session_key` that
#' was delivered (over Olm) in an `m.room_key` event. The receiver
#' stores the resulting object indexed by `(sender_curve25519,
#' session_id)` and re-uses it to decrypt incoming messages on that
#' session.
#'
#' @param session_key Base64 session_key from `m.room_key`.
#' @return An InboundGroupSession external pointer.
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
#' mxc_megolm_decrypt(igs, ct)$message_index
#' @export
mxc_megolm_inbound_new <- function(session_key) {
  .Call(.mxc_megolm_inbound_new, as.character(session_key))
}

#' Import a forwarded inbound Megolm session
#'
#' Imports the exported session-key format carried by
#' `m.forwarded_room_key`. Unlike [mxc_megolm_inbound_new()], the resulting
#' session does not treat the original sender signature as verified; the
#' caller must validate the forwarding chain and sender identity.
#'
#' @param session_key Base64 exported session key.
#' @return An InboundGroupSession external pointer.
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' fwd <- mxc_megolm_inbound_import(mxc_megolm_inbound_export(igs))
#' ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
#' rawToChar(mxc_megolm_decrypt(fwd, ct)$plaintext)
#' @export
mxc_megolm_inbound_import <- function(session_key) {
  .Call(.mxc_megolm_inbound_import, as.character(session_key))
}

#' Inspect an inbound Megolm session
#'
#' @param igs An InboundGroupSession.
#' @return Named list with `session_id` and `first_known_index`.
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' mxc_megolm_inbound_info(igs)
#' @export
mxc_megolm_inbound_info <- function(igs) {
  .Call(.mxc_megolm_inbound_info, igs)
}

#' Export an inbound Megolm session for forwarding
#'
#' Exports at the first known message index, retaining the maximum history
#' this recipient can legitimately share. The result is the `session_key`
#' value for `m.forwarded_room_key`.
#'
#' @param igs An InboundGroupSession.
#' @return Base64 exported session key.
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' exported <- mxc_megolm_inbound_export(igs)
#' fwd <- mxc_megolm_inbound_import(exported)
#' mxc_megolm_inbound_info(fwd)$session_id
#' @export
mxc_megolm_inbound_export <- function(igs) {
  .Call(.mxc_megolm_inbound_export, igs)
}

#' Decrypt a room message
#'
#' @param igs An InboundGroupSession.
#' @param ciphertext_b64 Base64 ciphertext (the `ciphertext` field of
#'   the `m.room.encrypted` event).
#' @return Named list: `plaintext` (raw) and `message_index` (integer).
#'   Use `message_index` to dedupe replays.
#' @examples
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
#' dec <- mxc_megolm_decrypt(igs, ct)
#' rawToChar(dec$plaintext)
#' dec$message_index
#' @export
mxc_megolm_decrypt <- function(igs, ciphertext_b64) {
  .Call(.mxc_megolm_decrypt, igs, as.character(ciphertext_b64))
}

#' Pickle an inbound group session
#'
#' Pickle after every decrypt so the ratchet state survives restart.
#'
#' @param igs An InboundGroupSession.
#' @param key 32-byte raw vector.
#' @return Base64 string.
#' @examples
#' key <- as.raw(1:32)
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' blob <- mxc_megolm_inbound_pickle(igs, key)
#' igs2 <- mxc_megolm_inbound_unpickle(blob, key)
#' @export
mxc_megolm_inbound_pickle <- function(igs, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxc_megolm_inbound_pickle, igs, key)
}

#' Restore an inbound group session from a pickle
#'
#' @param blob Base64 string.
#' @param key 32-byte raw vector.
#' @return An InboundGroupSession external pointer.
#' @examples
#' key <- as.raw(1:32)
#' gs <- mxc_megolm_outbound_new()
#' igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
#' igs2 <- mxc_megolm_inbound_unpickle(mxc_megolm_inbound_pickle(igs, key), key)
#' ct <- mxc_megolm_encrypt(gs, charToRaw("after restart"))
#' rawToChar(mxc_megolm_decrypt(igs2, ct)$plaintext)
#' @export
mxc_megolm_inbound_unpickle <- function(blob, key) {
  if (!is.raw(key) || length(key) != 32L) {
    stop("'key' must be a raw vector of length 32")
  }
  .Call(.mxc_megolm_inbound_unpickle, as.character(blob), key)
}
