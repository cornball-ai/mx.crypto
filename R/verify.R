# Signature verification helpers.
#
# mx.crypto's signing primitive (`mxc_account_sign`) has always existed,
# but until now there was no verification counterpart. That meant
# callers had no way to check `/keys/query` or `/keys/claim` responses
# from the homeserver — a malicious homeserver could substitute its own
# device keys (or its own ed25519 over a real curve25519) and the
# caller would happily open an Olm session into the attacker's hands.
#
# These helpers fail closed: any structural problem or signature
# mismatch raises an error rather than returning a "partially valid"
# object.

#' Verify an Ed25519 signature
#'
#' Thin wrapper over vodozemac's strict Ed25519 verifier
#' (\code{verify_strict}). Returns \code{TRUE} when the signature is
#' valid and \code{FALSE} when it isn't; raises an error if any of
#' \code{public_key}, \code{message}, or \code{signature} is malformed
#' (bad base64, wrong length, etc.).
#'
#' @param public_key Character. Unpadded base64 ed25519 public key
#'   (the same shape \code{mxc_account_identity_keys} returns).
#' @param message A \code{raw} vector. The byte sequence the signer
#'   ran ed25519 over; typically the output of
#'   \code{mx.api::mx_canonical_json()}.
#' @param signature Character. Unpadded base64 ed25519 signature
#'   (86 chars).
#'
#' @return Single logical: \code{TRUE} for a valid signature,
#'   \code{FALSE} otherwise.
#' @examples
#' \dontrun{
#' acct <- mxc_account_new()
#' ids <- mxc_account_identity_keys(acct)
#' sig <- mxc_account_sign(acct, "{\"hello\":\"world\"}")
#' mxc_ed25519_verify(ids$ed25519, charToRaw("{\"hello\":\"world\"}"), sig)
#' }
#' @export
mxc_ed25519_verify <- function(public_key, message, signature) {
    if (!is.raw(message)) {
        stop("'message' must be a raw vector", call. = FALSE)
    }
    .Call(.mxc_ed25519_verify,
          as.character(public_key),
          message,
          as.character(signature))
}

#' Verify a Matrix device-keys object
#'
#' Validates a single \code{device_keys} object as returned by
#' \code{/_matrix/client/v3/keys/query}: checks that the structural
#' fields (user_id, device_id, algorithms, keys, signatures) are
#' present and match the expected identity, then verifies the
#' ed25519 self-signature over the canonical-JSON byte sequence
#' (with \code{signatures} and \code{unsigned} stripped).
#'
#' Any of the following raises an error rather than returning
#' \code{FALSE}: missing field, wrong \code{user_id} or
#' \code{device_id}, missing curve25519 / ed25519 key, missing
#' signatures block, signature under the wrong user or device,
#' invalid signature, malformed base64.
#'
#' This function deliberately accepts \emph{any} ed25519 key the
#' object claims for itself; it does not pin against a previously
#' trusted key. Identity pinning is the caller's responsibility
#' (typically TOFU + cross-signing).
#'
#' @param device_keys Named list. The \code{device_keys} object,
#'   exactly as parsed from a homeserver response (no signatures
#'   block stripped).
#' @param expected_user_id Character. Matrix user id the device is
#'   supposed to belong to.
#' @param expected_device_id Character. The device id we're verifying.
#'
#' @return Named list with the verified \code{curve25519} and
#'   \code{ed25519} public keys (both base64). Use these as the
#'   inputs for Olm session establishment.
#' @examples
#' \dontrun{
#' q <- mx.api::mx_keys_query(s, list("@alice:server" = "ALICEDEV"))
#' dk <- q$device_keys[["@alice:server"]][["ALICEDEV"]]
#' keys <- mxc_verify_device_keys(dk, "@alice:server", "ALICEDEV")
#' keys$curve25519
#' }
#' @export
mxc_verify_device_keys <- function(device_keys, expected_user_id,
                                   expected_device_id) {
    dk <- device_keys
    if (!is.list(dk)) {
        stop("device_keys must be a list", call. = FALSE)
    }
    if (!identical(dk$user_id, expected_user_id)) {
        stop(sprintf(
                     "device_keys user_id mismatch: expected %s, got %s",
                     sQuote(expected_user_id),
                     sQuote(dk$user_id %||% "<missing>")
            ), call. = FALSE)
    }
    if (!identical(dk$device_id, expected_device_id)) {
        stop(sprintf(
                     "device_keys device_id mismatch: expected %s, got %s",
                     sQuote(expected_device_id),
                     sQuote(dk$device_id %||% "<missing>")
            ), call. = FALSE)
    }
    if (!is.list(dk$keys) || length(dk$keys) == 0L) {
        stop("device_keys has no 'keys' map", call. = FALSE)
    }
    curve_name <- paste0("curve25519:", expected_device_id)
    ed_name <- paste0("ed25519:", expected_device_id)
    curve <- dk$keys[[curve_name]]
    ed <- dk$keys[[ed_name]]
    if (is.null(curve) || !nzchar(curve)) {
        stop(sprintf("device_keys is missing %s", curve_name), call. = FALSE)
    }
    if (is.null(ed) || !nzchar(ed)) {
        stop(sprintf("device_keys is missing %s", ed_name), call. = FALSE)
    }
    if (!is.list(dk$signatures)) {
        stop("device_keys is unsigned (no signatures block)", call. = FALSE)
    }
    user_sigs <- dk$signatures[[expected_user_id]]
    if (!is.list(user_sigs)) {
        stop(sprintf(
                     "device_keys has no signatures from %s",
                     sQuote(expected_user_id)
            ), call. = FALSE)
    }
    sig <- user_sigs[[ed_name]]
    if (is.null(sig) || !nzchar(sig)) {
        stop(sprintf(
                     "device_keys has no %s signature from %s",
                     ed_name, sQuote(expected_user_id)
            ), call. = FALSE)
    }

    # Verify against the canonical JSON of the device_keys minus
    # signatures + unsigned, per the Matrix signing rule.
    if (!requireNamespace("mx.api", quietly = TRUE)) {
        stop(
             "mxc_verify_device_keys requires mx.api (>= 0.1.0.1) for ",
             "mx_canonical_json()",
             call. = FALSE
        )
    }
    to_sign <- dk
    to_sign$signatures <- NULL
    to_sign$unsigned <- NULL
    msg <- charToRaw(mx.api::mx_canonical_json(to_sign))
    if (!isTRUE(mxc_ed25519_verify(ed, msg, sig))) {
        stop(sprintf(
                     "device_keys signature did not verify for %s / %s",
                     expected_user_id, expected_device_id
            ), call. = FALSE)
    }
    list(curve25519 = curve, ed25519 = ed)
}

#' Verify a signed one-time / fallback key
#'
#' Validates a single signed_curve25519 object returned by
#' \code{/_matrix/client/v3/keys/claim} (or the \code{fallback_keys}
#' block of \code{/keys/upload}). The signing ed25519 key must come
#' from a previously verified \code{device_keys} object —
#' \emph{this function does not look it up for you}, because doing so
#' would silently re-trust whatever the homeserver hands back.
#'
#' @param key_object Named list. The signed key object (must contain
#'   \code{key} and \code{signatures}).
#' @param signing_ed25519 Character. The base64 ed25519 public key
#'   that should have signed this OTK (i.e. the ed25519 returned by
#'   \code{mxc_verify_device_keys} for the same device).
#' @param expected_user_id Character. Matrix user id the OTK is
#'   supposed to come from.
#' @param expected_device_id Character. Matrix device id.
#'
#' @return Character. The verified curve25519 OTK (base64), ready to
#'   feed into \code{mxc_olm_create_outbound}.
#' @examples
#' \dontrun{
#' cl <- mx.api::mx_keys_claim(s, list(
#'   "@alice:server" = list("ALICEDEV" = "signed_curve25519")
#' ))
#' obj <- cl$one_time_keys[["@alice:server"]][["ALICEDEV"]][[1]]
#' otk <- mxc_verify_one_time_key(obj, alice_ed, "@alice:server", "ALICEDEV")
#' }
#' @export
mxc_verify_one_time_key <- function(key_object, signing_ed25519,
                                    expected_user_id, expected_device_id) {
    if (!is.list(key_object)) {
        stop("key_object must be a list", call. = FALSE)
    }
    key <- key_object$key
    if (is.null(key) || !nzchar(key)) {
        stop("key_object is missing 'key'", call. = FALSE)
    }
    if (!is.list(key_object$signatures)) {
        stop("key_object is unsigned (no signatures block)", call. = FALSE)
    }
    user_sigs <- key_object$signatures[[expected_user_id]]
    if (!is.list(user_sigs)) {
        stop(sprintf(
                     "key_object has no signatures from %s",
                     sQuote(expected_user_id)
            ), call. = FALSE)
    }
    ed_name <- paste0("ed25519:", expected_device_id)
    sig <- user_sigs[[ed_name]]
    if (is.null(sig) || !nzchar(sig)) {
        stop(sprintf(
                     "key_object has no %s signature from %s",
                     ed_name, sQuote(expected_user_id)
            ), call. = FALSE)
    }
    if (!requireNamespace("mx.api", quietly = TRUE)) {
        stop(
             "mxc_verify_one_time_key requires mx.api (>= 0.1.0.1) for ",
             "mx_canonical_json()",
             call. = FALSE
        )
    }
    to_sign <- key_object
    to_sign$signatures <- NULL
    to_sign$unsigned <- NULL
    msg <- charToRaw(mx.api::mx_canonical_json(to_sign))
    if (!isTRUE(mxc_ed25519_verify(signing_ed25519, msg, sig))) {
        stop(sprintf(
                     "one-time key signature did not verify for %s / %s",
                     expected_user_id, expected_device_id
            ), call. = FALSE)
    }
    key
}

`%||%` <- function(a, b) if (is.null(a)) b else a

