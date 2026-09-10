#' Create an ephemeral Matrix SAS key agreement
#'
#' Wraps vodozemac's short-authentication-string key agreement. The handle
#' cannot be saved or restored; restart interrupted verification with a new
#' transaction and handle. Protocol negotiation, commitments, user prompts,
#' timeouts, and cross-signing policy belong to mx.client.
#' @return An opaque SAS handle.
#' @export
mxc_sas_new <- function() .Call(.sas__mxc_sas_new)

#' Read a SAS ephemeral public key
#' @param sas An opaque SAS handle.
#' @return An unpadded base64 Curve25519 public key.
#' @export
mxc_sas_public <- function(sas) .Call(.sas__mxc_sas_public, sas)

#' Establish a SAS shared secret
#'
#' Consumes the handle's ephemeral secret exactly once. A low-order peer key
#' is rejected and consumes the handle. No shared secret is returned to R.
#' @param sas An opaque SAS handle, modified in place.
#' @param peer_key The peer's unpadded base64 ephemeral public key.
#' @return Invisibly NULL.
#' @export
mxc_sas_establish <- function(sas, peer_key) {
    .Call(.sas__mxc_sas_establish, sas, peer_key)
    invisible(NULL)
}

#' Derive the six Matrix SAS display bytes
#' @param sas An established SAS handle.
#' @param info The protocol's ordered SAS context string.
#' @return A raw vector of length six, for decimal or emoji presentation.
#' @export
mxc_sas_bytes <- function(sas, info) .Call(.sas__mxc_sas_bytes, sas, info)

#' Authenticate a Matrix SAS key or key-id list
#' @param sas An established SAS handle.
#' @param input Public key or sorted key-id list to authenticate.
#' @param info The protocol's direction-specific MAC context string.
#' @return An unpadded base64 HMAC-SHA-256 tag for hkdf-hmac-sha256.v2.
#' @export
mxc_sas_mac <- function(sas, input, info) {
    .Call(.sas__mxc_sas_mac, sas, input, info)
}

#' Verify a Matrix SAS authentication tag
#'
#' Uses vodozemac's constant-time MAC verification. Malformed tags return
#' FALSE; an invalid or unestablished handle raises an error.
#' @param sas An established SAS handle.
#' @param input Public key or sorted key-id list being authenticated.
#' @param info The protocol's direction-specific MAC context string.
#' @param mac Unpadded base64 HMAC-SHA-256 tag.
#' @return TRUE for a matching tag, otherwise FALSE.
#' @export
mxc_sas_verify_mac <- function(sas, input, info, mac) {
    .Call(.sas__mxc_sas_verify_mac, sas, input, info, mac)
}

#' Hash a Matrix SAS public key and canonical start message
#'
#' Computes SHA-256 over the concatenated UTF-8 strings and returns unpadded
#' base64. The caller must canonicalize the complete start content first.
#' This function does not parse JSON or implement protocol policy.
#' @param public_key Unpadded base64 ephemeral Curve25519 public key.
#' @param canonical_start Canonical JSON of the complete start content.
#' @return The unpadded base64 SHA-256 commitment.
#' @export
mxc_sas_commitment <- function(public_key, canonical_start) {
    .Call(.sas__mxc_sas_commitment, enc2utf8(public_key), enc2utf8(canonical_start))
}
