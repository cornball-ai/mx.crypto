#' mx.crypto: Matrix End-to-End Encryption Primitives
#'
#' Olm and Megolm ratchet primitives for the Matrix protocol, wrapping
#' the `vodozemac` Rust crate. Pairs with `mx.api`, which handles HTTP
#' transport. mx.crypto is crypto only: no network or canonical JSON. It
#' supplies encrypted Ed25519 signing keys and forwarded Megolm session
#' import/export; higher layers own cross-signing, room-key-request, and trust
#' policy. SAS verification is not implemented.
#'
#' @name mx.crypto-package
#' @aliases mx.crypto
#' @useDynLib mx.crypto, .registration = TRUE
"_PACKAGE"
