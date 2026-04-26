#' mx.crypto: Matrix End-to-End Encryption Primitives
#'
#' Olm and Megolm ratchet primitives for the Matrix protocol, wrapping
#' the `vodozemac` Rust crate. Pairs with `mx.api`, which handles HTTP
#' transport. mx.crypto is crypto only: no network, no canonical-JSON,
#' no `m.room_key_request`, no cross-signing or SAS in 0.1.0.
#'
#' @name mx.crypto-package
#' @aliases mx.crypto
#' @useDynLib mx.crypto, .registration = TRUE
"_PACKAGE"
