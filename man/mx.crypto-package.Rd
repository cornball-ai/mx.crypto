% tinyrox says don't edit this manually, but it can't stop you!
\docType{package}
\name{mx.crypto-package}
\alias{mx.crypto}
\alias{mx.crypto-package}
\title{mx.crypto: Matrix End-to-End Encryption Primitives}
\description{
Olm and Megolm ratchet primitives for the Matrix protocol, wrapping
the `vodozemac` Rust crate. Pairs with `mx.api`, which handles HTTP
transport. mx.crypto is crypto only: no network, no canonical-JSON,
no `m.room_key_request`, no cross-signing or SAS in 0.1.0.
}
\author{
\strong{Maintainer}: Troy Hernandez \email{troy@cornball.ai}
}
