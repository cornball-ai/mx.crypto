% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_verify_device_keys}
\alias{mxc_verify_device_keys}
\title{Verify a Matrix device-keys object}
\usage{
mxc_verify_device_keys(device_keys, expected_user_id, expected_device_id)
}
\arguments{
\item{device_keys}{Named list. The \code{device_keys} object,
exactly as parsed from a homeserver response (no signatures
block stripped).}

\item{expected_user_id}{Character. Matrix user id the device is
supposed to belong to.}

\item{expected_device_id}{Character. The device id we're verifying.}
}
\value{
Named list with the verified \code{curve25519} and
  \code{ed25519} public keys (both base64). Use these as the
  inputs for Olm session establishment.
}
\description{
Validates a single \code{device_keys} object as returned by
\code{/_matrix/client/v3/keys/query}: checks that the structural
fields (user_id, device_id, algorithms, keys, signatures) are
present and match the expected identity, then verifies the
ed25519 self-signature over the canonical-JSON byte sequence
(with \code{signatures} and \code{unsigned} stripped).
Any of the following raises an error rather than returning
\code{FALSE}: missing field, wrong \code{user_id} or
\code{device_id}, missing curve25519 / ed25519 key, missing
signatures block, signature under the wrong user or device,
invalid signature, malformed base64.
This function deliberately accepts \emph{any} ed25519 key the
object claims for itself; it does not pin against a previously
trusted key. Identity pinning is the caller's responsibility
(typically TOFU + cross-signing).
}
\examples{
\dontrun{
q <- mx.api::mx_keys_query(s, list("@alice:server" = "ALICEDEV"))
dk <- q$device_keys[["@alice:server"]][["ALICEDEV"]]
keys <- mxc_verify_device_keys(dk, "@alice:server", "ALICEDEV")
keys$curve25519
}
}
