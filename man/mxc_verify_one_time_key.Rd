% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_verify_one_time_key}
\alias{mxc_verify_one_time_key}
\title{Verify a signed one-time / fallback key}
\usage{
mxc_verify_one_time_key(key_object, signing_ed25519, expected_user_id,
                        expected_device_id)
}
\arguments{
\item{key_object}{Named list. The signed key object (must contain
\code{key} and \code{signatures}).}

\item{signing_ed25519}{Character. The base64 ed25519 public key
that should have signed this OTK (i.e. the ed25519 returned by
\code{mxc_verify_device_keys} for the same device).}

\item{expected_user_id}{Character. Matrix user id the OTK is
supposed to come from.}

\item{expected_device_id}{Character. Matrix device id.}
}
\value{
Character. The verified curve25519 OTK (base64), ready to
  feed into \code{mxc_olm_create_outbound}.
}
\description{
Validates a single signed_curve25519 object returned by
\code{/_matrix/client/v3/keys/claim} (or the \code{fallback_keys}
block of \code{/keys/upload}). The signing ed25519 key must come
from a previously verified \code{device_keys} object —
\emph{this function does not look it up for you}, because doing so
would silently re-trust whatever the homeserver hands back.
}
\examples{
\dontrun{
cl <- mx.api::mx_keys_claim(s, list(
  "@alice:server" = list("ALICEDEV" = "signed_curve25519")
))
obj <- cl$one_time_keys[["@alice:server"]][["ALICEDEV"]][[1]]
otk <- mxc_verify_one_time_key(obj, alice_ed, "@alice:server", "ALICEDEV")
}
}
