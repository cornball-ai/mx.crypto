% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_verify_one_time_key}
\alias{mxc_verify_one_time_key}
\title{Verify a signed one-time / fallback key}
\usage{
mxc_verify_one_time_key(algorithm_key_id, key_object, signing_ed25519,
                        expected_user_id, expected_device_id)
}
\arguments{
\item{algorithm_key_id}{Character. The outer map key from the
\code{one_time_keys} or \code{fallback_keys} response, e.g.
\code{"signed_curve25519:AAAAAAAAAAA"}. The algorithm prefix
must be \code{signed_curve25519}.}

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
The caller must pass the outer map key (\code{"<algorithm>:<key_id>"})
alongside the inner key object so the helper can reject anything but
\code{signed_curve25519}. The helper also confirms the \code{key}
value decodes to a 32-byte curve25519 public key; a signature over
garbage bytes is not a useful "verified" result.
}
\examples{
\dontrun{
cl <- mx.api::mx_keys_claim(s, list(
  "@alice:server" = list("ALICEDEV" = "signed_curve25519")
))
entry <- cl$one_time_keys[["@alice:server"]][["ALICEDEV"]]
algo_kid <- names(entry)[[1]]   # e.g. "signed_curve25519:AAAA"
otk <- mxc_verify_one_time_key(
  algo_kid, entry[[1]], alice_ed, "@alice:server", "ALICEDEV"
)
}
}
