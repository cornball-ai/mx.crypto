% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_ed25519_verify}
\alias{mxc_ed25519_verify}
\title{Verify an Ed25519 signature}
\usage{
mxc_ed25519_verify(public_key, message, signature)
}
\arguments{
\item{public_key}{Character. Unpadded base64 ed25519 public key
(the same shape \code{mxc_account_identity_keys} returns).}

\item{message}{A \code{raw} vector. The byte sequence the signer
ran ed25519 over; typically the output of
\code{mx.api::mx_canonical_json()}.}

\item{signature}{Character. Unpadded base64 ed25519 signature
(86 chars).}
}
\value{
Single logical: \code{TRUE} for a valid signature,
  \code{FALSE} otherwise.
}
\description{
Thin wrapper over vodozemac's strict Ed25519 verifier
(\code{verify_strict}). Returns \code{TRUE} when the signature is
valid and \code{FALSE} when it isn't; raises an error if any of
\code{public_key}, \code{message}, or \code{signature} is malformed
(bad base64, wrong length, etc.).
}
\examples{
\dontrun{
acct <- mxc_account_new()
ids <- mxc_account_identity_keys(acct)
sig <- mxc_account_sign(acct, "{\"hello\":\"world\"}")
mxc_ed25519_verify(ids$ed25519, charToRaw("{\"hello\":\"world\"}"), sig)
}
}
