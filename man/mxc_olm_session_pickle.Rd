% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_session_pickle}
\alias{mxc_olm_session_pickle}
\title{Pickle an Olm session}
\usage{
mxc_olm_session_pickle(session, key)
}
\arguments{
\item{session}{An Olm Session.}

\item{key}{32-byte raw vector.}
}
\value{
Base64 string.
}
\description{
Pickle after every encrypt/decrypt to keep the ratchet state on disk.
}
\examples{
alice <- mxc_account_new()
bob <- mxc_account_new()
mxc_account_generate_one_time_keys(bob, 1L)
sess <- mxc_olm_create_outbound(alice,
  mxc_account_identity_keys(bob)$curve25519,
  mxc_account_one_time_keys(bob)[[1]])
key <- as.raw(1:32)
blob <- mxc_olm_session_pickle(sess, key)
}
