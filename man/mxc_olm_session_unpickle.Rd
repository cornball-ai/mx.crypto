% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_session_unpickle}
\alias{mxc_olm_session_unpickle}
\title{Restore an Olm session from a pickle}
\usage{
mxc_olm_session_unpickle(blob, key)
}
\arguments{
\item{blob}{Base64 string produced by [mxc_olm_session_pickle].}

\item{key}{32-byte raw vector.}
}
\value{
An Olm Session external pointer.
}
\description{
Restore an Olm session from a pickle
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
sess2 <- mxc_olm_session_unpickle(blob, key)
msg <- mxc_olm_encrypt(sess2, charToRaw("hello bob"))
}
