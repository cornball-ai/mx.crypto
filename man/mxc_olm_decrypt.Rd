% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_decrypt}
\alias{mxc_olm_decrypt}
\title{Decrypt a message on an Olm session}
\usage{
mxc_olm_decrypt(session, type, body)
}
\arguments{
\item{session}{An Olm Session.}

\item{type}{Message type: `0L` for pre-key, `1L` for normal.}

\item{body}{Ciphertext (base64).}
}
\value{
A `raw` vector of plaintext bytes.
}
\description{
Decrypt a message on an Olm session
}
\examples{
alice <- mxc_account_new()
bob <- mxc_account_new()
mxc_account_generate_one_time_keys(bob, 1L)
sess_a <- mxc_olm_create_outbound(alice,
  mxc_account_identity_keys(bob)$curve25519,
  mxc_account_one_time_keys(bob)[[1]])
msg <- mxc_olm_encrypt(sess_a, charToRaw("hello bob"))
sess_b <- mxc_olm_create_inbound(bob,
  mxc_account_identity_keys(alice)$curve25519, msg$body)$session
reply <- mxc_olm_encrypt(sess_b, charToRaw("hi alice"))
rawToChar(mxc_olm_decrypt(sess_a, reply$type, reply$body))
}
