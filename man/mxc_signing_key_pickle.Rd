% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_signing_key_pickle}
\alias{mxc_signing_key_pickle}
\title{Encrypt and pickle a signing key}
\usage{
mxc_signing_key_pickle(key, pickle_key)
}
\arguments{
\item{key}{A signing-key handle.}

\item{pickle_key}{A 32-byte raw encryption key.}
}
\value{
Encrypted base64 pickle.
}
\description{
Uses the same vodozemac pickle encryption as an Olm account. Although the
carrier also contains an unused Curve25519 identity, only the Ed25519 key
is part of the signing-key contract.
}
