% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_signing_key_unpickle}
\alias{mxc_signing_key_unpickle}
\title{Restore an encrypted signing key pickle}
\usage{
mxc_signing_key_unpickle(blob, pickle_key)
}
\arguments{
\item{blob}{An encrypted pickle from [mxc_signing_key_pickle()].}

\item{pickle_key}{The same 32-byte raw encryption key.}
}
\value{
An opaque signing-key handle.
}
\description{
Restore an encrypted signing key pickle
}
