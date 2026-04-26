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
