% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_encrypt}
\alias{mxc_olm_encrypt}
\title{Encrypt a message on an Olm session}
\usage{
mxc_olm_encrypt(session, plaintext)
}
\arguments{
\item{session}{An Olm Session.}

\item{plaintext}{A `raw` vector.}
}
\value{
Named list: `type` (`0L` pre-key, `1L` normal) and `body` (base64).
}
\description{
Encrypt a message on an Olm session
}
