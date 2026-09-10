% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_establish}
\alias{mxc_sas_establish}
\title{Establish a SAS shared secret}
\usage{
mxc_sas_establish(sas, peer_key)
}
\arguments{
\item{sas}{An opaque SAS handle, modified in place.}

\item{peer_key}{The peer's unpadded base64 ephemeral public key.}
}
\value{
Invisibly NULL.
}
\description{
Consumes the handle's ephemeral secret exactly once. A low-order peer key
is rejected and consumes the handle. No shared secret is returned to R.
}
