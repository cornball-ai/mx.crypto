% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_public}
\alias{mxc_sas_public}
\title{Read a SAS ephemeral public key}
\usage{
mxc_sas_public(sas)
}
\arguments{
\item{sas}{An opaque SAS handle.}
}
\value{
An unpadded base64 Curve25519 public key.
}
\description{
Read a SAS ephemeral public key
}
