% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_mac}
\alias{mxc_sas_mac}
\title{Authenticate a Matrix SAS key or key-id list}
\usage{
mxc_sas_mac(sas, input, info)
}
\arguments{
\item{sas}{An established SAS handle.}

\item{input}{Public key or sorted key-id list to authenticate.}

\item{info}{The protocol's direction-specific MAC context string.}
}
\value{
An unpadded base64 HMAC-SHA-256 tag for hkdf-hmac-sha256.v2.
}
\description{
Authenticate a Matrix SAS key or key-id list
}
