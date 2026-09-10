% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_verify_mac}
\alias{mxc_sas_verify_mac}
\title{Verify a Matrix SAS authentication tag}
\usage{
mxc_sas_verify_mac(sas, input, info, mac)
}
\arguments{
\item{sas}{An established SAS handle.}

\item{input}{Public key or sorted key-id list being authenticated.}

\item{info}{The protocol's direction-specific MAC context string.}

\item{mac}{Unpadded base64 HMAC-SHA-256 tag.}
}
\value{
TRUE for a matching tag, otherwise FALSE.
}
\description{
Uses vodozemac's constant-time MAC verification. Malformed tags return
FALSE; an invalid or unestablished handle raises an error.
}
