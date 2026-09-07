% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_signing_key_sign}
\alias{mxc_signing_key_sign}
\title{Sign canonical JSON with a signing key}
\usage{
mxc_signing_key_sign(key, canonical_json)
}
\arguments{
\item{key}{A signing-key handle.}

\item{canonical_json}{A canonical JSON character string.}
}
\value{
Unpadded base64 Ed25519 signature.
}
\description{
Sign canonical JSON with a signing key
}
