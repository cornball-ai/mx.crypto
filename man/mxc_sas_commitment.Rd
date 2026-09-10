% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_sas_commitment}
\alias{mxc_sas_commitment}
\title{Hash a Matrix SAS public key and canonical start message}
\usage{
mxc_sas_commitment(public_key, canonical_start)
}
\arguments{
\item{public_key}{Unpadded base64 ephemeral Curve25519 public key.}

\item{canonical_start}{Canonical JSON of the complete start content.}
}
\value{
The unpadded base64 SHA-256 commitment.
}
\description{
Computes SHA-256 over the concatenated UTF-8 strings and returns unpadded
base64. The caller must canonicalize the complete start content first.
This function does not parse JSON or implement protocol policy.
}
