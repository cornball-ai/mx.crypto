% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_identity_keys}
\alias{mxc_account_identity_keys}
\title{Public identity keys for an Account}
\usage{
mxc_account_identity_keys(account)
}
\arguments{
\item{account}{An Account from [mxc_account_new] or [mxc_account_unpickle].}
}
\value{
A named list with `curve25519` and `ed25519` strings.
}
\description{
Returns the device's two public keys: curve25519 (Olm sender / identity
key, used to start sessions) and ed25519 (signing / fingerprint key).
Both are unpadded base64 strings, ready for `/keys/upload`.
}
\examples{
\dontrun{
k <- mxc_account_identity_keys(mxc_account_new())
k$curve25519
}
}
