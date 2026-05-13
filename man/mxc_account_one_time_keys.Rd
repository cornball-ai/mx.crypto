% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_one_time_keys}
\alias{mxc_account_one_time_keys}
\title{Read pending one-time keys}
\usage{
mxc_account_one_time_keys(account)
}
\arguments{
\item{account}{An Account.}
}
\value{
Named list mapping `key_id` to `curve25519_pub` (both
  unpadded base64 strings).
}
\description{
Returns OTKs that have been generated but not yet marked as published.
Each value is a curve25519 public key; the caller should sign each
with [mxc_account_sign] and upload as `signed_curve25519:<key_id>`.
}
\examples{
acct <- mxc_account_new()
mxc_account_generate_one_time_keys(acct, 5L)
otks <- mxc_account_one_time_keys(acct)
}
