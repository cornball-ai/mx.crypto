% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_sign}
\alias{mxc_account_sign}
\title{Sign canonical JSON with the Account's ed25519 key}
\usage{
mxc_account_sign(account, canonical_json)
}
\arguments{
\item{account}{An Account.}

\item{canonical_json}{A character string containing canonical JSON.}
}
\value{
Unpadded base64 ed25519 signature.
}
\description{
The caller must canonicalise the JSON per the Matrix spec
(UTF-8, sorted keys, no whitespace, no insignificant data) before
passing it in. mx.crypto does not canonicalise; mx.api will.
}
\examples{
acct <- mxc_account_new()
sig <- mxc_account_sign(acct, '{"hello":"world"}')
}
