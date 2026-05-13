% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_generate_one_time_keys}
\alias{mxc_account_generate_one_time_keys}
\title{Generate one-time keys}
\usage{
mxc_account_generate_one_time_keys(account, n)
}
\arguments{
\item{account}{An Account.}

\item{n}{Number of OTKs to generate.}
}
\value{
Invisible NULL; mutates `account` in place.
}
\description{
Adds `n` curve25519 one-time keys to the Account's pool. Call
[mxc_account_one_time_keys] to read them out for upload, then
[mxc_account_mark_published] once the homeserver has accepted them.
}
\examples{
acct <- mxc_account_new()
mxc_account_generate_one_time_keys(acct, 5L)
}
