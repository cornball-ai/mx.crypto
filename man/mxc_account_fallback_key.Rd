% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_fallback_key}
\alias{mxc_account_fallback_key}
\title{Generate and return a fallback key}
\usage{
mxc_account_fallback_key(account)
}
\arguments{
\item{account}{An Account.}
}
\value{
Named list with `key_id` and `curve25519` (both base64).
}
\description{
Generates a fallback curve25519 key, which the homeserver hands out
when an OTK pool is exhausted. Returns the freshly generated key.
Calling it again rotates the previous fallback.
}
