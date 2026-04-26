% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_mark_published}
\alias{mxc_account_mark_published}
\title{Mark current one-time keys as published}
\usage{
mxc_account_mark_published(account)
}
\arguments{
\item{account}{An Account.}
}
\value{
Invisible NULL; mutates `account`.
}
\description{
Call after the homeserver has accepted a `/keys/upload` containing
the keys returned by [mxc_account_one_time_keys]. Future calls to
that function will not re-include them.
}
