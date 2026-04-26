% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_new}
\alias{mxc_account_new}
\title{Create a new Olm Account}
\usage{
mxc_account_new()
}
\value{
An external pointer to a vodozemac Account.
}
\description{
Creates a fresh device identity. Holds long-lived curve25519 / ed25519
identity keys and a one-time-key pool. The returned object is an
external pointer; persist it with [mxc_account_pickle].
}
\examples{
\dontrun{
acct <- mxc_account_new()
mxc_account_identity_keys(acct)
}
}
