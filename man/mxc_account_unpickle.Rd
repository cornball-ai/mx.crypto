% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_unpickle}
\alias{mxc_account_unpickle}
\title{Restore an Account from an encrypted pickle}
\usage{
mxc_account_unpickle(blob, key)
}
\arguments{
\item{blob}{A base64 string produced by [mxc_account_pickle].}

\item{key}{The 32-byte key the pickle was encrypted under.}
}
\value{
An Account external pointer.
}
\description{
Restore an Account from an encrypted pickle
}
