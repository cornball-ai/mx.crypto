% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_account_pickle}
\alias{mxc_account_pickle}
\title{Pickle an Account to an encrypted blob}
\usage{
mxc_account_pickle(account, key)
}
\arguments{
\item{account}{An Account.}

\item{key}{A `raw` vector of length 32. The caller is responsible for
key derivation; use a KDF on a passphrase, do not pass a passphrase.}
}
\value{
Base64 string containing the encrypted pickle.
}
\description{
Serialises the Account's state and encrypts it under a 32-byte key.
Restore with [mxc_account_unpickle]. Pickle after every state change
that you want to survive a restart (OTK generation, fallback key
rotation, mark-published).
}
