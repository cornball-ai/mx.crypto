% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_session_pickle}
\alias{mxc_olm_session_pickle}
\title{Pickle an Olm session}
\usage{
mxc_olm_session_pickle(session, key)
}
\arguments{
\item{session}{An Olm Session.}

\item{key}{32-byte raw vector.}
}
\value{
Base64 string.
}
\description{
Pickle after every encrypt/decrypt to keep the ratchet state on disk.
}
