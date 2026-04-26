% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_session_unpickle}
\alias{mxc_olm_session_unpickle}
\title{Restore an Olm session from a pickle}
\usage{
mxc_olm_session_unpickle(blob, key)
}
\arguments{
\item{blob}{Base64 string produced by [mxc_olm_session_pickle].}

\item{key}{32-byte raw vector.}
}
\value{
An Olm Session external pointer.
}
\description{
Restore an Olm session from a pickle
}
