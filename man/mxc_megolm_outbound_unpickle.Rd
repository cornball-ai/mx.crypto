% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_outbound_unpickle}
\alias{mxc_megolm_outbound_unpickle}
\title{Restore an outbound group session from a pickle}
\usage{
mxc_megolm_outbound_unpickle(blob, key)
}
\arguments{
\item{blob}{Base64 string.}

\item{key}{32-byte raw vector.}
}
\value{
An outbound GroupSession external pointer.
}
\description{
Restore an outbound group session from a pickle
}
