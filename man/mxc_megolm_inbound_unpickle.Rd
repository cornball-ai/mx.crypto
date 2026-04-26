% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_inbound_unpickle}
\alias{mxc_megolm_inbound_unpickle}
\title{Restore an inbound group session from a pickle}
\usage{
mxc_megolm_inbound_unpickle(blob, key)
}
\arguments{
\item{blob}{Base64 string.}

\item{key}{32-byte raw vector.}
}
\value{
An InboundGroupSession external pointer.
}
\description{
Restore an inbound group session from a pickle
}
