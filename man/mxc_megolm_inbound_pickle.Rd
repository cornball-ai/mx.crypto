% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_inbound_pickle}
\alias{mxc_megolm_inbound_pickle}
\title{Pickle an inbound group session}
\usage{
mxc_megolm_inbound_pickle(igs, key)
}
\arguments{
\item{igs}{An InboundGroupSession.}

\item{key}{32-byte raw vector.}
}
\value{
Base64 string.
}
\description{
Pickle after every decrypt so the ratchet state survives restart.
}
