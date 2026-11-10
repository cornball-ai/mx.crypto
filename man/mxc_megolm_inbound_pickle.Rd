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
\examples{
key <- as.raw(1:32)
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
blob <- mxc_megolm_inbound_pickle(igs, key)
igs2 <- mxc_megolm_inbound_unpickle(blob, key)
}
