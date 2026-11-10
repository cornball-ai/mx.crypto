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
\examples{
key <- as.raw(1:32)
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
igs2 <- mxc_megolm_inbound_unpickle(mxc_megolm_inbound_pickle(igs, key), key)
ct <- mxc_megolm_encrypt(gs, charToRaw("after restart"))
rawToChar(mxc_megolm_decrypt(igs2, ct)$plaintext)
}
