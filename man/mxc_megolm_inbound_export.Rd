% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_inbound_export}
\alias{mxc_megolm_inbound_export}
\title{Export an inbound Megolm session for forwarding}
\usage{
mxc_megolm_inbound_export(igs)
}
\arguments{
\item{igs}{An InboundGroupSession.}
}
\value{
Base64 exported session key.
}
\description{
Exports at the first known message index, retaining the maximum history
this recipient can legitimately share. The result is the `session_key`
value for `m.forwarded_room_key`.
}
\examples{
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
exported <- mxc_megolm_inbound_export(igs)
fwd <- mxc_megolm_inbound_import(exported)
mxc_megolm_inbound_info(fwd)$session_id
}
