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
