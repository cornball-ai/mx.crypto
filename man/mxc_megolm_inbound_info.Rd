% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_inbound_info}
\alias{mxc_megolm_inbound_info}
\title{Inspect an inbound Megolm session}
\usage{
mxc_megolm_inbound_info(igs)
}
\arguments{
\item{igs}{An InboundGroupSession.}
}
\value{
Named list with `session_id` and `first_known_index`.
}
\description{
Inspect an inbound Megolm session
}
\examples{
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
mxc_megolm_inbound_info(igs)
}
