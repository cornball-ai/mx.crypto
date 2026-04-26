% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_outbound_info}
\alias{mxc_megolm_outbound_info}
\title{Inspect an outbound group session}
\usage{
mxc_megolm_outbound_info(gs)
}
\arguments{
\item{gs}{An outbound GroupSession.}
}
\value{
Named list: `session_id` (str), `session_key` (str),
  `message_index` (int).
}
\description{
Returns the `session_id`, current `session_key` (the value to ship
via `m.room_key` to recipient devices), and `message_index`.
}
