% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_inbound_new}
\alias{mxc_megolm_inbound_new}
\title{Build an inbound Megolm session from a shared session_key}
\usage{
mxc_megolm_inbound_new(session_key)
}
\arguments{
\item{session_key}{Base64 session_key from `m.room_key`.}
}
\value{
An InboundGroupSession external pointer.
}
\description{
Constructs the receiver-side ratchet using the `session_key` that
was delivered (over Olm) in an `m.room_key` event. The receiver
stores the resulting object indexed by `(sender_curve25519,
session_id)` and re-uses it to decrypt incoming messages on that
session.
}
