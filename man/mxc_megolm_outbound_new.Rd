% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_outbound_new}
\alias{mxc_megolm_outbound_new}
\title{Create an outbound Megolm group session}
\usage{
mxc_megolm_outbound_new()
}
\value{
An outbound GroupSession external pointer.
}
\description{
The sender side of a Megolm ratchet. Use [mxc_megolm_outbound_info]
to read out the `session_key` that must be shared (over Olm) with
each recipient device, and [mxc_megolm_encrypt] to encrypt room
messages. Rotate (create a new one) on membership changes or after
your chosen number-of-messages / time threshold.
}
