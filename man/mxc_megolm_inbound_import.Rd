% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_inbound_import}
\alias{mxc_megolm_inbound_import}
\title{Import a forwarded inbound Megolm session}
\usage{
mxc_megolm_inbound_import(session_key)
}
\arguments{
\item{session_key}{Base64 exported session key.}
}
\value{
An InboundGroupSession external pointer.
}
\description{
Imports the exported session-key format carried by
`m.forwarded_room_key`. Unlike [mxc_megolm_inbound_new()], the resulting
session does not treat the original sender signature as verified; the
caller must validate the forwarding chain and sender identity.
}
\examples{
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
fwd <- mxc_megolm_inbound_import(mxc_megolm_inbound_export(igs))
ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
rawToChar(mxc_megolm_decrypt(fwd, ct)$plaintext)
}
