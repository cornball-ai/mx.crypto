% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_encrypt}
\alias{mxc_megolm_encrypt}
\title{Encrypt a room message}
\usage{
mxc_megolm_encrypt(gs, plaintext)
}
\arguments{
\item{gs}{An outbound GroupSession.}

\item{plaintext}{A `raw` vector. The caller is responsible for
producing the canonical JSON event body.}
}
\value{
Base64 ciphertext (the `ciphertext` field of `m.room.encrypted`).
}
\description{
Encrypt a room message
}
\examples{
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
rawToChar(mxc_megolm_decrypt(igs, ct)$plaintext)
}
