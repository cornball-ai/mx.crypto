% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_megolm_decrypt}
\alias{mxc_megolm_decrypt}
\title{Decrypt a room message}
\usage{
mxc_megolm_decrypt(igs, ciphertext_b64)
}
\arguments{
\item{igs}{An InboundGroupSession.}

\item{ciphertext_b64}{Base64 ciphertext (the `ciphertext` field of
the `m.room.encrypted` event).}
}
\value{
Named list: `plaintext` (raw) and `message_index` (integer).
  Use `message_index` to dedupe replays.
}
\description{
Decrypt a room message
}
\examples{
gs <- mxc_megolm_outbound_new()
igs <- mxc_megolm_inbound_new(mxc_megolm_outbound_info(gs)$session_key)
ct <- mxc_megolm_encrypt(gs, charToRaw("hello room"))
dec <- mxc_megolm_decrypt(igs, ct)
rawToChar(dec$plaintext)
dec$message_index
}
