% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_create_inbound}
\alias{mxc_olm_create_inbound}
\title{Build an inbound Olm session from a pre-key message}
\usage{
mxc_olm_create_inbound(account, peer_curve25519, prekey_b64)
}
\arguments{
\item{account}{The local Account (will be mutated: an OTK is consumed).}

\item{peer_curve25519}{Sender's curve25519 identity key (base64).}

\item{prekey_b64}{Body of the pre-key message (base64).}
}
\value{
Named list: `session` (external pointer) and `plaintext` (raw).
}
\description{
Consumes the matching one-time key from the local Account. The result
has the new Session and the decrypted plaintext of the pre-key
message; subsequent messages on this session use [mxc_olm_decrypt].
}
