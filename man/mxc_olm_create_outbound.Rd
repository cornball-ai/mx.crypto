% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_olm_create_outbound}
\alias{mxc_olm_create_outbound}
\title{Start an outbound Olm session}
\usage{
mxc_olm_create_outbound(account, peer_curve25519, peer_otk)
}
\arguments{
\item{account}{The local Account.}

\item{peer_curve25519}{Peer's curve25519 identity key (base64).}

\item{peer_otk}{Peer's one-time key (base64).}
}
\value{
An Olm Session external pointer.
}
\description{
Use a peer's published curve25519 identity key + one of their signed
one-time keys to bootstrap a 1:1 ratchet. The first ciphertext from
this session is a pre-key message (`type = 0`).
}
