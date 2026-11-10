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
\examples{
alice <- mxc_account_new()
bob <- mxc_account_new()
mxc_account_generate_one_time_keys(bob, 1L)
bob_key <- mxc_account_identity_keys(bob)$curve25519
bob_otk <- mxc_account_one_time_keys(bob)[[1]]
sess <- mxc_olm_create_outbound(alice, bob_key, bob_otk)
}
