% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_signing_key_new}
\alias{mxc_signing_key_new}
\title{Create a durable Ed25519 signing key}
\usage{
mxc_signing_key_new()
}
\value{
An opaque signing-key handle.
}
\description{
Creates a key suitable for a Matrix cross-signing role. Persist it with
[mxc_signing_key_pickle()]; the private material never needs to be exposed
as a string or raw vector.
}
