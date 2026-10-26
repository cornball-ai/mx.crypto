% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_attachment_decrypt}
\alias{mxc_attachment_decrypt}
\title{Decrypt and verify a Matrix attachment}
\usage{
mxc_attachment_decrypt(data, file)
}
\arguments{
\item{data}{A raw vector of ciphertext bytes.}

\item{file}{Matrix v2 encrypted-file metadata, including \code{key},
\code{iv}, \code{hashes}, and \code{v}. An optional \code{url} is ignored.}
}
\value{
A raw vector of plaintext bytes. Invalid metadata or a digest
  mismatch raises an error without returning plaintext.
}
\description{
Verifies the ciphertext's SHA-256 digest before returning plaintext.
The metadata must come from an authenticated encrypted room event;
the public digest alone does not authenticate the key or the sender.
}
