% tinyrox says don't edit this manually, but it can't stop you!
\name{mxc_attachment_encrypt}
\alias{mxc_attachment_encrypt}
\title{Encrypt a Matrix attachment}
\usage{
mxc_attachment_encrypt(data)
}
\arguments{
\item{data}{A raw vector of plaintext bytes.}
}
\value{
A list with ciphertext \code{data} and Matrix v2 \code{file}
  metadata. The metadata contains the secret decryption key.
}
\description{
Encrypts bytes with a fresh AES-256-CTR key and random 64-bit nonce.
The 64-bit counter starts at zero. The caller uploads only \code{data}
and sends \code{file}, with the upload's \code{url} added, inside an
encrypted room event. No HTTP or account state is used here.
}
