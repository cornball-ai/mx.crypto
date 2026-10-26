#' Encrypt a Matrix attachment
#'
#' Encrypts bytes with a fresh AES-256-CTR key and random 64-bit nonce.
#' The 64-bit counter starts at zero. The caller uploads only \code{data}
#' and sends \code{file}, with the upload's \code{url} added, inside an
#' encrypted room event. No HTTP or account state is used here.
#' @param data A raw vector of plaintext bytes.
#' @return A list with ciphertext \code{data} and Matrix v2 \code{file}
#'   metadata. The metadata contains the secret decryption key.
#' @export
mxc_attachment_encrypt <- function(data) {
    out <- .Call(.attachment__mxc_attachment_encrypt, data)
    list(data = out$data,
         file = list(key = list(kty = "oct", key_ops = list("encrypt", "decrypt"),
                                alg = "A256CTR", k = out$key, ext = TRUE),
                     iv = out$iv, hashes = list(sha256 = out$sha256), v = "v2"))
}

#' Decrypt and verify a Matrix attachment
#'
#' Verifies the ciphertext's SHA-256 digest before returning plaintext.
#' The metadata must come from an authenticated encrypted room event;
#' the public digest alone does not authenticate the key or the sender.
#' @param data A raw vector of ciphertext bytes.
#' @param file Matrix v2 encrypted-file metadata, including \code{key},
#'   \code{iv}, \code{hashes}, and \code{v}. An optional \code{url} is ignored.
#' @return A raw vector of plaintext bytes. Invalid metadata or a digest
#'   mismatch raises an error without returning plaintext.
#' @export
mxc_attachment_decrypt <- function(data, file) {
    scalar <- function(x) is.character(x) && length(x) == 1L && !is.na(x) && nzchar(x)
    if (!is.list(file) || !identical(file$v, "v2") || !is.list(file$key) ||
        !identical(file$key$kty, "oct") || !identical(file$key$alg, "A256CTR") ||
        !isTRUE(file$key$ext) || !"decrypt" %in% unlist(file$key$key_ops) ||
        !scalar(file$key$k) || !scalar(file$iv) || !is.list(file$hashes) ||
        !scalar(file$hashes$sha256)) {
        stop("invalid Matrix v2 attachment metadata", call. = FALSE)
    }
    .Call(.attachment__mxc_attachment_decrypt, data, file$key$k, file$iv,
          file$hashes$sha256)
}
