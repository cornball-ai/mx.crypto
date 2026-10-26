library(mx.crypto)
local({
    bytes <- as.raw(rep(0:255, 3))
    one <- mxc_attachment_encrypt(bytes)
    two <- mxc_attachment_encrypt(bytes)
    expect_identical(length(one$data), length(bytes))
    expect_false(identical(one$data, bytes))
    expect_false(identical(one$data, two$data))
    expect_false(identical(one$file$key$k, two$file$key$k))
    expect_identical(mxc_attachment_decrypt(one$data, one$file), bytes)
    expect_identical(one$file$key$key_ops, list("encrypt", "decrypt"))
    expect_true(grepl("^[A-Za-z0-9_-]{43}$", one$file$key$k))
    expect_true(grepl("^[A-Za-z0-9+/]{22}$", one$file$iv))
    expect_true(grepl("^[A-Za-z0-9+/]{43}$", one$file$hashes$sha256))
    empty <- mxc_attachment_encrypt(raw())
    expect_identical(mxc_attachment_decrypt(empty$data, empty$file), raw())
    tampered <- one$data
    tampered[1] <- as.raw(bitwXor(as.integer(tampered[1]), 1L))
    expect_error(mxc_attachment_decrypt(tampered, one$file), "integrity")
    expect_error(mxc_attachment_decrypt(one$data[-1], one$file), "integrity")
    for (field in c("v", "key", "iv", "hashes")) {
        bad <- one$file
        bad[[field]] <- NULL
        expect_error(mxc_attachment_decrypt(one$data, bad), "metadata")
    }
    for (field in c("kty", "alg", "k", "ext", "key_ops")) {
        bad <- one$file
        bad$key[[field]] <- NULL
        expect_error(mxc_attachment_decrypt(one$data, bad))
    }
    for (value in c("bad!", "AA")) {
        bad <- one$file
        bad$key$k <- value
        expect_error(mxc_attachment_decrypt(one$data, bad), "key")
        bad <- one$file
        bad$iv <- value
        expect_error(mxc_attachment_decrypt(one$data, bad), "IV")
        bad <- one$file
        bad$hashes$sha256 <- value
        expect_error(mxc_attachment_decrypt(one$data, bad))
    }
    expect_error(mxc_attachment_encrypt("not raw"), "raw")
    expect_error(mxc_attachment_decrypt("not raw", one$file), "raw")

    # NIST SP 800-38A F.5.5, first two AES-256-CTR blocks. The hash is
    # independently computed over the published ciphertext, not by this API.
    hex <- function(x) as.raw(strtoi(substring(x, seq(1, nchar(x), 2),
                                               seq(2, nchar(x), 2)), 16L))
    ciphertext <- hex(paste0("601ec313775789a5b7a7f504bbf3d228",
                             "f443e3ca4d62b59aca84e990cacaf5c5"))
    reference <- list(v = "v2", key = list(kty = "oct", alg = "A256CTR",
        ext = TRUE, key_ops = list("encrypt", "decrypt"),
        k = "YD3rEBXKcb4rc67whX13gR81LAc7YQjXLZgQowkU3_Q"),
        iv = "8PHy8/T19vf4+fr7/P3+/w",
        hashes = list(sha256 = "gYXFQj6PebINBoS1Eh0K+zvdqcNfGN5rkKC2mR7QQ54"))
    expect_identical(mxc_attachment_decrypt(ciphertext, reference),
        hex(paste0("6bc1bee22e409f96e93d7e117393172a",
                   "ae2d8a571e03ac9c9eb76fac45af8e51")))
})
