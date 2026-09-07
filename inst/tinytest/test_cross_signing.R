library(mx.crypto)

master <- mxc_signing_key_new()
self <- mxc_signing_key_new()
user <- mxc_signing_key_new()

pub <- vapply(list(master, self, user), mxc_signing_key_public,
              character(1))
expect_equal(length(unique(pub)), 3L)
expect_true(all(nchar(pub) == 43L))

payload <- '{"usage":["self_signing"],"user_id":"@tiny:example.org"}'
sig <- mxc_signing_key_sign(master, payload)
expect_true(mxc_ed25519_verify(pub[[1]], charToRaw(payload), sig))
expect_false(mxc_ed25519_verify(pub[[2]], charToRaw(payload), sig))

pickle_key <- as.raw(seq_len(32L) - 1L)
blob <- mxc_signing_key_pickle(master, pickle_key)
restored <- mxc_signing_key_unpickle(blob, pickle_key)
expect_identical(mxc_signing_key_public(restored), pub[[1]])
expect_true(mxc_ed25519_verify(
  pub[[1]], charToRaw(payload), mxc_signing_key_sign(restored, payload)
))

expect_error(mxc_signing_key_pickle(master, raw(31L)))
expect_error(mxc_signing_key_unpickle(blob, raw(33L)))
