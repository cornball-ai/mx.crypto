library(mx.crypto)

# Two parties: alice and bob. Bob publishes an OTK; alice initiates.

alice <- mxc_account_new()
bob   <- mxc_account_new()

mxc_account_generate_one_time_keys(bob, 1L)
bob_otks <- mxc_account_one_time_keys(bob)
expect_equal(length(bob_otks), 1L)

bob_idk   <- mxc_account_identity_keys(bob)
alice_idk <- mxc_account_identity_keys(alice)

# Outbound session: alice -> bob
sess_a <- mxc_olm_create_outbound(
  alice,
  peer_curve25519 = bob_idk$curve25519,
  peer_otk        = bob_otks[[1]]
)
expect_true(is(sess_a, "externalptr"))

# Alice encrypts a pre-key message
msg1_pt <- charToRaw("hello bob")
ct1 <- mxc_olm_encrypt(sess_a, msg1_pt)
expect_equal(ct1$type, 0L)
expect_true(nchar(ct1$body) > 0L)

# Bob receives the pre-key, builds inbound session
result <- mxc_olm_create_inbound(
  bob,
  peer_curve25519 = alice_idk$curve25519,
  prekey_b64      = ct1$body
)
expect_true(is(result$session, "externalptr"))
expect_true(is.raw(result$plaintext))
expect_identical(rawToChar(result$plaintext), "hello bob")
sess_b <- result$session

mxc_account_mark_published(bob)

# Bob replies; alice decrypts
msg2_pt <- charToRaw("hi alice")
ct2 <- mxc_olm_encrypt(sess_b, msg2_pt)
# Bob has not received any reply yet, so this is also pre-key
expect_true(ct2$type %in% c(0L, 1L))

dec2 <- mxc_olm_decrypt(sess_a, ct2$type, ct2$body)
expect_identical(rawToChar(dec2), "hi alice")

# Round-trip again now that both sides are warm
ct3 <- mxc_olm_encrypt(sess_a, charToRaw("third"))
dec3 <- mxc_olm_decrypt(sess_b, ct3$type, ct3$body)
expect_identical(rawToChar(dec3), "third")

# --- pickle round-trip ---------------------------------------------------

key <- as.raw(seq_len(32) - 1L)
blob <- mxc_olm_session_pickle(sess_a, key)
sess_a2 <- mxc_olm_session_unpickle(blob, key)

# Continue ratchet on the unpickled session
ct4 <- mxc_olm_encrypt(sess_a2, charToRaw("fourth"))
dec4 <- mxc_olm_decrypt(sess_b, ct4$type, ct4$body)
expect_identical(rawToChar(dec4), "fourth")

# --- unpadded base64 bodies (vodozemac / matrix-dart-sdk wire form) -------
# libolm padded Olm message bodies; vodozemac (matrix-dart-sdk 10.x,
# Element) emits them UNPADDED. The decoder must accept both, or every body
# whose length is not a multiple of 4 is dropped -- the root cause of the
# MatrixRTC call-key decryption failure (2026-10-07). Both create_inbound
# and decrypt go through the same base64 engine. Varying the plaintext
# length walks the base64 length modulo so a genuinely padded body is hit.

# Olm ciphertext is AES-CBC, so plaintext length only changes the body
# length when it crosses a 16-byte block boundary; these lengths step
# across blocks so the base64 length modulo (and thus padding) varies.
lens <- c(5L, 20L, 36L, 52L, 68L)

# create_inbound: find a pre-key body that carries padding, strip it, and
# confirm the inbound session still opens.
sess_c <- NULL
sess_d <- NULL
for (n in lens) {
  carol <- mxc_account_new()
  dave  <- mxc_account_new()
  mxc_account_generate_one_time_keys(dave, 1L)
  sc <- mxc_olm_create_outbound(carol, mxc_account_identity_keys(dave)$curve25519,
                                mxc_account_one_time_keys(dave)[[1]])
  pre <- mxc_olm_encrypt(sc, charToRaw(strrep("x", n)))
  if (grepl("=$", pre$body)) {
    res_u <- mxc_olm_create_inbound(dave,
                                    mxc_account_identity_keys(carol)$curve25519,
                                    sub("=+$", "", pre$body))
    expect_identical(rawToChar(res_u$plaintext), strrep("x", n))
    sess_c <- sc
    sess_d <- res_u$session
    break
  }
}
expect_false(is.null(sess_d))  # a padded pre-key body was found and opened

# decrypt: a padded normal body, stripped, still decrypts.
if (!is.null(sess_d)) {
  saw_padding <- FALSE
  for (n in lens) {
    m <- mxc_olm_encrypt(sess_c, charToRaw(strrep("y", n)))
    if (grepl("=$", m$body)) {
      saw_padding <- TRUE
      dec <- mxc_olm_decrypt(sess_d, m$type, sub("=+$", "", m$body))
      expect_identical(rawToChar(dec), strrep("y", n))
    } else {
      mxc_olm_decrypt(sess_d, m$type, m$body)  # keep the ratchet in order
    }
  }
  expect_true(saw_padding)
}

# Padded bodies (libolm senders) must keep working too.
ep <- mxc_account_new()
fp <- mxc_account_new()
mxc_account_generate_one_time_keys(fp, 1L)
sess_e <- mxc_olm_create_outbound(ep, mxc_account_identity_keys(fp)$curve25519,
                                  mxc_account_one_time_keys(fp)[[1]])
pp <- mxc_olm_encrypt(sess_e, charToRaw("padded still ok"))
res_p <- mxc_olm_create_inbound(fp, mxc_account_identity_keys(ep)$curve25519,
                                pp$body)
expect_identical(rawToChar(res_p$plaintext), "padded still ok")
