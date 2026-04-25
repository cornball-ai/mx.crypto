library(mx.encrypt)

# Two parties: alice and bob. Bob publishes an OTK; alice initiates.

alice <- mxe_account_new()
bob   <- mxe_account_new()

mxe_account_generate_one_time_keys(bob, 1L)
bob_otks <- mxe_account_one_time_keys(bob)
expect_equal(length(bob_otks), 1L)

bob_idk   <- mxe_account_identity_keys(bob)
alice_idk <- mxe_account_identity_keys(alice)

# Outbound session: alice -> bob
sess_a <- mxe_olm_create_outbound(
  alice,
  peer_curve25519 = bob_idk$curve25519,
  peer_otk        = bob_otks[[1]]
)
expect_true(is(sess_a, "externalptr"))

# Alice encrypts a pre-key message
msg1_pt <- charToRaw("hello bob")
ct1 <- mxe_olm_encrypt(sess_a, msg1_pt)
expect_equal(ct1$type, 0L)
expect_true(nchar(ct1$body) > 0L)

# Bob receives the pre-key, builds inbound session
result <- mxe_olm_create_inbound(
  bob,
  peer_curve25519 = alice_idk$curve25519,
  prekey_b64      = ct1$body
)
expect_true(is(result$session, "externalptr"))
expect_true(is.raw(result$plaintext))
expect_identical(rawToChar(result$plaintext), "hello bob")
sess_b <- result$session

mxe_account_mark_published(bob)

# Bob replies; alice decrypts
msg2_pt <- charToRaw("hi alice")
ct2 <- mxe_olm_encrypt(sess_b, msg2_pt)
# Bob has not received any reply yet, so this is also pre-key
expect_true(ct2$type %in% c(0L, 1L))

dec2 <- mxe_olm_decrypt(sess_a, ct2$type, ct2$body)
expect_identical(rawToChar(dec2), "hi alice")

# Round-trip again now that both sides are warm
ct3 <- mxe_olm_encrypt(sess_a, charToRaw("third"))
dec3 <- mxe_olm_decrypt(sess_b, ct3$type, ct3$body)
expect_identical(rawToChar(dec3), "third")

# --- pickle round-trip ---------------------------------------------------

key <- as.raw(seq_len(32) - 1L)
blob <- mxe_olm_session_pickle(sess_a, key)
sess_a2 <- mxe_olm_session_unpickle(blob, key)

# Continue ratchet on the unpickled session
ct4 <- mxe_olm_encrypt(sess_a2, charToRaw("fourth"))
dec4 <- mxe_olm_decrypt(sess_b, ct4$type, ct4$body)
expect_identical(rawToChar(dec4), "fourth")
