library(mx.encrypt)

# Outbound (sender) ----------------------------------------------------

gs <- mxe_megolm_outbound_new()
expect_true(is(gs, "externalptr"))

info <- mxe_megolm_outbound_info(gs)
expect_equal(sort(names(info)),
             c("message_index", "session_id", "session_key"))
expect_true(nzchar(info$session_id))
expect_true(nzchar(info$session_key))
expect_equal(info$message_index, 0L)

# Inbound (receiver) ---------------------------------------------------

igs <- mxe_megolm_inbound_new(info$session_key)
expect_true(is(igs, "externalptr"))

# Encrypt / decrypt round-trip ----------------------------------------

ct1_b64 <- mxe_megolm_encrypt(gs, charToRaw("hello room"))
expect_true(is.character(ct1_b64) && nchar(ct1_b64) > 0L)

dec1 <- mxe_megolm_decrypt(igs, ct1_b64)
expect_equal(sort(names(dec1)), c("message_index", "plaintext"))
expect_identical(rawToChar(dec1$plaintext), "hello room")
expect_equal(dec1$message_index, 0L)

# message_index advances
ct2_b64 <- mxe_megolm_encrypt(gs, charToRaw("again"))
dec2 <- mxe_megolm_decrypt(igs, ct2_b64)
expect_identical(rawToChar(dec2$plaintext), "again")
expect_equal(dec2$message_index, 1L)

# outbound info reflects the advance
info2 <- mxe_megolm_outbound_info(gs)
expect_equal(info2$message_index, 2L)
expect_identical(info2$session_id, info$session_id)

# Pickle round-trip ----------------------------------------------------

key <- as.raw(seq_len(32) - 1L)

# outbound
blob_out <- mxe_megolm_outbound_pickle(gs, key)
gs2 <- mxe_megolm_outbound_unpickle(blob_out, key)
ct3_b64 <- mxe_megolm_encrypt(gs2, charToRaw("after pickle"))
dec3 <- mxe_megolm_decrypt(igs, ct3_b64)
expect_identical(rawToChar(dec3$plaintext), "after pickle")

# inbound
blob_in <- mxe_megolm_inbound_pickle(igs, key)
igs2 <- mxe_megolm_inbound_unpickle(blob_in, key)
ct4_b64 <- mxe_megolm_encrypt(gs2, charToRaw("after both pickles"))
dec4 <- mxe_megolm_decrypt(igs2, ct4_b64)
expect_identical(rawToChar(dec4$plaintext), "after both pickles")

# Wrong key length fails up front
expect_error(mxe_megolm_outbound_pickle(gs, raw(31)))
expect_error(mxe_megolm_inbound_pickle(igs, raw(33)))
