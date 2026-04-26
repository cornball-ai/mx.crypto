library(mx.crypto)

# --- new account ---------------------------------------------------------

acct <- mxc_account_new()
expect_true(is(acct, "externalptr"))

ids <- mxc_account_identity_keys(acct)
expect_equal(sort(names(ids)), c("curve25519", "ed25519"))
expect_true(is.character(ids$curve25519) && nzchar(ids$curve25519))
expect_true(is.character(ids$ed25519) && nzchar(ids$ed25519))
# unpadded base64 of a 32-byte key is 43 chars
expect_equal(nchar(ids$curve25519), 43L)
expect_equal(nchar(ids$ed25519), 43L)

# --- one-time keys -------------------------------------------------------

# Empty pool initially
expect_equal(length(mxc_account_one_time_keys(acct)), 0L)

mxc_account_generate_one_time_keys(acct, 3L)
otks <- mxc_account_one_time_keys(acct)
expect_equal(length(otks), 3L)
expect_true(all(nzchar(names(otks))))
expect_true(all(vapply(otks, function(k) nchar(k) == 43L, logical(1))))

mxc_account_mark_published(acct)
expect_equal(length(mxc_account_one_time_keys(acct)), 0L)

# --- fallback key --------------------------------------------------------

fk <- mxc_account_fallback_key(acct)
expect_equal(sort(names(fk)), c("curve25519", "key_id"))
expect_true(nzchar(fk$key_id))
expect_equal(nchar(fk$curve25519), 43L)

# --- signing -------------------------------------------------------------

sig <- mxc_account_sign(acct, '{"hello":"world"}')
expect_true(is.character(sig) && nchar(sig) > 0L)
# ed25519 signature unpadded base64 is 86 chars
expect_equal(nchar(sig), 86L)

# --- pickle round-trip ---------------------------------------------------

key <- as.raw(seq_len(32) - 1L) # 0x00..0x1f
blob <- mxc_account_pickle(acct, key)
expect_true(is.character(blob) && nchar(blob) > 0L)

acct2 <- mxc_account_unpickle(blob, key)
ids2 <- mxc_account_identity_keys(acct2)
expect_identical(ids$curve25519, ids2$curve25519)
expect_identical(ids$ed25519, ids2$ed25519)

# Wrong key fails
bad_key <- as.raw(rep(0xff, 32))
expect_error(mxc_account_unpickle(blob, bad_key))

# Wrong key length fails up front
expect_error(mxc_account_pickle(acct, raw(31)))
expect_error(mxc_account_pickle(acct, "not raw"))
