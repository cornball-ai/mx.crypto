library(mx.crypto)

# ============================================================================
# mxc_ed25519_verify — round-trip + tamper
# ============================================================================

acct <- mxc_account_new()
ids <- mxc_account_identity_keys(acct)
msg <- charToRaw("{\"hello\":\"world\"}")
sig <- mxc_account_sign(acct, rawToChar(msg))

# Valid round-trip
expect_true(mxc_ed25519_verify(ids$ed25519, msg, sig))

# Tampered message
expect_false(mxc_ed25519_verify(
  ids$ed25519, charToRaw("{\"hello\":\"WORLD\"}"), sig
))

# Tampered signature (last 6 chars rewritten)
bad_sig <- paste0(substr(sig, 1, 80), "AAAAAA")
expect_false(mxc_ed25519_verify(ids$ed25519, msg, bad_sig))

# Wrong public key
other_acct <- mxc_account_new()
other_ed <- mxc_account_identity_keys(other_acct)$ed25519
expect_false(mxc_ed25519_verify(other_ed, msg, sig))

# Malformed public key / signature both raise errors
expect_error(mxc_ed25519_verify("not-base64!", msg, sig))
expect_error(mxc_ed25519_verify(ids$ed25519, msg, "not-base64!"))
# Wrong-length public key (32 chars instead of 43)
expect_error(mxc_ed25519_verify(strrep("A", 32), msg, sig))
# message must be raw
expect_error(mxc_ed25519_verify(ids$ed25519, "not raw", sig))

# ============================================================================
# Regression: mxc_olm_create_outbound rejects non-contributory DH keys
# ============================================================================

# All-zero curve25519: vodozemac returns Err(NonContributoryKey); mx.crypto
# now propagates that as an R error instead of returning a corrupt
# externalptr.
# 32 zero bytes, base64-encoded. Hardcoded so the test doesn't need
# jsonlite as an unconditional dependency.
zero_curve <- "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
expect_error(
  mxc_olm_create_outbound(acct, zero_curve, zero_curve),
  pattern = "non-contributory|create_outbound_session"
)

# ============================================================================
# mxc_verify_device_keys — happy path + every rejection branch
# ============================================================================

# Build a real, signed device_keys object the way mx.crypto/mx.api wants.
build_dk <- function(account, user_id, device_id) {
  k <- mxc_account_identity_keys(account)
  unsigned <- list(
    user_id = user_id,
    device_id = device_id,
    algorithms = list("m.olm.v1.curve25519-aes-sha2",
                      "m.megolm.v1.aes-sha2"),
    keys = setNames(
      list(k$curve25519, k$ed25519),
      c(paste0("curve25519:", device_id),
        paste0("ed25519:", device_id))
    )
  )
  s <- mxc_account_sign(account, mx.api::mx_canonical_json(unsigned))
  out <- unsigned
  out$signatures <- setNames(
    list(setNames(list(s), paste0("ed25519:", device_id))),
    user_id
  )
  out
}

if (requireNamespace("mx.api", quietly = TRUE) &&
    utils::packageVersion("mx.api") >= "0.2.0") {
  alice <- mxc_account_new()
  alice_ids <- mxc_account_identity_keys(alice)
  dk_ok <- build_dk(alice, "@alice:example.org", "ALICEDEV")

  # Happy path — returns the verified keys
  keys <- mxc_verify_device_keys(dk_ok, "@alice:example.org", "ALICEDEV")
  expect_equal(keys$curve25519, alice_ids$curve25519)
  expect_equal(keys$ed25519, alice_ids$ed25519)

  # Wrong expected user id
  expect_error(
    mxc_verify_device_keys(dk_ok, "@mallory:example.org", "ALICEDEV"),
    pattern = "user_id mismatch"
  )

  # Wrong expected device id
  expect_error(
    mxc_verify_device_keys(dk_ok, "@alice:example.org", "OTHERDEV"),
    pattern = "device_id mismatch"
  )

  # Missing curve25519
  bad <- dk_ok
  bad$keys[[paste0("curve25519:", "ALICEDEV")]] <- NULL
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "missing curve25519"
  )

  # Missing ed25519
  bad <- dk_ok
  bad$keys[[paste0("ed25519:", "ALICEDEV")]] <- NULL
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "missing ed25519"
  )

  # No signatures block
  bad <- dk_ok
  bad$signatures <- NULL
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "unsigned"
  )

  # Signature under the wrong user id (homeserver re-signs alice's keys
  # as if they were mallory's)
  mallory <- mxc_account_new()
  mallory_sig <- mxc_account_sign(
    mallory,
    mx.api::mx_canonical_json(within(dk_ok, signatures <- NULL))
  )
  bad <- dk_ok
  bad$signatures <- setNames(
    list(setNames(list(mallory_sig), paste0("ed25519:", "ALICEDEV"))),
    "@mallory:example.org"
  )
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "no signatures from"
  )

  # Mutated keys content — signature no longer matches
  bad <- dk_ok
  bad$keys[[paste0("curve25519:", "ALICEDEV")]] <- mxc_account_identity_keys(
    mxc_account_new()
  )$curve25519
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "did not verify"
  )

  # Signature attached under wrong device id (ed25519:OTHERDEV instead of
  # ed25519:ALICEDEV)
  bad <- dk_ok
  bad$signatures[["@alice:example.org"]] <- setNames(
    list(bad$signatures[["@alice:example.org"]][[paste0("ed25519:",
                                                        "ALICEDEV")]]),
    paste0("ed25519:", "OTHERDEV")
  )
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "no ed25519:ALICEDEV signature"
  )

  # algorithms: missing entirely
  bad <- dk_ok
  bad$algorithms <- NULL
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "missing 'algorithms'"
  )

  # algorithms: present but missing the required Olm algorithm
  bad <- dk_ok
  bad$algorithms <- list("m.megolm.v1.aes-sha2")  # no olm
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "missing required entries.*m\\.olm"
  )

  # algorithms: empty list
  bad <- dk_ok
  bad$algorithms <- list()
  expect_error(
    mxc_verify_device_keys(bad, "@alice:example.org", "ALICEDEV"),
    pattern = "non-empty"
  )

  # algorithms: opt out via required_algorithms = character(0) still passes
  bad <- dk_ok
  bad$algorithms <- NULL
  expect_silent(mxc_verify_device_keys(
    dk_ok, "@alice:example.org", "ALICEDEV",
    required_algorithms = character(0)
  ))

  # ==========================================================================
  # mxc_verify_one_time_key — happy path + every rejection branch
  # ==========================================================================

  mxc_account_generate_one_time_keys(alice, 1L)
  otks <- mxc_account_one_time_keys(alice)
  otk_kid <- names(otks)[[1L]]
  otk_key <- otks[[1L]]
  unsigned_otk <- list(key = otk_key)
  s <- mxc_account_sign(alice, mx.api::mx_canonical_json(unsigned_otk))
  otk_ok <- list(
    key = otk_key,
    signatures = setNames(
      list(setNames(list(s), paste0("ed25519:", "ALICEDEV"))),
      "@alice:example.org"
    )
  )
  algo_kid_ok <- paste0("signed_curve25519:", otk_kid)

  # Happy path
  verified <- mxc_verify_one_time_key(
    algo_kid_ok, otk_ok, alice_ids$ed25519,
    "@alice:example.org", "ALICEDEV"
  )
  expect_equal(verified, otk_key)

  # Wrong signing key (mallory's ed25519 instead of alice's)
  mallory_ids <- mxc_account_identity_keys(mallory)
  expect_error(
    mxc_verify_one_time_key(
      algo_kid_ok, otk_ok, mallory_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "did not verify"
  )

  # Missing key field
  bad <- otk_ok
  bad$key <- NULL
  expect_error(
    mxc_verify_one_time_key(
      algo_kid_ok, bad, alice_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "missing 'key'"
  )

  # Unsigned
  bad <- otk_ok
  bad$signatures <- NULL
  expect_error(
    mxc_verify_one_time_key(
      algo_kid_ok, bad, alice_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "unsigned"
  )

  # Wrong user signed it
  bad <- otk_ok
  bad$signatures <- setNames(bad$signatures, "@mallory:example.org")
  expect_error(
    mxc_verify_one_time_key(
      algo_kid_ok, bad, alice_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "no signatures from"
  )

  # Mutated key — signature mismatch
  bad <- otk_ok
  bad$key <- mxc_account_identity_keys(mxc_account_new())$curve25519
  expect_error(
    mxc_verify_one_time_key(
      algo_kid_ok, bad, alice_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "did not verify"
  )

  # Wrong algorithm prefix on the outer map key
  expect_error(
    mxc_verify_one_time_key(
      paste0("curve25519:", otk_kid), otk_ok, alice_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "does not start with"
  )
  expect_error(
    mxc_verify_one_time_key(
      paste0("signed_ed25519:", otk_kid), otk_ok, alice_ids$ed25519,
      "@alice:example.org", "ALICEDEV"
    ),
    pattern = "does not start with"
  )
  # Empty / NA algorithm_key_id
  expect_error(
    mxc_verify_one_time_key("", otk_ok, alice_ids$ed25519,
                            "@alice:example.org", "ALICEDEV"),
    pattern = "non-empty"
  )
  expect_error(
    mxc_verify_one_time_key(NA_character_, otk_ok, alice_ids$ed25519,
                            "@alice:example.org", "ALICEDEV"),
    pattern = "non-empty"
  )

  # 'key' value that is signed but not a valid curve25519 public key.
  # Build a fresh otk_object where the key is garbage bytes, signed
  # correctly by alice. The signature is over the canonical_json of
  # {"key": "<garbage>"}, so it verifies — but the curve25519 check
  # must still reject before mxc_olm_create_outbound ever sees it.
  bogus_key <- "AAAA"  # short base64, not 32 bytes
  bogus_unsigned <- list(key = bogus_key)
  bogus_sig <- mxc_account_sign(alice,
                                mx.api::mx_canonical_json(bogus_unsigned))
  bogus_otk <- list(
    key = bogus_key,
    signatures = setNames(
      list(setNames(list(bogus_sig), paste0("ed25519:", "ALICEDEV"))),
      "@alice:example.org"
    )
  )
  expect_error(
    mxc_verify_one_time_key(
      paste0("signed_curve25519:invalid"), bogus_otk,
      alice_ids$ed25519, "@alice:example.org", "ALICEDEV"
    ),
    pattern = "valid curve25519 public key"
  )
}
