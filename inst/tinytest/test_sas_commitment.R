library(tinytest)
library(mx.crypto)
# Independent OpenSSL SHA-256 vector over the literal public key plus {}.
public <- "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
expect_identical(mxc_sas_commitment(public, "{}"),
    "vF46+KF5GpVlvkZWx+0kYShxXlO4Nuj8pq5lG7M3//o")
expect_false(identical(mxc_sas_commitment(public, "{}"),
    mxc_sas_commitment(public, "{ }")))
expect_error(mxc_sas_commitment("bad", "{}"), "public key")
expect_error(mxc_sas_commitment(NA_character_, "{}"))
