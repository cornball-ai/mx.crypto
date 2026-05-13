# End-to-end smoke demo: mx.crypto + mx.api against a real homeserver.
#
# Targets a local Conduit (or any Matrix-spec homeserver). Two test
# accounts log in, each holds its own Olm Account; A queries B's keys,
# claims an OTK, opens an Olm session, ships a Megolm session_key over
# to-device, then publishes a Megolm-encrypted room message. B syncs,
# decrypts the to-device Olm pre-key, ingests the session_key, and
# decrypts the room event. Confirms the package primitives plus
# `mx.api 0.1.0.1` transport endpoints are sufficient to wire up E2EE.
#
# This script is intentionally outside the tinytest suite. It hits a
# real network endpoint, mutates server state, and rotates real device
# keys — none of which belongs in `R CMD check`. It is also gated
# behind environment variables so it never runs by accident.
#
# Required env vars:
#   MX_HOMESERVER   base URL, e.g. "http://localhost:6167" for Conduit
#   MX_USER_A       localpart for sender device
#   MX_PASS_A       password for sender
#   MX_USER_B       localpart for receiver device
#   MX_PASS_B       password for receiver
#   MX_ROOM_ID      a room both users have joined
#
# Run with:
#   MX_HOMESERVER=... MX_USER_A=alice MX_PASS_A=... \
#     MX_USER_B=bob MX_PASS_B=... MX_ROOM_ID='!abc:host' \
#     Rscript --vanilla inst/integration/e2e_demo.R

required <- c("MX_HOMESERVER", "MX_USER_A", "MX_PASS_A",
              "MX_USER_B", "MX_PASS_B", "MX_ROOM_ID")
missing <- required[!nzchar(Sys.getenv(required))]
if (length(missing)) {
    stop(sprintf(
        "Missing env vars: %s\nSee header for the full list.",
        paste(missing, collapse = ", ")
    ), call. = FALSE)
}

suppressPackageStartupMessages({
    library(mx.api)
    library(mx.crypto)
})

`%||%` <- function(a, b) if (is.null(a)) b else a

server <- Sys.getenv("MX_HOMESERVER")
room_id <- Sys.getenv("MX_ROOM_ID")

cat("Logging in A and B on", server, "\n")
sA <- mx_login(server, Sys.getenv("MX_USER_A"), Sys.getenv("MX_PASS_A"))
sB <- mx_login(server, Sys.getenv("MX_USER_B"), Sys.getenv("MX_PASS_B"))
cat("  A:", sA$user_id, "/", sA$device_id, "\n")
cat("  B:", sB$user_id, "/", sB$device_id, "\n")

cat("B captures a since-cursor before any traffic flows\n")
syncB0 <- mx_sync(sB, timeout = 0L)
since_B <- syncB0$next_batch

# ---- key publication -----------------------------------------------------

sign_device_keys <- function(account, user_id, device_id) {
    ids <- mxc_account_identity_keys(account)
    unsigned <- list(
        user_id = user_id,
        device_id = device_id,
        algorithms = list("m.olm.v1.curve25519-aes-sha2",
                          "m.megolm.v1.aes-sha2"),
        keys = setNames(
            list(ids$curve25519, ids$ed25519),
            c(paste0("curve25519:", device_id),
              paste0("ed25519:", device_id))
        )
    )
    sig <- mxc_account_sign(account, mx_canonical_json(unsigned))
    out <- unsigned
    out$signatures <- setNames(
        list(setNames(list(sig), paste0("ed25519:", device_id))),
        user_id
    )
    out
}

sign_one_time_keys <- function(account, user_id, device_id, n = 5L) {
    mxc_account_generate_one_time_keys(account, n)
    otks <- mxc_account_one_time_keys(account)
    out <- list()
    for (kid in names(otks)) {
        unsigned <- list(key = otks[[kid]])
        sig <- mxc_account_sign(account, mx_canonical_json(unsigned))
        signed <- unsigned
        signed$signatures <- setNames(
            list(setNames(list(sig), paste0("ed25519:", device_id))),
            user_id
        )
        out[[paste0("signed_curve25519:", kid)]] <- signed
    }
    out
}

acctA <- mxc_account_new()
acctB <- mxc_account_new()
idA <- mxc_account_identity_keys(acctA)
idB <- mxc_account_identity_keys(acctB)

cat("Uploading device + OTKs for A and B\n")
upA <- mx_keys_upload(
    sA,
    device_keys = sign_device_keys(acctA, sA$user_id, sA$device_id),
    one_time_keys = sign_one_time_keys(acctA, sA$user_id, sA$device_id, 5L)
)
mxc_account_mark_published(acctA)

upB <- mx_keys_upload(
    sB,
    device_keys = sign_device_keys(acctB, sB$user_id, sB$device_id),
    one_time_keys = sign_one_time_keys(acctB, sB$user_id, sB$device_id, 5L)
)
mxc_account_mark_published(acctB)

cat("  A OTK counts:",
    paste(names(upA$one_time_key_counts %||% list()),
          unlist(upA$one_time_key_counts %||% list()),
          sep = "=", collapse = " "), "\n")
cat("  B OTK counts:",
    paste(names(upB$one_time_key_counts %||% list()),
          unlist(upB$one_time_key_counts %||% list()),
          sep = "=", collapse = " "), "\n")

# ---- A queries B, claims an OTK, opens Olm + Megolm ---------------------

cat("A queries B's device keys\n")
q <- mx_keys_query(sA, setNames(list(sB$device_id), sB$user_id))
deviceB <- q$device_keys[[sB$user_id]][[sB$device_id]]
stopifnot(!is.null(deviceB))
b_curve <- deviceB$keys[[paste0("curve25519:", sB$device_id)]]
b_ed <- deviceB$keys[[paste0("ed25519:", sB$device_id)]]
stopifnot(b_curve == idB$curve25519, b_ed == idB$ed25519)

cat("A claims an OTK from B\n")
cl <- mx_keys_claim(
    sA,
    setNames(list(setNames(list("signed_curve25519"), sB$device_id)),
             sB$user_id)
)
otk_obj <- cl$one_time_keys[[sB$user_id]][[sB$device_id]]
stopifnot(length(otk_obj) == 1L)
otk_value <- otk_obj[[1]]$key

cat("A opens outbound Olm + Megolm sessions\n")
olmA <- mxc_olm_create_outbound(acctA, b_curve, otk_value)
megolmA <- mxc_megolm_outbound_new()
info <- mxc_megolm_outbound_info(megolmA)

cat("A ships m.room_key over Olm via to-device\n")
room_key_payload <- list(
    type = "m.room_key",
    content = list(
        algorithm = "m.megolm.v1.aes-sha2",
        room_id = room_id,
        session_id = info$session_id,
        session_key = info$session_key
    ),
    sender = sA$user_id,
    recipient = sB$user_id,
    recipient_keys = list(ed25519 = b_ed),
    keys = list(ed25519 = idA$ed25519)
)
ct <- mxc_olm_encrypt(olmA, charToRaw(mx_canonical_json(room_key_payload)))
mx_send_to_device(
    sA, "m.room.encrypted",
    setNames(
        list(setNames(list(list(
            algorithm = "m.olm.v1.curve25519-aes-sha2",
            sender_key = idA$curve25519,
            ciphertext = setNames(
                list(list(type = ct$type, body = ct$body)),
                b_curve
            )
        )), sB$device_id)),
        sB$user_id
    )
)

cat("A posts a Megolm-encrypted m.room.encrypted to the room\n")
room_event_plain <- list(
    type = "m.room.message",
    room_id = room_id,
    content = list(
        msgtype = "m.text",
        body = sprintf("mx.crypto smoke test %s", Sys.time())
    )
)
room_ct <- mxc_megolm_encrypt(
    megolmA, charToRaw(mx_canonical_json(room_event_plain))
)
room_send_path <- sprintf(
    "/_matrix/client/v3/rooms/%s/send/%s/%s",
    utils::URLencode(room_id, reserved = TRUE),
    "m.room.encrypted",
    paste0("mxc-", as.integer(Sys.time()), "-",
           sample.int(.Machine$integer.max, 1))
)
# mx.api has no generic raw-HTTP export, so build the room send via curl
# directly. Once mx.client lands this becomes mx_send_encrypted().
h <- curl::new_handle()
curl::handle_setopt(h, customrequest = "PUT")
curl::handle_setheaders(h, .list = list(
    Authorization = paste("Bearer", sA$token),
    `Content-Type` = "application/json",
    Accept = "application/json"
))
curl::handle_setopt(h, postfields = jsonlite::toJSON(list(
    algorithm = "m.megolm.v1.aes-sha2",
    sender_key = idA$curve25519,
    device_id = sA$device_id,
    session_id = info$session_id,
    ciphertext = room_ct
), auto_unbox = TRUE))
resp <- curl::curl_fetch_memory(
    paste0(sub("/$", "", server), room_send_path), handle = h
)
stopifnot(resp$status_code < 400)

# ---- B decrypts ----------------------------------------------------------

cat("B long-polls /sync for the to-device + room event\n")
collect_enc <- function(sync) {
    rooms <- sync$rooms$join %||% list()
    ev_list <- rooms[[room_id]]$timeline$events %||% list()
    Find(function(e) identical(e$type, "m.room.encrypted") &&
                     identical(e$content$session_id, info$session_id),
         ev_list)
}
collect_td <- function(sync) {
    td <- sync$to_device$events %||% list()
    Find(function(e) identical(e$type, "m.room.encrypted") &&
                     identical(e$content$sender_key, idA$curve25519),
         td)
}

cursor <- since_B
ev_td <- NULL
ev_room <- NULL
for (i in seq_len(4L)) {
    s <- mx_sync(sB, since = cursor, timeout = 5000L)
    if (is.null(ev_td)) {
        ev_td <- collect_td(s)
    }
    if (is.null(ev_room)) {
        ev_room <- collect_enc(s)
    }
    cursor <- s$next_batch
    if (!is.null(ev_td) && !is.null(ev_room)) {
        break
    }
}
stopifnot(!is.null(ev_td), !is.null(ev_room))

ctB <- ev_td$content$ciphertext[[idB$curve25519]]
stopifnot(!is.null(ctB))

cat("B decrypts the Olm pre-key, builds inbound Megolm, decrypts the room\n")
inb <- mxc_olm_create_inbound(acctB, ev_td$content$sender_key, ctB$body)
parsed <- jsonlite::fromJSON(rawToChar(inb$plaintext), simplifyVector = FALSE)
stopifnot(identical(parsed$type, "m.room_key"))
stopifnot(identical(parsed$content$session_id, info$session_id))

igsB <- mxc_megolm_inbound_new(parsed$content$session_key)
dec <- mxc_megolm_decrypt(igsB, ev_room$content$ciphertext)
plain_room <- rawToChar(dec$plaintext)
cat("Decrypted room event:\n  ", plain_room, "\n", sep = "")

try(mx_logout(sA), silent = TRUE)
try(mx_logout(sB), silent = TRUE)
cat("Done. Test devices logged out.\n")
