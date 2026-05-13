# mx.crypto integration scripts

Live network demos that hit a real Matrix homeserver. None of these run
under `R CMD check`, by design.

## e2e_demo.R

Exercises the full round-trip: device-key upload, key query, OTK claim,
Olm handshake, Megolm session sharing via to-device, Megolm-encrypted
room message, and inbound decrypt on the receiver. Uses `mx.api`
(0.1.0.1+) for transport and `mx.crypto` for crypto.

### Requirements

* `mx.api (>= 0.1.0.1)` installed.
* A reachable homeserver. A local Conduit instance is the easiest path
  (`docker run --rm -p 6167:6167 ...`); Synapse works the same way.
* Two accounts on that homeserver who have both joined the same room.

### Environment

| Var             | Meaning                                                       |
|-----------------|---------------------------------------------------------------|
| `MX_HOMESERVER` | Base URL, e.g. `http://localhost:6167`                        |
| `MX_USER_A`     | Localpart for the sender (e.g. `alice`)                       |
| `MX_PASS_A`     | Password for the sender                                       |
| `MX_USER_B`     | Localpart for the receiver (e.g. `bob`)                       |
| `MX_PASS_B`     | Password for the receiver                                     |
| `MX_ROOM_ID`    | Room id both users have joined, e.g. `!xyz:localhost`         |

### Run

```bash
MX_HOMESERVER=http://localhost:6167 \
MX_USER_A=alice MX_PASS_A=alicepass \
MX_USER_B=bob   MX_PASS_B=bobpass \
MX_ROOM_ID='!xyz:localhost' \
Rscript --vanilla "$(Rscript -e 'cat(system.file("integration/e2e_demo.R", package = "mx.crypto"))')"
```

Expected tail of output:

```
B decrypts the Olm pre-key, builds inbound Megolm, decrypts the room
Decrypted room event:
  {"content":{"body":"mx.crypto smoke test ..."},"room_id":"...","type":"m.room.message"}
Done. Test devices logged out.
```

### Notes

* The script creates fresh device ids on each run and uploads new
  identity / one-time keys for them. Existing devices on the same
  accounts are unaffected.
* The room does not need to have `m.room.encryption` set; the script
  emits `m.room.encrypted` events directly. Clients without the
  Megolm session won't decrypt them — that's the point of the demo.
* Once `mx.client` lands, the hand-rolled `curl` PUT for the room send
  will be replaced with `mx.client::mx_send_encrypted()`.
