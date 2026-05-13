// mx.crypto: Olm + Megolm primitives wrapping vodozemac for R.
//
// Stateful objects (Account, Session, GroupSession, InboundGroupSession)
// are returned to R as externalptr SEXPs; R's finalizer drops the boxed
// Rust value when the SEXP is GC'd. Keys/ciphertext travel as base64
// strings (Matrix wire format), plaintexts as raw vectors. Pickle keys
// must be raw(32); R wrappers validate length before crossing.

roxido_registration!();
use roxido::*;

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use vodozemac::megolm::{
    GroupSession, GroupSessionPickle, InboundGroupSession, InboundGroupSessionPickle,
    MegolmMessage, SessionConfig as MegolmSessionConfig, SessionKey,
};
use vodozemac::olm::{
    Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle,
};
use vodozemac::Curve25519PublicKey;
use vodozemac::Ed25519PublicKey;
use vodozemac::Ed25519Signature;

const TAG_ACCOUNT: &str = "mx.crypto::Account";
const TAG_OLM_SESSION: &str = "mx.crypto::OlmSession";
const TAG_GROUP_SESSION: &str = "mx.crypto::GroupSession";
const TAG_INBOUND_GROUP_SESSION: &str = "mx.crypto::InboundGroupSession";

// -- helpers -----------------------------------------------------------

fn pickle_key_from(robj: &RObject) -> [u8; 32] {
    let v = robj.as_vector().stop_str("key must be raw(32)");
    let raw = v.as_u8().stop_str("key must be raw(32)");
    let bytes = raw.slice();
    if bytes.len() != 32 {
        stop!("key must be raw(32) (got {} bytes)", bytes.len());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(bytes);
    k
}

fn raw_bytes(robj: &RObject) -> &[u8] {
    let v = robj.as_vector().stop_str("expected raw vector");
    let raw = v.as_u8().stop_str("expected raw vector");
    raw.slice()
}

fn b64_to_curve25519(s: &str) -> Curve25519PublicKey {
    Curve25519PublicKey::from_base64(s).stop_str("invalid curve25519 base64 key")
}

// -- Account -----------------------------------------------------------

#[roxido]
fn mxc_account_new() {
    let acct = Account::new();
    RExternalPtr::encode(acct, TAG_ACCOUNT, pc)
}

#[roxido]
fn mxc_account_identity_keys(account: &RObject) {
    let ext = account.as_external_ptr().stop_str("expected externalptr");
    let acct: &Account = ext.decode_ref();
    let ids = acct.identity_keys();
    let curve = ids.curve25519.to_base64();
    let ed = ids.ed25519.to_base64();
    let out = RList::with_names(&["curve25519", "ed25519"], pc);
    out.set(0, curve.as_str().to_r(pc)).stop();
    out.set(1, ed.as_str().to_r(pc)).stop();
    out
}

#[roxido]
fn mxc_account_sign(account: &RObject, canonical_json: &str) {
    let ext = account.as_external_ptr().stop_str("expected externalptr");
    let acct: &Account = ext.decode_ref();
    let sig = acct.sign(canonical_json).to_base64();
    sig.as_str().to_r(pc)
}

#[roxido]
fn mxc_account_generate_one_time_keys(account: &mut RObject, n: usize) {
    let ext = account
        .as_external_ptr_mut()
        .stop_str("expected externalptr");
    let acct: &mut Account = ext.decode_mut();
    acct.generate_one_time_keys(n);
}

#[roxido]
fn mxc_account_one_time_keys(account: &RObject) {
    let ext = account.as_external_ptr().stop_str("expected externalptr");
    let acct: &Account = ext.decode_ref();
    let keys = acct.one_time_keys();
    let mut id_strs: Vec<String> = Vec::with_capacity(keys.len());
    let mut val_strs: Vec<String> = Vec::with_capacity(keys.len());
    for (id, key) in keys.iter() {
        id_strs.push(id.to_base64());
        val_strs.push(key.to_base64());
    }
    let id_refs: Vec<&str> = id_strs.iter().map(String::as_str).collect();
    let out = RList::with_names(&id_refs, pc);
    for (i, v) in val_strs.iter().enumerate() {
        out.set(i, v.as_str().to_r(pc)).stop();
    }
    out
}

#[roxido]
fn mxc_account_mark_published(account: &mut RObject) {
    let ext = account
        .as_external_ptr_mut()
        .stop_str("expected externalptr");
    let acct: &mut Account = ext.decode_mut();
    acct.mark_keys_as_published();
}

#[roxido]
fn mxc_account_fallback_key(account: &mut RObject) {
    let ext = account
        .as_external_ptr_mut()
        .stop_str("expected externalptr");
    let acct: &mut Account = ext.decode_mut();
    acct.generate_fallback_key();
    let fk = acct.fallback_key();
    let (id, key) = fk
        .into_iter()
        .next()
        .stop_str("no fallback key produced");
    let id_b64 = id.to_base64();
    let key_b64 = key.to_base64();
    let out = RList::with_names(&["key_id", "curve25519"], pc);
    out.set(0, id_b64.as_str().to_r(pc)).stop();
    out.set(1, key_b64.as_str().to_r(pc)).stop();
    out
}

#[roxido]
fn mxc_account_pickle(account: &RObject, key: &RObject) {
    let ext = account.as_external_ptr().stop_str("expected externalptr");
    let acct: &Account = ext.decode_ref();
    let k = pickle_key_from(key);
    let blob = acct.pickle().encrypt(&k);
    blob.as_str().to_r(pc)
}

#[roxido]
fn mxc_account_unpickle(blob: &str, key: &RObject) {
    let k = pickle_key_from(key);
    let pickle = AccountPickle::from_encrypted(blob, &k).stop_str("invalid account pickle");
    let acct = Account::from_pickle(pickle);
    RExternalPtr::encode(acct, TAG_ACCOUNT, pc)
}

// -- Olm sessions ------------------------------------------------------

#[roxido]
fn mxc_olm_create_outbound(account: &RObject, peer_curve25519: &str, peer_otk: &str) {
    let ext = account.as_external_ptr().stop_str("expected externalptr");
    let acct: &Account = ext.decode_ref();
    let id_key = b64_to_curve25519(peer_curve25519);
    let otk = b64_to_curve25519(peer_otk);
    let sess = acct
        .create_outbound_session(SessionConfig::version_1(), id_key, otk)
        .stop_str(
            "create_outbound_session failed (e.g. non-contributory \
             Diffie-Hellman key)",
        );
    RExternalPtr::encode(sess, TAG_OLM_SESSION, pc)
}

#[roxido]
fn mxc_olm_create_inbound(account: &mut RObject, peer_curve25519: &str, prekey_b64: &str) {
    let ext = account
        .as_external_ptr_mut()
        .stop_str("expected externalptr");
    let acct: &mut Account = ext.decode_mut();
    let id_key = b64_to_curve25519(peer_curve25519);
    let body_bytes = B64
        .decode(prekey_b64)
        .stop_str("prekey body is not valid base64");
    let msg = OlmMessage::from_parts(0, &body_bytes).stop_str("invalid prekey message");
    let prekey = match msg {
        OlmMessage::PreKey(m) => m,
        OlmMessage::Normal(_) => stop!("expected pre-key olm message (type 0)"),
    };
    let result = acct
        .create_inbound_session(SessionConfig::version_1(), id_key, &prekey)
        .stop_str("create_inbound_session failed");
    let session_ptr = RExternalPtr::encode(result.session, TAG_OLM_SESSION, pc);
    let plaintext_vec = (&result.plaintext[..]).to_r(pc);
    let out = RList::with_names(&["session", "plaintext"], pc);
    out.set(0, session_ptr).stop();
    out.set(1, plaintext_vec).stop();
    out
}

#[roxido]
fn mxc_olm_encrypt(session: &mut RObject, plaintext: &RObject) {
    let ext = session
        .as_external_ptr_mut()
        .stop_str("expected externalptr");
    let sess: &mut Session = ext.decode_mut();
    let pt = raw_bytes(plaintext);
    let msg = sess.encrypt(pt).stop_str("olm encrypt failed");
    let (mtype, body_bytes) = msg.to_parts();
    let body_b64 = B64.encode(&body_bytes);
    let out = RList::with_names(&["type", "body"], pc);
    out.set(0, (mtype as i32).to_r(pc)).stop();
    out.set(1, body_b64.as_str().to_r(pc)).stop();
    out
}

#[roxido]
fn mxc_olm_decrypt(session: &mut RObject, message_type: i32, body: &str) {
    let ext = session
        .as_external_ptr_mut()
        .stop_str("expected externalptr");
    let sess: &mut Session = ext.decode_mut();
    let body_bytes = B64
        .decode(body)
        .stop_str("olm body is not valid base64");
    let msg = OlmMessage::from_parts(message_type as usize, &body_bytes)
        .stop_str("invalid olm message");
    let pt = sess.decrypt(&msg).stop_str("olm decrypt failed");
    (&pt[..]).to_r(pc)
}

#[roxido]
fn mxc_olm_session_pickle(session: &RObject, key: &RObject) {
    let ext = session.as_external_ptr().stop_str("expected externalptr");
    let sess: &Session = ext.decode_ref();
    let k = pickle_key_from(key);
    let blob = sess.pickle().encrypt(&k);
    blob.as_str().to_r(pc)
}

#[roxido]
fn mxc_olm_session_unpickle(blob: &str, key: &RObject) {
    let k = pickle_key_from(key);
    let pickle = SessionPickle::from_encrypted(blob, &k).stop_str("invalid session pickle");
    let sess = Session::from_pickle(pickle);
    RExternalPtr::encode(sess, TAG_OLM_SESSION, pc)
}

// -- Megolm: outbound (sender) -----------------------------------------

#[roxido]
fn mxc_megolm_outbound_new() {
    let gs = GroupSession::new(MegolmSessionConfig::version_1());
    RExternalPtr::encode(gs, TAG_GROUP_SESSION, pc)
}

#[roxido]
fn mxc_megolm_outbound_info(gs: &RObject) {
    let ext = gs.as_external_ptr().stop_str("expected externalptr");
    let g: &GroupSession = ext.decode_ref();
    let sid = g.session_id();
    let skey = g.session_key().to_base64();
    let idx = g.message_index() as i32;
    let out = RList::with_names(&["session_id", "session_key", "message_index"], pc);
    out.set(0, sid.as_str().to_r(pc)).stop();
    out.set(1, skey.as_str().to_r(pc)).stop();
    out.set(2, idx.to_r(pc)).stop();
    out
}

#[roxido]
fn mxc_megolm_encrypt(gs: &mut RObject, plaintext: &RObject) {
    let ext = gs.as_external_ptr_mut().stop_str("expected externalptr");
    let g: &mut GroupSession = ext.decode_mut();
    let pt = raw_bytes(plaintext);
    let msg = g.encrypt(pt);
    let body = msg.to_base64();
    body.as_str().to_r(pc)
}

#[roxido]
fn mxc_megolm_outbound_pickle(gs: &RObject, key: &RObject) {
    let ext = gs.as_external_ptr().stop_str("expected externalptr");
    let g: &GroupSession = ext.decode_ref();
    let k = pickle_key_from(key);
    let blob = g.pickle().encrypt(&k);
    blob.as_str().to_r(pc)
}

#[roxido]
fn mxc_megolm_outbound_unpickle(blob: &str, key: &RObject) {
    let k = pickle_key_from(key);
    let pickle =
        GroupSessionPickle::from_encrypted(blob, &k).stop_str("invalid group session pickle");
    let gs = GroupSession::from_pickle(pickle);
    RExternalPtr::encode(gs, TAG_GROUP_SESSION, pc)
}

// -- Megolm: inbound (receiver) ----------------------------------------

#[roxido]
fn mxc_megolm_inbound_new(session_key: &str) {
    let sk = SessionKey::from_base64(session_key).stop_str("invalid session_key base64");
    let igs = InboundGroupSession::new(&sk, MegolmSessionConfig::version_1());
    RExternalPtr::encode(igs, TAG_INBOUND_GROUP_SESSION, pc)
}

#[roxido]
fn mxc_megolm_decrypt(igs: &mut RObject, ciphertext_b64: &str) {
    let ext = igs.as_external_ptr_mut().stop_str("expected externalptr");
    let g: &mut InboundGroupSession = ext.decode_mut();
    let msg = MegolmMessage::from_base64(ciphertext_b64).stop_str("invalid megolm ciphertext");
    let dec = g.decrypt(&msg).stop_str("megolm decrypt failed");
    let pt_vec = (&dec.plaintext[..]).to_r(pc);
    let idx = dec.message_index as i32;
    let out = RList::with_names(&["plaintext", "message_index"], pc);
    out.set(0, pt_vec).stop();
    out.set(1, idx.to_r(pc)).stop();
    out
}

#[roxido]
fn mxc_megolm_inbound_pickle(igs: &RObject, key: &RObject) {
    let ext = igs.as_external_ptr().stop_str("expected externalptr");
    let g: &InboundGroupSession = ext.decode_ref();
    let k = pickle_key_from(key);
    let blob = g.pickle().encrypt(&k);
    blob.as_str().to_r(pc)
}

#[roxido]
fn mxc_megolm_inbound_unpickle(blob: &str, key: &RObject) {
    let k = pickle_key_from(key);
    let pickle = InboundGroupSessionPickle::from_encrypted(blob, &k)
        .stop_str("invalid inbound group session pickle");
    let igs = InboundGroupSession::from_pickle(pickle);
    RExternalPtr::encode(igs, TAG_INBOUND_GROUP_SESSION, pc)
}

// -- Ed25519 signature verification ------------------------------------

#[roxido]
fn mxc_curve25519_is_valid(public_key_b64: &str) {
    let ok = Curve25519PublicKey::from_base64(public_key_b64).is_ok();
    ok.to_r(pc)
}

#[roxido]
fn mxc_ed25519_verify(public_key_b64: &str, message: &RObject, signature_b64: &str) {
    let pk = Ed25519PublicKey::from_base64(public_key_b64)
        .stop_str("invalid ed25519 public key (base64)");
    let sig = Ed25519Signature::from_base64(signature_b64)
        .stop_str("invalid ed25519 signature (base64 / length)");
    let msg = raw_bytes(message);
    let ok = pk.verify(msg, &sig).is_ok();
    ok.to_r(pc)
}
