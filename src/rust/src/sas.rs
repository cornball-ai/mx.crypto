// Ephemeral SAS handles are deliberately not serializable. A restarted
// verification starts a new transaction and a fresh ephemeral key pair.
use roxido::*;
use sha2::{Digest, Sha256};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use vodozemac::sas::{EstablishedSas, Mac, Sas};
use vodozemac::Curve25519PublicKey;

const TAG_SAS: &str = "mx.crypto::Sas";

struct SasHandle {
    public: Curve25519PublicKey,
    fresh: Option<Sas>,
    established: Option<EstablishedSas>,
}

fn checked(object: &RObject) -> &RExternalPtr {
    let ext = object.as_external_ptr().stop_str("expected a SAS handle");
    if ext.is_null() || ext.tag_str() != TAG_SAS {
        stop!("expected a live SAS handle");
    }
    ext
}

fn established(object: &RObject) -> &EstablishedSas {
    let handle: &SasHandle = checked(object).decode_ref();
    handle.established.as_ref().stop_str("SAS shared secret is not established")
}

#[roxido(module = sas)]
fn mxc_sas_new() {
    let sas = Sas::new();
    let handle = SasHandle {
        public: sas.public_key(), fresh: Some(sas), established: None,
    };
    RExternalPtr::encode(handle, TAG_SAS, pc)
}

#[roxido(module = sas)]
fn mxc_sas_public(sas: &RObject) {
    let handle: &SasHandle = checked(sas).decode_ref();
    handle.public.to_base64().as_str().to_r(pc)
}

#[roxido(module = sas)]
fn mxc_sas_establish(sas: &mut RObject, peer_key: &str) {
    checked(sas);
    let peer = Curve25519PublicKey::from_base64(peer_key)
        .stop_str("invalid SAS peer public key");
    let ext = sas.as_external_ptr_mut().stop_str("expected a SAS handle");
    let handle: &mut SasHandle = ext.decode_mut();
    let fresh = handle.fresh.take().stop_str("SAS ephemeral key already consumed");
    handle.established = Some(fresh.diffie_hellman(peer)
        .stop_str("non-contributory SAS peer public key"));
}

#[roxido(module = sas)]
fn mxc_sas_bytes(sas: &RObject, info: &str) {
    let bytes = established(sas).bytes(info);
    (&bytes.as_bytes()[..]).to_r(pc)
}

#[roxido(module = sas)]
fn mxc_sas_mac(sas: &RObject, input: &str, info: &str) {
    established(sas).calculate_mac(input, info).to_base64().as_str().to_r(pc)
}

#[roxido(module = sas)]
fn mxc_sas_verify_mac(sas: &RObject, input: &str, info: &str, mac: &str) {
    let sas = established(sas);
    let valid = Mac::from_base64(mac).map(|tag| {
        tag.as_bytes().len() == 32 && sas.verify_mac(input, info, &tag).is_ok()
    }).unwrap_or(false);
    valid.to_r(pc)
}

#[roxido(module = sas)]
fn mxc_sas_commitment(public_key: &str, canonical_start: &str) {
    Curve25519PublicKey::from_base64(public_key)
        .stop_str("invalid SAS public key");
    let mut hash = Sha256::new();
    hash.update(public_key.as_bytes());
    hash.update(canonical_start.as_bytes());
    STANDARD_NO_PAD.encode(hash.finalize()).as_str().to_r(pc)
}
