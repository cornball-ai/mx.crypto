// Matrix v2 encrypted attachments: AES-256-CTR with a 64-bit counter,
// a fresh key and nonce per file, and SHA-256 over the ciphertext.
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{alphabet, engine::{general_purpose::{GeneralPurpose, GeneralPurposeConfig}, DecodePaddingMode}, Engine};
use rand::{rngs::OsRng, RngCore};
use roxido::*;
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;
const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent);
const B64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
const URL64: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

fn crypt(bytes: &mut [u8], key: &[u8], iv: &[u8]) {
    Aes256Ctr::new_from_slices(key, iv).stop_str("invalid attachment key or IV")
        .try_apply_keystream(bytes).stop_str("attachment counter exhausted");
}

#[roxido(module = attachment)]
fn mxc_attachment_encrypt(data: &RObject) {
    let mut bytes = crate::raw_bytes(data).to_vec();
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    OsRng.try_fill_bytes(&mut key).stop_str("attachment randomness unavailable");
    OsRng.try_fill_bytes(&mut iv[..8]).stop_str("attachment randomness unavailable");
    crypt(&mut bytes, &key, &iv);
    let result = RList::with_names(&["data", "key", "iv", "sha256"], pc);
    result.set(0, bytes.as_slice().to_r(pc)).stop();
    result.set(1, URL64.encode(key).as_str().to_r(pc)).stop();
    result.set(2, B64.encode(iv).as_str().to_r(pc)).stop();
    result.set(3, B64.encode(Sha256::digest(&bytes)).as_str().to_r(pc)).stop();
    result
}

#[roxido(module = attachment)]
fn mxc_attachment_decrypt(data: &RObject, key: &str, iv: &str, sha256: &str) {
    let bytes = crate::raw_bytes(data);
    let key = URL64.decode(key).stop_str("invalid attachment key encoding");
    let iv = B64.decode(iv).stop_str("invalid attachment IV encoding");
    let hash = B64.decode(sha256).stop_str("invalid attachment hash encoding");
    // Verify before releasing any plaintext. The hash is public; the
    // encrypted room event protects the key and these metadata fields.
    if hash.len() != 32 || hash.as_slice() != &Sha256::digest(bytes)[..] {
        stop!("attachment integrity check failed");
    }
    let mut plaintext = bytes.to_vec();
    crypt(&mut plaintext, &key, &iv);
    plaintext.as_slice().to_r(pc)
}
