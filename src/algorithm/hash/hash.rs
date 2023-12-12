use super::hash_ctx::HashCtx;
use crate::algorithm::hash;
use crate::algorithm::hash::HashType;
use crate::constant;

/// <https://www.rfc-editor.org/rfc/rfc4253#section-7.2>
///
/// The key exchange produces two values: a shared secret K, and an
/// exchange hash H.  Encryption and authentication keys are derived from
/// these.  The exchange hash H from the first key exchange is
/// additionally used as the session identifier, which is a unique
/// identifier for this connection.  It is used by authentication methods
/// as a part of the data that is signed as a proof of possession of a
/// private key.  Once computed, the session identifier is not changed,
/// even if keys are later re-exchanged.

/// Each key exchange method specifies a hash function that is used in
/// the key exchange.  The same hash algorithm MUST be used in key
/// derivation.  Here, we'll call it HASH.

/// Encryption keys MUST be computed as HASH, of a known value and K, as
/// follows:

/// o  Initial IV client to server: HASH(K || H || "A" || session_id)
///    (Here K is encoded as mpint and "A" as byte and session_id as raw
///    data.  "A" means the single character A, ASCII 65).

/// o  Initial IV server to client: HASH(K || H || "B" || session_id)

/// o  Encryption key client to server: HASH(K || H || "C" || session_id)

/// o  Encryption key server to client: HASH(K || H || "D" || session_id)

/// o  Integrity key client to server: HASH(K || H || "E" || session_id)

/// o  Integrity key server to client: HASH(K || H || "F" || session_id)

/// Key data MUST be taken from the beginning of the hash output.  As
/// many bytes as needed are taken from the beginning of the hash value.
/// If the key length needed is longer than the output of the HASH, the
/// key is extended by computing HASH of the concatenation of K and H and
/// the entire key so far, and appending the resulting bytes (as many as
/// HASH generates) to the key.  This process is repeated until enough
/// key material is available; the key is taken from the beginning of
/// this value.  In other words:

///    K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
///    K2 = HASH(K || H || K1)
///    K3 = HASH(K || H || K1 || K2)
///    ...
///    key = K1 || K2 || K3 || ...

/// This process will lose entropy if the amount of entropy in K is
/// larger than the internal state size of HASH.
pub struct Hash {
    /// reandom number used once
    pub iv_c_s: Vec<u8>,
    pub iv_s_c: Vec<u8>,

    /// key used for data exchange
    pub ek_c_s: Vec<u8>,
    pub ek_s_c: Vec<u8>,

    /// key used for hmac
    pub ik_c_s: Vec<u8>,
    pub ik_s_c: Vec<u8>,

    hash_type: HashType,
    hash_ctx: HashCtx,
}

impl Hash {
    pub fn new(hash_ctx: HashCtx, session_id: &[u8], hash_type: HashType) -> Self {
        let k = hash_ctx.k.as_slice();
        let h = hash::digest(&hash_ctx.as_bytes(), hash_type);
        let mut keys = vec![];
        for v in constant::ALPHABET {
            keys.push(Hash::mix(k, &h, v, session_id, hash_type));
        }
        Hash {
            iv_c_s: keys[0].clone(),
            iv_s_c: keys[1].clone(),

            ek_c_s: keys[2].clone(),
            ek_s_c: keys[3].clone(),

            ik_c_s: keys[4].clone(),
            ik_s_c: keys[5].clone(),

            hash_type,
            hash_ctx,
        }
    }

    fn mix(k: &[u8], h: &[u8], key_char: u8, session_id: &[u8], hash_type: HashType) -> Vec<u8> {
        let mut key: Vec<u8> = Vec::new();
        key.extend(k);
        key.extend(h);
        key.push(key_char);
        key.extend(session_id);
        hash::digest(key.as_slice(), hash_type)
    }

    pub fn mix_ek(&self, key_size: usize) -> (Vec<u8>, Vec<u8>) {
        let mut ck = self.ek_c_s.to_vec();
        let mut sk = self.ek_s_c.to_vec();
        while key_size > ck.len() {
            ck.extend(self.extend(ck.as_slice()));
            sk.extend(self.extend(sk.as_slice()));
        }
        (ck, sk)
    }

    pub fn mix_ik(&self, key_size: usize) -> (Vec<u8>, Vec<u8>) {
        let mut ck = self.ik_c_s.to_vec();
        let mut sk = self.ik_s_c.to_vec();
        while key_size > ck.len() {
            ck.extend(self.extend(ck.as_slice()));
            sk.extend(self.extend(sk.as_slice()));
        }
        (ck, sk)
    }

    fn extend(&self, key: &[u8]) -> Vec<u8> {
        let k = self.hash_ctx.k.clone();
        let h = hash::digest(self.hash_ctx.as_bytes().as_slice(), self.hash_type);
        let mut hash: Vec<u8> = Vec::new();
        hash.extend(k);
        hash.extend(h);
        hash.extend(key);
        hash::digest(hash.as_slice(), self.hash_type)
    }
}
