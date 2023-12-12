use crate::model::Data;

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
///
/// H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
///
///
#[derive(Clone, Debug, Default)]
pub struct HashCtx {
    /// string    V_C, the client's identification string (CR and LF excluded)
    pub v_c: Vec<u8>,
    /// string    V_S, the server's identification string (CR and LF excluded)
    pub v_s: Vec<u8>,

    /// string    I_C, the payload of the client's SSH_MSG_KEXINIT
    pub i_c: Vec<u8>,
    /// string    I_S, the payload of the server's SSH_MSG_KEXINIT
    pub i_s: Vec<u8>,

    /// string    K_S, the host key
    pub k_s: Vec<u8>,

    /// mpint     e, exchange value sent by the client
    pub e: Vec<u8>,
    /// mpint     f, exchange value sent by the server
    pub f: Vec<u8>,

    /// mpint     K, the shared secret
    pub k: Vec<u8>,
}

impl HashCtx {
    pub fn new() -> Self {
        HashCtx {
            v_c: vec![],
            v_s: vec![],
            i_c: vec![],
            i_s: vec![],
            k_s: vec![],
            e: vec![],
            f: vec![],
            k: vec![],
        }
    }

    pub fn set_v_c(&mut self, vc: &str) {
        let mut data = Data::new();
        data.put_str(vc);
        self.v_c = data.to_vec();
    }
    pub fn set_v_s(&mut self, vs: &str) {
        let mut data = Data::new();
        data.put_str(vs);
        self.v_s = data.to_vec();
    }
    pub fn set_i_c(&mut self, ic: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(ic);
        self.i_c = data.to_vec();
    }
    pub fn set_i_s(&mut self, is: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(is);
        self.i_s = data.to_vec();
    }
    pub fn set_k_s(&mut self, ks: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(ks);
        self.k_s = data.to_vec();
    }
    pub fn set_e(&mut self, qc: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(qc);
        self.e = data.to_vec();
    }
    pub fn set_f(&mut self, qs: &[u8]) {
        let mut data = Data::new();
        data.put_u8s(qs);
        self.f = data.to_vec();
    }
    pub fn set_k(&mut self, k: &[u8]) {
        let mut data = Data::new();
        data.put_mpint(k);
        self.k = data.to_vec();
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = vec![];
        v.extend(&self.v_c);
        v.extend(&self.v_s);
        v.extend(&self.i_c);
        v.extend(&self.i_s);
        v.extend(&self.k_s);
        v.extend(&self.e);
        v.extend(&self.f);
        v.extend(&self.k);
        v
    }
}
