/// The hash type used during kex
/// this is determined by the kex alg
#[derive(Copy, Clone)]
pub enum HashType {
    None,
    SHA1,
    SHA256,
}
