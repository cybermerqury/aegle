use bitvec::vec::BitVec;

use crate::models::Toeplitz;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum FollowerRequests {
    /// Register an LDPC code of the given ID with SimCommSys
    #[cfg(feature = "ec_simcommsys")]
    RegisterCode(String),
    Reveal(Vec<usize>),
    Syndrome(Vec<Vec<usize>>),
    PrivacyAmplification(Toeplitz),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum FollowerResponse {
    Reveal(BitVec),
    Syndrome(BitVec),
    PrivacyAmplificationConfirmed(PAReply),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum PAReply {
    Confirmed,
    Error,
}
