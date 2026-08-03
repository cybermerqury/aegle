use bitvec::vec::BitVec;

use crate::models::Toeplitz;

// #[non_exhaustive]
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum FollowerRequests {
    /// Register an LDPC code of the given ID with SimCommSys
    Reveal(Vec<usize>),
    Syndrome(Vec<Vec<usize>>),
    PrivacyAmplification(Toeplitz),
    #[cfg(feature = "ec_simcommsys")]
    SCSRegisterCode(String),
    #[cfg(feature = "ec_simcommsys")]
    SCSSyndrome(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum FollowerResponse {
    Reveal(BitVec),
    Syndrome(BitVec),
    PrivacyAmplificationConfirmed(PAReply),
    #[cfg(feature = "ec_simcommsys")]
    SCSRegisterCode(bool),
    #[cfg(feature = "ec_simcommsys")]
    SCSSyndrome(Option<BitVec>),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum PAReply {
    Confirmed,
    Error,
}
