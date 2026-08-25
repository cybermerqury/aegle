use bitvec::vec::BitVec;

use crate::models::Toeplitz;

#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum FollowerRequests {
    /// Register an LDPC code of the given ID with SimCommSys
    Reveal(Vec<usize>),
    Syndrome(Vec<Vec<usize>>),
    PrivacyAmplification(Toeplitz),
    #[cfg(feature = "ec_simcommsys")]
    SCSRegisterCode(String),
    #[cfg(feature = "ec_simcommsys")]
    SCSSyndrome,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(debug_assertions, derive(Debug))]
pub enum FollowerResponse {
    Reveal(BitVec),
    Syndrome(BitVec),
    PrivacyAmplificationConfirmed(PAReply),
    #[cfg(feature = "ec_simcommsys")]
    SCSRegisterCode(bool),
    #[cfg(feature = "ec_simcommsys")]
    SCSSyndrome(Option<Vec<BitVec>>),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum PAReply {
    Confirmed,
    Error,
}
