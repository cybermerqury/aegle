pub const PARITY_MATRIX: [[u8; 6]; 4] = [
    [1, 1, 0, 1, 0, 0],
    [0, 1, 1, 0, 1, 0],
    [1, 0, 0, 0, 1, 1],
    [0, 0, 1, 1, 0, 1],
];

#[cfg(feature = "ec_simcommsys")]
pub const SCS_CODEC_ID: &str = "aegle-codec";
