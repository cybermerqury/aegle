pub const OLD_PARITY_MATRIX: [[u8; 6]; 4] = [
    [1, 1, 0, 1, 0, 0],
    [0, 1, 1, 0, 1, 0],
    [1, 0, 0, 0, 1, 1],
    [0, 0, 1, 1, 0, 1],
];

pub const PARITY_MATRIX: [[u8; 6]; 4] = [
    [0, 1, 1, 0, 0, 0],
    [1, 1, 0, 1, 0, 0],
    [1, 0, 0, 0, 1, 0],
    [0, 1, 0, 0, 0, 1],
];

pub const WORD_SIZE: usize = 2;

pub const GENERATOR_MATRIX: [[u8; 6]; WORD_SIZE] = [[1, 0, 0, 1, 1, 0], [0, 1, 1, 1, 0, 1]];

#[cfg(feature = "ec_simcommsys")]
pub const SCS_CODEC_ID: &str = "aegle-codec";
