// pub const CODEWORD_SIZE: usize = 1008;
// pub const WORD_SIZE: usize = 504;
pub const CODEWORD_SIZE: usize = 6;
pub const WORD_SIZE: usize = 2;
pub const CHECKS_SIZE: usize = CODEWORD_SIZE - WORD_SIZE;

// pub const PARITY_MATRIX_STR: &str = include_str!("../../../res/ldpc_h.alist");

// pub const GENERATOR_MATRIX_STR: &str = include_str!("../../../res/ldpc_g.alist");

pub const PARITY_MATRIX: [[u8; CODEWORD_SIZE]; CHECKS_SIZE] = [
    [0, 1, 1, 0, 0, 0],
    [1, 1, 0, 1, 0, 0],
    [1, 0, 0, 0, 1, 0],
    [0, 1, 0, 0, 0, 1],
];

pub const GENERATOR_MATRIX: [[u8; CODEWORD_SIZE]; WORD_SIZE] =
    [[1, 0, 0, 1, 1, 0], [0, 1, 1, 1, 0, 1]];

#[cfg(feature = "ec_simcommsys")]
pub const SCS_CODEC_ID: &str = "aegle-codec";
