pub mod backup;
pub mod exe_patch;
pub mod metadata;
pub mod pipeline;
pub mod rugp;

pub const EXPECTED_BASE_RUO_SIZE: u64 = 359_226_836;
pub const EXPECTED_BASE_RUO_SHA256: &str =
    "57a9cc354300a3f4ac680332b3c0cb6a3ef751823a1622f6f95644ac3ad83765";
pub const EXPECTED_EXE_SHA256: &str =
    "0bfb31f2127d1ac4039f13097a137471838256128a63012c9ff44e5dac7f4b71";
