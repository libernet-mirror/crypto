use dusk_bls12_381::{G1Affine, G2Affine};
use primitive_types::{H384, H768};
use std::sync::LazyLock;

const BYTES: &[u8] = include_bytes!("../params/params0.bin");

static PARAMS: LazyLock<Vec<(H384, H768)>> = LazyLock::new(|| {
    let (params, _) =
        bincode::serde::decode_from_slice(BYTES, bincode::config::standard()).unwrap();
    params
});

pub fn g1(index: usize) -> G1Affine {
    let (h384, _) = PARAMS[index];
    G1Affine::from_compressed(h384.as_fixed_bytes())
        .into_option()
        .unwrap()
}

pub fn g2(index: usize) -> G2Affine {
    let (_, h768) = PARAMS[index];
    G2Affine::from_compressed(h768.as_fixed_bytes())
        .into_option()
        .unwrap()
}
