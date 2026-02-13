use blstrs::{G1Affine, G2Affine};
use group::prime::PrimeCurveAffine;
use primitive_types::{H384, H768};
use std::sync::LazyLock;

static G1_BYTES: &[u8] = include_bytes!("../params/g1.bin");
static G2_BYTES: &[u8] = include_bytes!("../params/g2.bin");

const NUM_POINTS: usize = 65536;

static G1: LazyLock<&'static [H384]> = LazyLock::new(|| {
    assert_eq!(G1_BYTES.len(), NUM_POINTS * 48);
    unsafe { std::slice::from_raw_parts(G1_BYTES.as_ptr() as *const H384, NUM_POINTS) }
});

static G2: LazyLock<&'static [H768]> = LazyLock::new(|| {
    assert_eq!(G2_BYTES.len(), NUM_POINTS * 96);
    unsafe { std::slice::from_raw_parts(G2_BYTES.as_ptr() as *const H768, NUM_POINTS) }
});

/// Returns the i-th parameter of the KZG SRS.
///
/// `g1(i)` returns `G1 * tau^i`, where `G1` is the G1 generator of BLS12-381.
pub fn g1(index: usize) -> G1Affine {
    if index > 0 {
        G1Affine::from_compressed(G1[index - 1].as_fixed_bytes())
            .into_option()
            .unwrap()
    } else {
        G1Affine::generator()
    }
}

/// Returns `G2 * tau`, with `G2` being the G2 generator of BLS12-381. Used in KZG.
pub fn g2(index: usize) -> G2Affine {
    if index > 0 {
        G2Affine::from_compressed(G2[index - 1].as_fixed_bytes())
            .into_option()
            .unwrap()
    } else {
        G2Affine::generator()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1() {
        assert_eq!(G1.len(), NUM_POINTS);
        assert_eq!(g1(0), G1Affine::generator());
        let mut g1 = Vec::<H384>::from(*G1);
        g1.sort();
        for i in 1..g1.len() {
            assert_ne!(g1[i], g1[i - 1]);
        }
    }

    #[test]
    fn test_g2() {
        assert_eq!(G2.len(), NUM_POINTS);
        assert_eq!(g2(0), G2Affine::generator());
        let mut g2 = Vec::<H768>::from(*G2);
        g2.sort();
        for i in 1..g2.len() {
            assert_ne!(g2[i], g2[i - 1]);
        }
    }
}
