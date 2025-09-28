use blstrs::{G1Affine, G2Affine};
use group::prime::PrimeCurveAffine;
use primitive_types::{H384, H768};
use std::sync::LazyLock;

const G1_BYTES: &[u8] = include_bytes!("../params/g1.bin");
const G2_BYTES: &[u8] = include_bytes!("../params/g2.bin");
const P_BYTES: &[u8] = include_bytes!("../params/p.bin");

static G1: LazyLock<Vec<H384>> = LazyLock::new(|| {
    let (params, _) =
        bincode::serde::decode_from_slice(G1_BYTES, bincode::config::standard()).unwrap();
    params
});

static G2: LazyLock<H768> = LazyLock::new(|| {
    let (params, _) =
        bincode::serde::decode_from_slice(G2_BYTES, bincode::config::standard()).unwrap();
    params
});

static P: LazyLock<Vec<H384>> = LazyLock::new(|| {
    let (params, _) =
        bincode::serde::decode_from_slice(P_BYTES, bincode::config::standard()).unwrap();
    params
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
pub fn g2() -> G2Affine {
    G2Affine::from_compressed(G2.as_fixed_bytes())
        .into_option()
        .unwrap()
}

/// Returns the i-th generator for Pedersen hash.
pub fn p(index: usize) -> G1Affine {
    G1Affine::from_compressed(P[index].as_fixed_bytes())
        .into_option()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{G2Projective, Scalar};
    use ff::Field;
    use group::Group;

    #[test]
    fn test_g1() {
        assert_eq!(G1.len(), 65536);
        let mut g1 = G1.clone();
        g1.sort();
        for i in 1..g1.len() {
            assert_ne!(g1[i], g1[i - 1]);
        }
    }

    #[test]
    fn test_g2() {
        assert_ne!(g2(), G2Affine::generator());
        assert_ne!(
            G2Projective::from(g2()),
            G2Projective::generator() * Scalar::ZERO
        );
    }

    #[test]
    fn test_p() {
        assert_eq!(P.len(), 65536);
        let mut p = P.clone();
        p.sort();
        for i in 1..p.len() {
            assert_ne!(p[i], p[i - 1]);
        }
    }
}
