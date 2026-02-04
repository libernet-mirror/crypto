use blstrs::Scalar;
use ff::Field;
use std::sync::LazyLock;

const R: usize = 3;
const C: usize = 1;
const T: usize = R + C;
const NUM_FULL_ROUNDS_START: usize = 4;
const NUM_FULL_ROUNDS_END: usize = 4;
const NUM_FULL_ROUNDS: usize = NUM_FULL_ROUNDS_START + NUM_FULL_ROUNDS_END;
const NUM_PARTIAL_ROUNDS: usize = 56;
const NUM_ROUNDS: usize = NUM_FULL_ROUNDS + NUM_PARTIAL_ROUNDS;

static ROUND_CONSTANTS: LazyLock<[Scalar; NUM_ROUNDS * T]> = LazyLock::new(|| {
    let bytes = include_bytes!("../params/arc.bin");
    let mut constants = [Scalar::ZERO; NUM_ROUNDS * T];
    for i in 0..(NUM_ROUNDS * T) {
        constants[i] = Scalar::from_bytes_le(&bytes[(i * 32)..((i + 1) * 32)].try_into().unwrap())
            .into_option()
            .unwrap();
    }
    constants
});

static MDS_MATRIX: LazyLock<[[Scalar; T]; T]> = LazyLock::new(|| {
    let bytes = include_bytes!("../params/mds.bin");
    let mut mds = [[Scalar::ZERO; T]; T];
    for i in 0..T {
        for j in 0..T {
            let offset = (i * T + j) * 32;
            mds[i][j] = Scalar::from_bytes_le(&bytes[offset..(offset + 32)].try_into().unwrap())
                .into_option()
                .unwrap()
        }
    }
    mds
});

fn sbox(x: Scalar) -> Scalar {
    x.square().square() * x
}

fn round(state: &mut [Scalar; T], r: usize, full: bool) {
    let c = &*ROUND_CONSTANTS;
    let mds = &*MDS_MATRIX;

    for i in 0..T {
        state[i] += c[r * T + i];
    }

    state[0] = sbox(state[0]);
    if full {
        for i in 1..T {
            state[i] = sbox(state[i]);
        }
    }

    let mut new_state = [Scalar::ZERO; T];
    for i in 0..T {
        for j in 0..T {
            new_state[i] += mds[i][j] * state[j];
        }
    }
    *state = new_state;
}

pub fn hash(inputs: &[Scalar]) -> Scalar {
    assert!(T > 0);
    assert!(!inputs.is_empty());
    let mut state = [Scalar::ZERO; T];
    for chunk in inputs.chunks(T - 1) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        for i in 0..NUM_ROUNDS {
            round(
                &mut state,
                i,
                /*full=*/
                i < NUM_FULL_ROUNDS_START || i >= NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS,
            );
        }
    }
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::parse_scalar;

    #[test]
    fn test_hash1() {
        assert_eq!(
            hash(&[42.into()]),
            parse_scalar("0x0531b2fa3c2aa794859d54c409ac6bf33a19981275bff625c5eeb8d1cc8d123c")
        );
    }

    #[test]
    fn test_hash2() {
        assert_eq!(
            hash(&[1.into(), 2.into()]),
            parse_scalar("0x520651bc5804254d3306d30c7e3242e00f527bb7f39aedb7f828e346299bd91c")
        );
    }

    #[test]
    fn test_hash3() {
        assert_eq!(
            hash(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x1a9f84b2d90c7ec4efb7e8c38efddad5983245c1132434bb94c74d19eb04cb3a")
        );
    }

    #[test]
    fn test_hash4() {
        assert_eq!(
            hash(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x5497afdc8bc505782b08a63601eec9fa0e4037e61d06f453edff9a8ca1991b76")
        );
    }
}
