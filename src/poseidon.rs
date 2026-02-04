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

fn pow5(x: Scalar) -> Scalar {
    x.square().square() * x
}

fn round(state: &mut [Scalar; T], i: usize, full: bool) {
    let c = &ROUND_CONSTANTS;
    let mds = &*MDS_MATRIX;

    state[0] += c[i * T + 0];
    state[1] += c[i * T + 1];
    state[2] += c[i * T + 2];
    state[3] += c[i * T + 3];

    state[0] = pow5(state[0]);
    if full {
        state[1] = pow5(state[1]);
        state[2] = pow5(state[2]);
        state[3] = pow5(state[3]);
    }

    let mut new_state = [Scalar::ZERO; T];
    new_state[0] =
        mds[0][0] * state[0] + mds[0][1] * state[1] + mds[0][2] * state[2] + mds[0][3] * state[3];
    new_state[1] =
        mds[1][0] * state[0] + mds[1][1] * state[1] + mds[1][2] * state[2] + mds[1][3] * state[3];
    new_state[2] =
        mds[2][0] * state[0] + mds[2][1] * state[1] + mds[2][2] * state[2] + mds[2][3] * state[3];
    new_state[3] =
        mds[3][0] * state[0] + mds[3][1] * state[1] + mds[3][2] * state[2] + mds[3][3] * state[3];
    *state = new_state;
}

pub fn hash(inputs: &[Scalar]) -> Scalar {
    assert!(!inputs.is_empty());
    let mut state = [Scalar::ZERO; T];
    for chunk in inputs.chunks(3) {
        state[0] += chunk[0];
        if chunk.len() > 1 {
            state[1] += chunk[1];
        }
        if chunk.len() > 2 {
            state[2] += chunk[2];
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
