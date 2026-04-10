use crate::bluesky::Scalar;
use crate::poseidon;
use crate::utils;
use std::sync::LazyLock;

/// Domain separator tag for Fiat-Shamir challenges.
static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri3/challenge"));

/// Checks if a number is a power of 3.
fn is_power_of_three(mut value: usize) -> bool {
    if value == 0 {
        return false;
    }
    while value > 1 {
        if value % 3 != 0 {
            return false;
        }
        value /= 3;
    }
    true
}

/// Computes all Merkle hashes of a vector of values up to the root.
///
/// `n` is the number of values and must be a power of three.
///
/// The full ternary Merkle tree is stored inline in the `values` vector as follows:
///
///   * the first `n` elements are the values of the original vector,
///   * the next `n / 3` elements are the hashes of the second-last layer of the tree,
///   * the next `n / 9` elements are the hashes of the third-last layer of the tree,
///   * ...
///   * the last stored element is the Merkle root.
///
/// It's the caller's responsibility to ensure the `values` array has at least `(3n - 1) / 2` slots
/// so that the full tree can be stored.
///
/// Note that the Merkle root will be at index `3 * (n - 1) / 2`.
fn merklify(values: &mut [Scalar], mut n: usize) {
    assert!(is_power_of_three(n));
    let mut i = 0;
    while n > 1 {
        let m = n / 3;
        for j in 0..m {
            values[i + n + j] = poseidon::hash_t4(&[
                values[i + j * 3],
                values[i + j * 3 + 1],
                values[i + j * 3 + 2],
            ]);
        }
        i += n;
        n = m;
    }
}

// TODO

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::parse_scalar;

    #[test]
    fn test_merklify_one() {
        let mut values = vec![12.into()];
        merklify(&mut values, 1);
        assert_eq!(values, vec![12.into()]);
    }

    #[test]
    fn test_merklify_three() {
        let mut values = vec![34.into(), 56.into(), 78.into()];
        values.resize(4, 0.into());
        merklify(&mut values, 3);
        assert_eq!(
            values,
            vec![
                34.into(),
                56.into(),
                78.into(),
                parse_scalar("0x64607a4e12aa794615a7329a8a862574b207057fc159da8a660276dea158b151")
            ]
        );
    }

    #[test]
    fn test_merklify_nine() {
        let mut values = vec![
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            78.into(),
            56.into(),
            34.into(),
            12.into(),
        ];
        values.resize(13, 0.into());
        merklify(&mut values, 9);
        assert_eq!(
            values,
            vec![
                12.into(),
                34.into(),
                56.into(),
                78.into(),
                90.into(),
                78.into(),
                56.into(),
                34.into(),
                12.into(),
                parse_scalar("0x236092ebefc7e6565e0e75414d8fdce1ce2e19bb59002d36b794b9c3111bb9cd"),
                parse_scalar("0x25ff2477c9f7620f997d9c2cada87f756cee4fdee2b7d4fb6e5c7d3d005447eb"),
                parse_scalar("0x0f9332ff17f975d1fd450166f45d971017a9ab2f4287ac98568204b9b3350546"),
                parse_scalar("0x2c4e52ae8124220a5df522f37ccb8f6be7506ade1251e462a769db6c876ae321"),
            ]
        );
    }

    // TODO
}
