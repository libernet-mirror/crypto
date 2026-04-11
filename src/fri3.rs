use crate::bluesky::{Scalar, ThreeAdicRootOfUnity};
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::Field;
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

fn ilog3(mut n: usize) -> usize {
    let mut c = 0;
    while n > 1 {
        c += 1;
        n /= 3;
    }
    c
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
                values[i + j * 3 + 0],
                values[i + j * 3 + 1],
                values[i + j * 3 + 2],
            ]);
        }
        i += n;
        n = m;
    }
}

/// Stores the Merkle root hashes of a FRI commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The first element in the array is the root of the main Merkle tree, the second one is the
    /// root of the Merkle tree from the first folding round, and so on until the last element which
    /// is the value of the last folding round.
    roots: Vec<Scalar>,
}

impl Commitment {
    pub fn roots(&self) -> &[Scalar] {
        self.roots.as_slice()
    }
}

/// A Merkle proof for a single value in a ternary Merkle tree.
///
/// A FRI opening `Proof` uses several of these: one from the main Merkle tree and one for each
/// folding round.
///
/// NOTE: this object only stores the proven scalar and the sister hashes of the proven path, but it
/// doesn't store the lookup key or the root hash anywhere because those pieces of information are
/// reconstructed separately during the verification of a whole `Proof`. In particular, all root
/// hashes are stored in the `Commitment`.
#[derive(Debug, Clone)]
struct LeafProof {
    value: Scalar,
    path: Vec<(Scalar, Scalar)>,
}

impl LeafProof {
    /// Builds a ternary Merkle proof for the leaf at `index` in a tree with `n` leaves.
    ///
    /// The tree is stored in `values` using the layout described in `merklify`.
    ///
    /// REQUIRES: `n` must be a power of 3.
    /// REQUIRES: values.len() >= (3 * n - 1) / 2
    /// REQUIRES: index < n
    fn new(values: &[Scalar], mut n: usize, mut index: usize) -> Self {
        debug_assert!(is_power_of_three(n));
        assert!(index < n);
        let value = values[index];
        let mut path = Vec::with_capacity(ilog3(n));
        let mut i = 0usize;
        while n > 1 {
            let j = i + index - index % 3;
            match index % 3 {
                0 => path.push((values[j + 1], values[j + 2])),
                1 => path.push((values[j + 0], values[j + 2])),
                _ => path.push((values[j + 0], values[j + 1])),
            };
            i += n;
            n /= 3;
            index /= 3;
        }
        Self { value, path }
    }

    /// Returns the proven value.
    fn value(&self) -> &Scalar {
        &self.value
    }

    /// Verifies this Merkle proof against the given `root_hash` using the given `index`.
    fn verify(&self, mut index: usize, root_hash: Scalar) -> Result<()> {
        let mut hash = self.value;
        for (sibling1, sibling2) in &self.path {
            hash = match index % 3 {
                0 => poseidon::hash_t4(&[hash, *sibling1, *sibling2]),
                1 => poseidon::hash_t4(&[*sibling1, hash, *sibling2]),
                _ => poseidon::hash_t4(&[*sibling1, *sibling2, hash]),
            };
            index /= 3;
        }
        if index != 0 {
            return Err(anyhow!("index out of bounds"));
        }
        if hash != root_hash {
            return Err(anyhow!(
                "root hash mismatch (got {}, want {})",
                utils::format_scalar(hash),
                utils::format_scalar(root_hash)
            ));
        }
        Ok(())
    }
}

/// A complete ternary FRI opening proof.
#[derive(Debug, Clone)]
pub struct Proof {
    /// The index of the element we're opening.
    index: usize,
    /// The opened value.
    value: Scalar,
    /// Proves a triplet of "partner" values at each folding round with one `LeafProof` triplet for
    /// every round. Note that either `folds[0].0`, `folds[0].1`, or `folds[0].2` proves `value`.
    folds: Vec<(LeafProof, LeafProof, LeafProof)>,
}

impl Proof {
    /// Returns the index of the opened value.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the opened value.
    pub fn value(&self) -> &Scalar {
        &self.value
    }

    /// Verifies this proof against the given commitment.
    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        // TODO
        todo!()
    }
}

/// A FRI prover.
///
/// The struct contains the original committed vector, the ternary Merkle tree built upon it, all
/// folded polynomials, and all Merkle trees of all folded polynomials. All scalars are laid out on
/// a single flat array.
///
/// Each Merkle tree is complete because the size of the bottom layer is always a power of 3, so we
/// store it inline using `(3n-1)/2` slots, with `n` being the size of the bottom layer.
///
/// The layout of a Merkle tree with `n` leaves is the one generated by the `merklify` function
/// above. All trees are stored in the `values` array sequentially as follows:
///
///   * the first tree is the main Merkle tree (`n` committed elements, `(3n-1)/2` used slots),
///   * the second tree is the one resulting from the first folding round (`n/3` leaves, `(n-1)/2`
///     used slots),
///   * the third tree is the one resulting from the second folding round (`n/9` leaves, `(n/3-1)/2`
///     used slots),
///
/// etc.
///
/// NOTE: the total capacity allocated for the `values` array is `(9n-1)/4` for simplicity, but
/// that's not exactly the sum of `(3n-1)/2` for all powers of 3. There's excess capacity and some
/// slots are unused.
#[derive(Debug, Clone)]
pub struct Prover {
    values: Vec<Scalar>,
}

impl Prover {
    /// Runs a folding round over a ternary Merkle tree with `n` leaves, resulting in a new ternary
    /// Merkle tree with `n/3` leaves.
    ///
    /// The input tree must be stored at the beginning of the provided slice, so that the first `n`
    /// elements of the slice are the evaluations of the polynomial to fold.
    ///
    /// The root of the input tree is therefore located at index `3 * (n - 1) / 2` and is used to
    /// generate the Fiat-Shamir challenge for the round.
    ///
    /// The output tree will be stored immediatelt after the input one and will take exactly
    /// `(n-1)/2` slots. It's the caller's responsibility to ensure that `values` has enough space.
    fn fold(values: &mut [Scalar], n: usize) {
        assert!(is_power_of_three(n));
        let alpha = poseidon::hash_t3(&[*DST, values[3 * (n - 1) / 2]]);

        let k = ilog3(n) as u32;
        let omega_inv =
            Scalar::THREE_ADIC_ROOT_OF_UNITY_INV.pow_vartime([1u64 << (Scalar::T - k), 0, 0, 0]);

        let m = n / 3;
        let mut omega_inv_i = Scalar::ONE;
        for i in 0..m {
            // TODO
        }

        merklify(&mut values[((3 * n - 1) / 2)..], m);
    }

    /// Runs all folding passes by calling `fold` iteratively until the polynomial is folded into a
    /// single scalar.
    ///
    /// All generated Merkle trees are laid out across `values` as described above.
    fn fold_all(values: &mut [Scalar], n: usize) {
        let mut offset = 0usize;
        let mut m = n;
        while m > 1 {
            Self::fold(&mut values[offset..], m);
            offset += (3 * m - 1) / 2;
            m /= 3;
        }
    }

    /// Constructs a new FRI prover that commits to the provided list of `values`.
    ///
    /// The underlying algorithms require that the number of committed values is a power of two, so
    /// if that's not the case this function will automatically pad them with zeros.
    pub fn new(mut values: Vec<Scalar>) -> Self {
        let n = values.len().next_power_of_two();
        assert!(n <= 1usize << Scalar::T);
        values.resize((9 * n - 1) / 4, Scalar::ZERO);
        merklify(&mut values[0..((3 * n - 1) / 2)], n);
        Self::fold_all(&mut values, n);
        Self { values }
    }

    /// Returns the length of the original committed vector.
    pub fn length(&self) -> usize {
        (self.values.len() * 4 + 1) / 9
    }

    /// Creates the FRI commitment for the committed vector.
    pub fn commit(&self) -> Commitment {
        let mut n = self.length();
        let k = ilog3(n) as usize + 1;
        let mut roots = vec![Scalar::ZERO; k];
        let mut offset = 0usize;
        for i in 0..k {
            roots[i] = self.values[offset + 3 * (n - 1) / 2];
            offset += n * 3;
            n /= 3;
        }
        Commitment { roots }
    }
}

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
