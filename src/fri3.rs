use crate::bluesky::{Scalar, ThreeAdicRootOfUnity};
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::Field;
use std::sync::LazyLock;

/// Domain separator tag for Fiat-Shamir challenges.
static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri3/challenge"));

/// Returns the smallest power of three that is >= n (returns 1 for n=0).
fn next_power_of_three(n: usize) -> usize {
    let mut pow = 1usize;
    while pow < n {
        pow *= 3;
    }
    pow
}

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
        let k = self.folds.len();
        let n = 3usize.pow(k as u32);

        if commitment.roots.len() != k + 1 {
            return Err(anyhow!(
                "commitment has {} roots but proof expects {}",
                commitment.roots.len(),
                k + 1
            ));
        }
        if self.index >= n {
            return Err(anyhow!("index {} out of bounds (n={})", self.index, n));
        }

        if k == 0 {
            if self.value != commitment.roots[0] {
                return Err(anyhow!(
                    "value mismatch: got {}, want {}",
                    utils::format_scalar(self.value),
                    utils::format_scalar(commitment.roots[0])
                ));
            }
            return Ok(());
        }

        let value_in_folds = match self.index * 3 / n {
            0 => *self.folds[0].0.value(),
            1 => *self.folds[0].1.value(),
            _ => *self.folds[0].2.value(),
        };
        if self.value != value_in_folds {
            return Err(anyhow!("value does not match folds[0]"));
        }

        let mut q = self.index;
        let mut n_r = n;

        for r in 0..k {
            let m = n_r / 3;
            let pos = q % m;

            self.folds[r].0.verify(pos, commitment.roots[r])?;
            self.folds[r].1.verify(pos + m, commitment.roots[r])?;
            self.folds[r].2.verify(pos + 2 * m, commitment.roots[r])?;

            let alpha = poseidon::hash_t3(&[*DST, commitment.roots[r]]);
            let k_r = ilog3(n_r) as u32;
            let omega_inv = Scalar::THREE_ADIC_ROOT_OF_UNITY_INV.pow_vartime([
                3u64.pow(Scalar::T - k_r),
                0,
                0,
                0,
            ]);
            let omega_m = omega_inv.pow_vartime([2 * m as u64, 0, 0, 0]);
            let omega_m_sq = omega_m * omega_m;
            let omega_inv_pos = omega_inv.pow_vartime([pos as u64, 0, 0, 0]);

            let v0 = *self.folds[r].0.value();
            let v1 = *self.folds[r].1.value();
            let v2 = *self.folds[r].2.value();

            let g0 = (v0 + v1 + v2) * Scalar::THREE_INV;
            let g1 = (v0 + v1 * omega_m_sq + v2 * omega_m) * Scalar::THREE_INV * omega_inv_pos;
            let g2 = (v0 + v1 * omega_m + v2 * omega_m_sq)
                * Scalar::THREE_INV
                * omega_inv_pos
                * omega_inv_pos;
            let folded = g0 + alpha * g1 + alpha * alpha * g2;

            let expected = if r + 1 == k {
                commitment.roots[r + 1]
            } else {
                match pos * 3 / m {
                    0 => *self.folds[r + 1].0.value(),
                    1 => *self.folds[r + 1].1.value(),
                    _ => *self.folds[r + 1].2.value(),
                }
            };

            if folded != expected {
                return Err(anyhow!("fold consistency check failed at round {}", r));
            }

            q = pos;
            n_r = m;
        }

        Ok(())
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
    /// The number of elements in the committed vector rounded up to the next power of 3.
    count: usize,
    /// A flat array containing all scalars using the layout described above.
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
            Scalar::THREE_ADIC_ROOT_OF_UNITY_INV.pow_vartime([3u64.pow(Scalar::T - k), 0, 0, 0]);

        let m = n / 3;
        let omega_m = omega_inv.pow_vartime([2 * m as u64, 0, 0, 0]);
        let omega_m_sq = omega_m * omega_m;
        let alpha_sq = alpha * alpha;

        let mut omega_inv_i = Scalar::ONE;
        for i in 0..m {
            let v0 = values[i];
            let v1 = values[i + m];
            let v2 = values[i + 2 * m];

            let g0 = (v0 + v1 + v2) * Scalar::THREE_INV;
            let g1 = (v0 + v1 * omega_m_sq + v2 * omega_m) * Scalar::THREE_INV * omega_inv_i;
            let g2 = (v0 + v1 * omega_m + v2 * omega_m_sq)
                * Scalar::THREE_INV
                * omega_inv_i
                * omega_inv_i;

            values[(3 * n - 1) / 2 + i] = g0 + alpha * g1 + alpha_sq * g2;
            omega_inv_i *= omega_inv;
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
    /// The underlying algorithms require that the number of committed values is a power of three,
    /// so if that's not the case this function will automatically pad them with zeros.
    pub fn new(mut values: Vec<Scalar>) -> Self {
        let n = next_power_of_three(values.len());
        assert!(ilog3(n) <= Scalar::T as usize);
        values.resize((9 * n - 1) / 4, Scalar::ZERO);
        merklify(&mut values[0..((3 * n - 1) / 2)], n);
        Self::fold_all(&mut values, n);
        Self { count: n, values }
    }

    /// Returns the length of the original committed vector (always a power of 3).
    pub fn length(&self) -> usize {
        self.count
    }

    /// Creates the FRI commitment for the committed vector.
    pub fn commit(&self) -> Commitment {
        let mut n = self.length();
        let k = ilog3(n) + 1;
        let mut roots = vec![Scalar::ZERO; k];
        let mut offset = 0usize;
        for i in 0..k {
            roots[i] = self.values[offset + 3 * (n - 1) / 2];
            offset += (3 * n - 1) / 2;
            n /= 3;
        }
        Commitment { roots }
    }

    /// Builds a FRI opening proof for the value at the specified index of the evaluation domain.
    pub fn open_at(&self, index: usize) -> Proof {
        let mut n = self.length();
        assert!(index < n);

        let value = self.values[index];
        let mut folds = Vec::with_capacity(ilog3(n));
        let mut offset = 0usize;
        let mut q = index;

        while n > 1 {
            let tree_size = (3 * n - 1) / 2;
            let m = n / 3;
            let pos = q % m;
            folds.push((
                LeafProof::new(&self.values[offset..offset + tree_size], n, pos),
                LeafProof::new(&self.values[offset..offset + tree_size], n, pos + m),
                LeafProof::new(&self.values[offset..offset + tree_size], n, pos + 2 * m),
            ));
            offset += tree_size;
            n = m;
            q = pos;
        }

        Proof {
            index,
            value,
            folds,
        }
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

    #[test]
    fn test_empty_vector_commitment() {
        let prover = Prover::new(vec![]);
        let commitment = prover.commit();
        assert_eq!(commitment.roots(), vec![Scalar::ZERO]);
    }

    #[test]
    fn test_commit_one_element_1() {
        let prover = Prover::new(vec![12.into()]);
        let commitment = prover.commit();
        assert_eq!(commitment.roots(), vec![12.into()]);
    }

    #[test]
    fn test_commit_one_element_2() {
        let prover = Prover::new(vec![34.into()]);
        let commitment = prover.commit();
        assert_eq!(commitment.roots(), vec![34.into()]);
    }

    #[test]
    fn test_commit_two_elements_1() {
        let prover = Prover::new(vec![56.into(), 78.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x782b98187d82e99def511fe7c7b8be449ddeacbc16190b3e5b09935aa1352e68"),
                parse_scalar("0x7bf5334e0ef8727840282a567988144cd4230b0dd12b5c7f660b1a70e1f30bd8"),
            ]
        );
    }

    #[test]
    fn test_commit_two_elements_2() {
        let prover = Prover::new(vec![78.into(), 56.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x2dc37da8609d4b9d333d1660264e9cc0402c0c2e76a31d334e926b2b1b65e5f6"),
                parse_scalar("0x688fbe7c24366e25ce879e8d34aff0fa21ea9d5c511045700298877e5fde9b3c"),
            ]
        );
    }

    #[test]
    fn test_commit_two_elements_3() {
        let prover = Prover::new(vec![78.into(), 90.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x2dfc8ad00312f501c230ed8a1949f1bef30bc9ba70a396f1a4ee894cc7b02703"),
                parse_scalar("0x5181f1bc1364bf1402fe6b64d67e08693add577d36b9950e876a6109f49dd96f"),
            ]
        );
    }

    #[test]
    fn test_commit_three_elements_1() {
        let prover = Prover::new(vec![56.into(), 78.into(), 0.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x782b98187d82e99def511fe7c7b8be449ddeacbc16190b3e5b09935aa1352e68"),
                parse_scalar("0x7bf5334e0ef8727840282a567988144cd4230b0dd12b5c7f660b1a70e1f30bd8"),
            ]
        );
    }

    #[test]
    fn test_commit_three_elements_2() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x236092ebefc7e6565e0e75414d8fdce1ce2e19bb59002d36b794b9c3111bb9cd"),
                parse_scalar("0x7245aef7c5350ac88c79b4e4e38a731b5f74ec16764f37ae88ed5acbbdb1c6cd"),
            ]
        );
    }

    #[test]
    fn test_commit_four_elements() {
        let prover = Prover::new(vec![34.into(), 56.into(), 78.into(), 90.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x15bc73f34d10d0269af70050d2e6dbe50c7486acdce791b66143dd6a49566605"),
                parse_scalar("0x1378e8b4af85f154a8418f6d42180f5b24abf8b2f2e8f6395ee5e4066020f6fa"),
                parse_scalar("0x4b09fed4ebea20ffa93b130a9dd35d30899f3baaa450f6c676eded4391910a6a"),
            ]
        );
    }

    #[test]
    fn test_commit_nine_elements_1() {
        let prover = Prover::new(vec![
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x15bc73f34d10d0269af70050d2e6dbe50c7486acdce791b66143dd6a49566605"),
                parse_scalar("0x1378e8b4af85f154a8418f6d42180f5b24abf8b2f2e8f6395ee5e4066020f6fa"),
                parse_scalar("0x4b09fed4ebea20ffa93b130a9dd35d30899f3baaa450f6c676eded4391910a6a"),
            ]
        );
    }

    #[test]
    fn test_commit_nine_elements_2() {
        let prover = Prover::new(vec![
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            78.into(),
            56.into(),
            34.into(),
            12.into(),
        ]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x2c4e52ae8124220a5df522f37ccb8f6be7506ade1251e462a769db6c876ae321"),
                parse_scalar("0x7b4a7923d7ad754e5641f3d29b385c67b9910a15e3e83d2f56df18d5df51146d"),
                parse_scalar("0x798bb437e054919147e6c4579a8fd33cdc62b3c3628cdaa1125e025d2b17da81"),
            ]
        );
    }

    fn open_and_verify_all(values: Vec<Scalar>) {
        let prover = Prover::new(values.clone());
        let commitment = prover.commit();
        for (index, value) in values.iter().enumerate() {
            let proof = prover.open_at(index);
            assert_eq!(proof.index(), index);
            assert_eq!(*proof.value(), *value);
            assert!(proof.verify(&commitment).is_ok());
        }
    }

    #[test]
    fn test_open_verify_one() {
        open_and_verify_all(vec![42.into()]);
    }

    #[test]
    fn test_open_verify_three() {
        open_and_verify_all(vec![10.into(), 20.into(), 30.into()]);
    }

    #[test]
    fn test_open_verify_nine() {
        open_and_verify_all(vec![
            1.into(),
            2.into(),
            3.into(),
            4.into(),
            5.into(),
            6.into(),
            7.into(),
            8.into(),
            9.into(),
        ]);
    }

    #[test]
    fn test_open_verify_non_power_of_three() {
        open_and_verify_all(vec![11.into(), 22.into(), 33.into(), 44.into(), 55.into()]);
    }

    #[test]
    fn test_verify_rejects_wrong_value() {
        let prover = Prover::new(vec![1.into(), 2.into(), 3.into()]);
        let commitment = prover.commit();
        let mut proof = prover.open_at(1);
        proof.value = 99.into();
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_commitment() {
        let prover = Prover::new(vec![1.into(), 2.into(), 3.into()]);
        let other = Prover::new(vec![9.into(), 8.into(), 7.into()]);
        let proof = prover.open_at(0);
        assert!(proof.verify(&other.commit()).is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_fold_value() {
        let prover = Prover::new(vec![
            1.into(),
            2.into(),
            3.into(),
            4.into(),
            5.into(),
            6.into(),
            7.into(),
            8.into(),
            9.into(),
        ]);
        let commitment = prover.commit();
        let mut proof = prover.open_at(0);
        proof.folds[0].1.value = 99.into();
        assert!(proof.verify(&commitment).is_err());
    }
}
