use crate::bluesky::Scalar;
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use std::sync::LazyLock;

/// Domain separator tag for Fiat-Shamir challenges.
static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri2/challenge"));

/// Computes all Merkle hashes of a vector of values up to the root.
///
/// `n` is the number of values and must be a power of two.
///
/// The full Merkle tree is stored inline in the `values` vector as follows:
///
///   * the first `n` elements are the values of the original vector,
///   * the next `n / 2` elements are the hashes of the second-last layer of the tree,
///   * the next `n / 4` elements are the hashes of the third-last layer of the tree,
///   * ...
///   * the last stored element is the Merkle root.
///
/// It's the caller's responsibility to ensure the `values` array has at least `n * 2 - 1` slots so
/// that the full tree can be stored.
///
/// Note that the Merkle root will be at index `(n - 1) * 2`.
fn merklify(values: &mut [Scalar], mut n: usize) {
    assert!(n.is_power_of_two());
    let mut i = 0;
    while n > 1 {
        let m = n / 2;
        for j in 0..m {
            values[i + n + j] = poseidon::hash_t3(&[values[i + j * 2], values[i + j * 2 + 1]]);
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

/// A Merkle proof for a single value in a Merkle tree.
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
    path: Vec<Scalar>,
}

impl LeafProof {
    /// Builds a Merkle proof for the leaf at `index` in a tree with `n` leaves.
    ///
    /// The tree is stored in `values` using the layout described in `merklify`.
    ///
    /// REQUIRES: `n` must be a power of 2.
    /// REQUIRES: values.len() >= n * 2 - 1
    /// REQUIRES: index < n
    fn new(values: &[Scalar], mut n: usize, mut index: usize) -> Self {
        debug_assert!(n.is_power_of_two());
        let value = values[index];
        let mut path = Vec::with_capacity(n.trailing_zeros() as usize);
        let mut i = 0usize;
        while n > 1 {
            path.push(values[i + (index ^ 1)]);
            i += n;
            n /= 2;
            index >>= 1;
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
        for sibling in &self.path {
            hash = if index & 1 != 0 {
                poseidon::hash_t3(&[*sibling, hash])
            } else {
                poseidon::hash_t3(&[hash, *sibling])
            };
            index >>= 1;
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

/// A complete FRI opening proof.
#[derive(Debug, Clone)]
pub struct Proof {
    /// The index of the element we're opening.
    index: usize,
    /// The opened value.
    value: Scalar,
    /// Proves a pair of "partner" values at each folding round with one `LeafProof` pair for every
    /// round. Note that either `folds[0].0` or `folds[0].1` proves `value`.
    folds: Vec<(LeafProof, LeafProof)>,
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
        let n = 1usize << k;

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

        let value_in_folds = if self.index < n / 2 {
            *self.folds[0].0.value()
        } else {
            *self.folds[0].1.value()
        };
        if self.value != value_in_folds {
            return Err(anyhow!("value does not match folds[0]"));
        }

        let mut q = self.index;
        let mut n_r = n;

        for r in 0..k {
            let m = n_r / 2;
            let pos = q % m;
            let neg = pos + m;

            self.folds[r].0.verify(pos, commitment.roots[r])?;
            self.folds[r].1.verify(neg, commitment.roots[r])?;

            let alpha = poseidon::hash_t3(&[*DST, commitment.roots[r]]);
            let k_r = n_r.trailing_zeros();
            let omega_inv =
                Scalar::ROOT_OF_UNITY_INV.pow_vartime([1u64 << (Scalar::S - k_r), 0, 0, 0]);
            let omega_inv_pos = omega_inv.pow_vartime([pos as u64, 0, 0, 0]);
            let f_pos = *self.folds[r].0.value();
            let f_neg = *self.folds[r].1.value();
            let folded =
                (f_pos + f_neg + alpha * omega_inv_pos * (f_pos - f_neg)) * Scalar::TWO_INV;

            let expected = if r + 1 == k {
                commitment.roots[r + 1]
            } else if pos < m / 2 {
                *self.folds[r + 1].0.value()
            } else {
                *self.folds[r + 1].1.value()
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
/// The struct contains the original committed vector, the Merkle tree built upon it, all folded
/// polynomials, and all Merkle trees of all folded polynomials. All scalars are laid out on a
/// single flat array.
///
/// Each Merkle tree is complete because the size of the bottom layer is always a power of 2, so we
/// store it inline using `2n` slots, with `n` being the size of the bottom layer. Note: a complete
/// binary tree with `n` leaves would normally require `2n-1` slots, but we pad all trees with an
/// empty slot to simplify the layout formula. This results in `log2(n)` unused slots in total,
/// which we deem acceptable.
///
/// The layout of a Merkle tree with `n` leaves is the one generated by the `merklify` function
/// above, plus an extra element for padding. Our Merkle trees are stored in the `values` array
/// sequentially as follows:
///
///   * the first tree is the main Merkle tree (`n` committed elements, `2n` used slots),
///   * the second tree is the one resulting from the first folding round (`n/2` leaves, `n` used
///     slots),
///   * the third tree is the one resulting from the second folding round (`n/4` leaves, `n/2` used
///     slots),
///
/// etc.
///
/// The total size of the `values` array is `4n-2`.
#[derive(Debug, Clone)]
pub struct Prover {
    values: Vec<Scalar>,
}

impl Prover {
    /// Runs a folding round over a Merkle tree with `n` leaves, resulting in a new Merkle tree with
    /// `n/2` leaves.
    ///
    /// The input Merkle tree must be stored at the beginning of the provided slice, so that the
    /// first `n` elements of the slice are the evaluations of the polynomial to fold.
    ///
    /// The root of the input Merkle tree is therefore located at index `(n - 1) * 2` and is used to
    /// generate the Fiat-Shamir challenge for the round.
    ///
    /// The output Merkle tree will be stored at offset `2n` and will take exactly `n` slots
    /// (including the final padding element). It's the caller's responsibility to ensure that
    /// `values` has enough space.
    fn fold(values: &mut [Scalar], n: usize) {
        assert!(n.is_power_of_two());

        let alpha = poseidon::hash_t3(&[*DST, values[(n - 1) * 2]]);

        let k = n.trailing_zeros();
        let omega_inv = Scalar::ROOT_OF_UNITY_INV.pow_vartime([1u64 << (Scalar::S - k), 0, 0, 0]);

        let m = n / 2;
        let mut omega_inv_i = Scalar::ONE;
        for i in 0..m {
            let f_pos = values[i];
            let f_neg = values[i + m];
            values[2 * n + i] =
                (f_pos + f_neg + alpha * omega_inv_i * (f_pos - f_neg)) * Scalar::TWO_INV;
            omega_inv_i *= omega_inv;
        }

        merklify(&mut values[(2 * n)..(3 * n)], m);
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
            offset += 2 * m;
            m /= 2;
        }
    }

    /// Constructs a new FRI prover that commits to the provided list of `values`.
    ///
    /// The underlying algorithms require that the number of committed values is a power of two, so
    /// if that's not the case this function will automatically pad them with zeros.
    pub fn new(mut values: Vec<Scalar>) -> Self {
        let n = values.len().next_power_of_two();
        assert!(n <= 1usize << Scalar::S);
        values.resize(n * 4 - 2, Scalar::ZERO);
        merklify(&mut values[0..(2 * n)], n);
        Self::fold_all(&mut values, n);
        Self { values }
    }

    /// Returns the length of the original committed vector.
    pub fn length(&self) -> usize {
        (self.values.len() + 2) / 4
    }

    /// Creates the FRI commitment for the committed vector.
    pub fn commit(&self) -> Commitment {
        let mut n = self.length();
        let k = (n.trailing_zeros() + 1) as usize;
        let mut roots = vec![Scalar::ZERO; k];
        let mut offset = 0usize;
        for i in 0..k {
            roots[i] = self.values[offset + (n - 1) * 2];
            offset += n * 2;
            n /= 2;
        }
        Commitment { roots }
    }

    /// Builds a FRI opening proof for the value at the specified index of the evaluation domain.
    pub fn open_at(&self, index: usize) -> Proof {
        let mut n = self.length();
        assert!(index < n);

        let value = self.values[index];
        let mut folds = Vec::with_capacity(n.trailing_zeros() as usize);

        let mut offset = 0usize;
        let mut q = index;

        while n > 1 {
            let next_offset = offset + n * 2;
            let m = n / 2;
            let pos = q % m;
            let neg = pos + m;
            folds.push((
                LeafProof::new(&self.values[offset..next_offset], n, pos),
                LeafProof::new(&self.values[offset..next_offset], n, neg),
            ));
            offset = next_offset;
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
    fn test_merklify_two() {
        let mut values = vec![34.into(), 56.into()];
        values.resize(3, 0.into());
        merklify(&mut values, 2);
        assert_eq!(
            values,
            vec![
                34.into(),
                56.into(),
                parse_scalar("0x5ec03322128c00fc47cb817c548a0dd60d1f10817b4cefe8ad1de3ea4504a552")
            ]
        );
    }

    #[test]
    fn test_merklify_four() {
        let mut values = vec![78.into(), 90.into(), 12.into(), 34.into()];
        values.resize(7, 0.into());
        merklify(&mut values, 4);
        assert_eq!(
            values,
            vec![
                78.into(),
                90.into(),
                12.into(),
                34.into(),
                parse_scalar("0x64276ccf57e84d0b2cbf42907160074c5d3db75ff85bd92d78580624c8cd8260"),
                parse_scalar("0x165e74be18ef4be6de5e232cd3480dcc38176807ac918b904576964612c5b6de"),
                parse_scalar("0x1b207cff4c6c97c46c0b950b7524dae299cf3b48d766f0e5990a63fc378cba29"),
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
                parse_scalar("0x38e7bb7b6ccae0c74031423877db058f4ab3a284964e2d91bf97497851eca5db"),
                parse_scalar("0x2235bc231a4a1a51bd36cf648a8f29d0446045ab530ce75dafd68413de05dcc1"),
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
                parse_scalar("0x1befadaea6bd1cf2b575269ecd25b536e965ca76b0a605acdc907b132caa2407"),
                parse_scalar("0x30c06125c2f978f9cc91b0cb5094312a7741074dba9bc26af219fc4309b2acb1"),
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
                parse_scalar("0x64276ccf57e84d0b2cbf42907160074c5d3db75ff85bd92d78580624c8cd8260"),
                parse_scalar("0x29f412f3ebb68bd1a08894ef0012f570e68012e3b9c99abc5fb465603996219d"),
            ]
        );
    }

    #[test]
    fn test_commit_three_elements_1() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x128d169b8d3b12c340f50556ab8b4363434da8fd2eb1fc10031b1bc4ae4547ef"),
                parse_scalar("0x553f8ee71cb542c0907824df502548adbc6e2aa1480306ef25425e30483f798b"),
                parse_scalar("0x1db640d0d059f9f4abc1a87afdeb95f0d650ece4992da9a57849c21be79c4eb3"),
            ]
        );
    }

    #[test]
    fn test_commit_three_elements_2() {
        let prover = Prover::new(vec![78.into(), 90.into(), 12.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x0cbbc7748a2f74433a266e8610d2cf53a5c56fdc029bd61e843f4afc4aa4df8d"),
                parse_scalar("0x1668d9873f5011a10e8742bd738124974202cbf760c9f24912dd386d2b234312"),
                parse_scalar("0x27d7a92dd73748e2b69c63b0efabcc6b8021904a4fde9ca7dd66f90ab0e3155b"),
            ]
        );
    }

    #[test]
    fn test_commit_four_elements_1() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into(), 0.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x128d169b8d3b12c340f50556ab8b4363434da8fd2eb1fc10031b1bc4ae4547ef"),
                parse_scalar("0x553f8ee71cb542c0907824df502548adbc6e2aa1480306ef25425e30483f798b"),
                parse_scalar("0x1db640d0d059f9f4abc1a87afdeb95f0d650ece4992da9a57849c21be79c4eb3"),
            ]
        );
    }

    #[test]
    fn test_commit_four_elements_2() {
        let prover = Prover::new(vec![34.into(), 56.into(), 78.into(), 90.into()]);
        let commitment = prover.commit();
        assert_eq!(
            commitment.roots(),
            vec![
                parse_scalar("0x752cc74f03f5419d2d899ae717ea7d843f5fa3f2db53b87cb24afecf56050db4"),
                parse_scalar("0x2e6db60e1ec63487e65e09212472aa094f00f270927f00d17d7c1c3937f61a2f"),
                parse_scalar("0x1138aea576f58a7c574a79187cde3ec230a00c9b4cc84eada73f16010dc85ecf"),
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
    fn test_open_verify_two() {
        open_and_verify_all(vec![56.into(), 78.into()]);
    }

    #[test]
    fn test_open_verify_four() {
        open_and_verify_all(vec![12.into(), 34.into(), 56.into(), 78.into()]);
    }

    #[test]
    fn test_open_verify_non_power_of_two() {
        open_and_verify_all(vec![10.into(), 20.into(), 30.into()]);
    }

    #[test]
    fn test_verify_rejects_wrong_value() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        let commitment = prover.commit();
        let mut proof = prover.open_at(1);
        proof.value = 99.into();
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_commitment() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        let other = Prover::new(vec![99.into(), 88.into(), 77.into(), 66.into()]);
        let proof = prover.open_at(0);
        assert!(proof.verify(&other.commit()).is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_fold_value() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        let commitment = prover.commit();
        let mut proof = prover.open_at(0);
        proof.folds[0].1.value = 99.into();
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_verify_rejects_tampered_fold_path() {
        let prover = Prover::new(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        let commitment = prover.commit();
        let mut proof = prover.open_at(2);
        proof.folds[0].0.path[0] = 99.into();
        assert!(proof.verify(&commitment).is_err());
    }
}
