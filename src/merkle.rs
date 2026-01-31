use crate::utils;
use crate::xits;
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use ff::Field;
use std::fmt::Debug;

/// Makes a type representable as a BLS12-381 scalar. Must be implemened by all Merkle tree values.
///
/// Typical implementations use the value itself when it fits in a single scalar (e.g. u64 or
/// BLS12-381 scalars themselves), and use a Poseidon hash when it doesn't.
///
/// NOTE: the returned scalar must never change while the value is stored in the Merkle tree.
/// Typical implementations are simply immutable so that the returned representation never changes.
pub trait AsScalar {
    fn as_scalar(&self) -> Scalar;
}

impl AsScalar for Scalar {
    fn as_scalar(&self) -> Scalar {
        *self
    }
}

impl AsScalar for u32 {
    fn as_scalar(&self) -> Scalar {
        Scalar::from(*self as u64)
    }
}

impl AsScalar for u64 {
    fn as_scalar(&self) -> Scalar {
        Scalar::from(*self)
    }
}

/// Makes a type parseable from a BLS12-381 scalar. Must be implemented by all types used as keys in
/// Merkle trees.
///
/// BLS12-381 scalars are encoded in 32 bytes (they are ~255 bits wide) but if the key type requires
/// less than that then the least significant bytes must be used, not the most significant ones.
/// That is because the least significant bits are the ones closer to the leaves, as opposed to the
/// most significant ones which are closest to the root, and using the former allows for trees of
/// lower height.
pub trait FromScalar: Sized {
    fn from_scalar(scalar: Scalar) -> Result<Self>;
}

impl FromScalar for Scalar {
    fn from_scalar(scalar: Scalar) -> Result<Self> {
        Ok(scalar)
    }
}

impl FromScalar for u32 {
    fn from_scalar(scalar: Scalar) -> Result<Self> {
        let bytes32 = scalar.to_bytes_le();
        for i in 4..32 {
            if bytes32[i] != 0 {
                return Err(anyhow!("invalid 32-bit scalar"));
            }
        }
        let mut bytes4 = [0u8; 4];
        bytes4.copy_from_slice(&bytes32[0..4]);
        Ok(u32::from_le_bytes(bytes4))
    }
}

impl FromScalar for u64 {
    fn from_scalar(scalar: Scalar) -> Result<Self> {
        let bytes32 = scalar.to_bytes_le();
        for i in 8..32 {
            if bytes32[i] != 0 {
                return Err(anyhow!("invalid 64-bit scalar"));
            }
        }
        let mut bytes8 = [0u8; 8];
        bytes8.copy_from_slice(&bytes32[0..8]);
        Ok(u64::from_le_bytes(bytes8))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> {
    key: K,
    value: V,
    path: [[Scalar; W]; H],
    root_hash: Scalar,
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const W: usize,
    const H: usize,
> Proof<K, V, W, H>
{
    pub fn new(key: K, value: V, path: [[Scalar; W]; H], root_hash: Scalar) -> Self {
        Self {
            key,
            value,
            path,
            root_hash,
        }
    }

    pub fn key(&self) -> K {
        self.key
    }

    pub fn value(&self) -> &V {
        &self.value
    }

    pub fn take_value(self) -> V {
        self.value
    }

    /// Returns a new proof with the value replaced by the provided one, failing if the scalar
    /// representation of the two values doesn't match.
    pub fn map<U: Debug + Clone + Send + Sync + AsScalar + 'static>(
        self,
        new_value: U,
    ) -> Result<Proof<K, U, W, H>> {
        let current_hash = self.value.as_scalar();
        let new_hash = new_value.as_scalar();
        if new_hash != current_hash {
            return Err(anyhow!(
                "cannot map Merkle proof from value hash {} to value hash {}",
                utils::format_scalar(current_hash),
                utils::format_scalar(new_hash)
            ));
        }
        Ok(Proof {
            key: self.key,
            value: new_value,
            path: self.path,
            root_hash: self.root_hash,
        })
    }

    pub fn path(&self) -> &[[Scalar; W]; H] {
        &self.path
    }

    pub fn root_hash(&self) -> Scalar {
        self.root_hash
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> Proof<K, V, 2, H>
{
    fn reconstruct_path(
        mut key: Scalar,
        mut value: Scalar,
        hashes: &[Scalar],
    ) -> Result<[[Scalar; 2]; H]> {
        if hashes.len() != H {
            return Err(anyhow!(
                "wrong number of hashes in Merkle proof: got {}, want {}",
                hashes.len(),
                H
            ));
        }
        let mut path = [[Scalar::ZERO; 2]; H];
        for i in 0..H {
            let bit = xits::and1(key);
            key = xits::shr1(key);
            if bit != 0.into() {
                path[i] = [hashes[i], value];
            } else {
                path[i] = [value, hashes[i]];
            }
            value = utils::poseidon_hash(&path[i]);
        }
        Ok(path)
    }

    pub fn from_compressed(key: K, value: V, root_hash: Scalar, hashes: &[Scalar]) -> Result<Self> {
        let path = Self::reconstruct_path(key.as_scalar(), value.as_scalar(), hashes)?;
        Ok(Self {
            key,
            value,
            path,
            root_hash,
        })
    }

    pub fn compressed_path(&self) -> [Scalar; H] {
        let mut key = self.key.as_scalar();
        let mut path = [Scalar::ZERO; H];
        for i in 0..H {
            let bit = xits::and1(key);
            key = xits::shr1(key);
            if bit != 0.into() {
                path[i] = self.path[i][0];
            } else {
                path[i] = self.path[i][1];
            }
        }
        path
    }

    pub fn verify(&self) -> Result<()> {
        let mut key = self.key.as_scalar();
        let mut hash = self.value.as_scalar();
        for children in self.path {
            let bit = xits::and1(key);
            let bit = bit.to_bytes_le()[0] as usize;
            if hash != children[bit] {
                return Err(anyhow!(
                    "hash mismatch: got {}, want {}",
                    utils::format_scalar(children[bit]),
                    utils::format_scalar(hash),
                ));
            }
            key = xits::shr1(key);
            hash = utils::poseidon_hash(&children);
        }
        if hash != self.root_hash {
            return Err(anyhow!(
                "final hash mismatch: got {}, want {}",
                utils::format_scalar(self.root_hash),
                utils::format_scalar(hash),
            ));
        }
        Ok(())
    }
}

impl<
    K: Debug + Copy + Send + Sync + FromScalar + AsScalar + 'static,
    V: Debug + Clone + Send + Sync + AsScalar + 'static,
    const H: usize,
> Proof<K, V, 3, H>
{
    fn reconstruct_path(
        mut key: Scalar,
        mut value: Scalar,
        hashes: &[[Scalar; 2]],
    ) -> Result<[[Scalar; 3]; H]> {
        if hashes.len() != H {
            return Err(anyhow!(
                "wrong number of hashes in Merkle proof: got {}, want {}",
                hashes.len(),
                H
            ));
        }
        let mut path = [[Scalar::ZERO; 3]; H];
        for i in 0..H {
            let trit = xits::mod3(key);
            key = xits::div3(key);
            if trit == 0.into() {
                path[i] = [value, hashes[i][0], hashes[i][1]];
            } else if trit == 1.into() {
                path[i] = [hashes[i][0], value, hashes[i][1]];
            } else if trit == 2.into() {
                path[i] = [hashes[i][0], hashes[i][1], value];
            } else {
                unreachable!();
            }
            value = utils::poseidon_hash(&path[i]);
        }
        Ok(path)
    }

    pub fn from_compressed(
        key: K,
        value: V,
        root_hash: Scalar,
        hashes: &[[Scalar; 2]],
    ) -> Result<Self> {
        let path = Self::reconstruct_path(key.as_scalar(), value.as_scalar(), hashes)?;
        Ok(Self {
            key,
            value,
            path,
            root_hash,
        })
    }

    pub fn compressed_path(&self) -> [[Scalar; 2]; H] {
        let mut key = self.key.as_scalar();
        let mut path = [[Scalar::ZERO; 2]; H];
        for i in 0..H {
            let trit = xits::mod3(key);
            key = xits::div3(key);
            if trit == 0.into() {
                path[i] = [self.path[i][1], self.path[i][2]];
            } else if trit == 1.into() {
                path[i] = [self.path[i][0], self.path[i][2]];
            } else if trit == 2.into() {
                path[i] = [self.path[i][0], self.path[i][1]];
            } else {
                unreachable!();
            }
        }
        path
    }

    pub fn verify(&self) -> Result<()> {
        let mut key = self.key.as_scalar();
        let mut hash = self.value.as_scalar();
        for children in self.path {
            let trit = xits::mod3(key);
            let trit = trit.to_bytes_le()[0] as usize;
            if hash != children[trit] {
                return Err(anyhow!(
                    "hash mismatch: got {}, want {}",
                    utils::format_scalar(children[trit]),
                    utils::format_scalar(hash),
                ));
            }
            key = xits::div3(key);
            hash = utils::poseidon_hash(&children);
        }
        if hash != self.root_hash {
            return Err(anyhow!(
                "final hash mismatch: got {}, want {}",
                utils::format_scalar(self.root_hash),
                utils::format_scalar(hash),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::testing::parse_scalar;

    #[test]
    fn test_scalar_as_scalar() {
        let value =
            parse_scalar("0x4bbbaa6849aeede337bab1b0271b2fc649170a6333866d8106bb65fba05109a7");
        assert_eq!(value.as_scalar(), value);
    }

    #[test]
    fn test_u32_as_scalar() {
        assert_eq!(0xa05109a7u32.as_scalar(), parse_scalar("0xa05109a7"));
    }

    #[test]
    fn test_u64_as_scalar() {
        assert_eq!(
            0x06bb65fba05109a7u64.as_scalar(),
            parse_scalar("0x06bb65fba05109a7")
        );
    }

    #[test]
    fn test_scalar_from_scalar() {
        let scalar =
            parse_scalar("0x4bbbaa6849aeede337bab1b0271b2fc649170a6333866d8106bb65fba05109a7");
        assert_eq!(scalar, Scalar::from_scalar(scalar).unwrap());
    }

    #[test]
    fn test_u32_from_scalar() {
        assert_eq!(
            0xa05109a7u32,
            u32::from_scalar(parse_scalar("0xa05109a7")).unwrap()
        );
    }

    #[test]
    fn test_u64_from_scalar() {
        assert_eq!(
            0x06bb65fba05109a7u64,
            u64::from_scalar(parse_scalar("0x06bb65fba05109a7")).unwrap()
        );
    }

    #[test]
    fn test_proof_2_0() {
        let root_hash =
            parse_scalar("0x2f1e5f91aa954def1ed17cb40d9fd24da546f68da56f314ca3f7e4dc1d0a2400");
        let value =
            parse_scalar("0x2f1e5f91aa954def1ed17cb40d9fd24da546f68da56f314ca3f7e4dc1d0a2400");
        let proof = Proof::<Scalar, Scalar, 2, 0>::from_compressed(0.into(), value, root_hash, &[])
            .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_2_1_left() {
        let root_hash =
            parse_scalar("0x13aabe6d8d1ea32e1d1efc19d499440d1142d4dc02609dbb7cf2b65c433069ab");
        let left =
            parse_scalar("0x649911b84fd6fceb1314d8eda893ee60abb4f55d52ef2a7a88491587dd432c24");
        let right =
            parse_scalar("0x11be4b396567dc3aef3f8e3e9a621aaedb507d5aa7f8bcc1da64d28b8e22e811");
        let proof =
            Proof::<Scalar, Scalar, 2, 1>::from_compressed(0.into(), left, root_hash, &[right])
                .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_2_1_right() {
        let root_hash =
            parse_scalar("0x13aabe6d8d1ea32e1d1efc19d499440d1142d4dc02609dbb7cf2b65c433069ab");
        let left =
            parse_scalar("0x649911b84fd6fceb1314d8eda893ee60abb4f55d52ef2a7a88491587dd432c24");
        let right =
            parse_scalar("0x11be4b396567dc3aef3f8e3e9a621aaedb507d5aa7f8bcc1da64d28b8e22e811");
        let proof =
            Proof::<Scalar, Scalar, 2, 1>::from_compressed(1.into(), right, root_hash, &[left])
                .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_2_2_00() {
        let root_hash =
            parse_scalar("0x2ea3e8888f132ca1f224698490b5613ad178d5ec41e4cfbf6397a8bfa22f41cd");
        let value =
            parse_scalar("0xc777df35747c268a08f5ca158972a8fc04f5cdb460c47ae63c4fc758c72844b");
        let sister1 =
            parse_scalar("0x539b16757d586f847a0821b28d3177a484457451b4f90fe9b51c96348de51d53");
        let sister2 =
            parse_scalar("0x6ab45fd4070883dc5ea816a1b4919223f4e7e23a321f58ae9f4adc4ba92f56c1");
        let proof = Proof::<Scalar, Scalar, 2, 2>::from_compressed(
            0.into(),
            value,
            root_hash,
            &[sister1, sister2],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_2_2_01() {
        let root_hash =
            parse_scalar("0x49b1fb8f09f556ffb909110010eb6437bc776248d53092fd4225a6ff0befd780");
        let value =
            parse_scalar("0xc777df35747c268a08f5ca158972a8fc04f5cdb460c47ae63c4fc758c72844b");
        let sister1 =
            parse_scalar("0x539b16757d586f847a0821b28d3177a484457451b4f90fe9b51c96348de51d53");
        let sister2 =
            parse_scalar("0x6ab45fd4070883dc5ea816a1b4919223f4e7e23a321f58ae9f4adc4ba92f56c1");
        let proof = Proof::<Scalar, Scalar, 2, 2>::from_compressed(
            1.into(),
            value,
            root_hash,
            &[sister1, sister2],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_2_2_10() {
        let root_hash =
            parse_scalar("0x5de6173e8862dd5099ac2abc2bcc738cd26bf0e31134b712774ac4650fc8684e");
        let value =
            parse_scalar("0xc777df35747c268a08f5ca158972a8fc04f5cdb460c47ae63c4fc758c72844b");
        let sister1 =
            parse_scalar("0x539b16757d586f847a0821b28d3177a484457451b4f90fe9b51c96348de51d53");
        let sister2 =
            parse_scalar("0x6ab45fd4070883dc5ea816a1b4919223f4e7e23a321f58ae9f4adc4ba92f56c1");
        let proof = Proof::<Scalar, Scalar, 2, 2>::from_compressed(
            2.into(),
            value,
            root_hash,
            &[sister1, sister2],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_2_2_11() {
        let root_hash =
            parse_scalar("0x40d3e3924c147a60a84b2e7150842d9822d596fa22bd92c5bfe59b2e64905a33");
        let value =
            parse_scalar("0xc777df35747c268a08f5ca158972a8fc04f5cdb460c47ae63c4fc758c72844b");
        let sister1 =
            parse_scalar("0x539b16757d586f847a0821b28d3177a484457451b4f90fe9b51c96348de51d53");
        let sister2 =
            parse_scalar("0x6ab45fd4070883dc5ea816a1b4919223f4e7e23a321f58ae9f4adc4ba92f56c1");
        let proof = Proof::<Scalar, Scalar, 2, 2>::from_compressed(
            3.into(),
            value,
            root_hash,
            &[sister1, sister2],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_0() {
        let root_hash =
            parse_scalar("0x22853de9cbf26d30c244a89351a5429784c0dda73d36762a5c0be74bbc72e5b0");
        let value =
            parse_scalar("0x22853de9cbf26d30c244a89351a5429784c0dda73d36762a5c0be74bbc72e5b0");
        let proof = Proof::<Scalar, Scalar, 3, 0>::from_compressed(0.into(), value, root_hash, &[])
            .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_1_0() {
        let root_hash =
            parse_scalar("0x69eac82309f9d539b3387c6f2b0b4556d28c0ce50b21986eab98216b12b12bdd");
        let value =
            parse_scalar("0x71f09f7f8c126f0fad998f73ef79a489f91b09ed820681a5dc8a88882d912d6b");
        let sister1 =
            parse_scalar("0x684d795929e259d083c80e20f7da73c18d237c3e948143bdf3321e0a0186fdfd");
        let sister2 =
            parse_scalar("0x2a63c64dec4a49d17d37f8d44d4d1bc2086668eb4fe6baa8550bd60cdfc18d54");
        let proof = Proof::<Scalar, Scalar, 3, 1>::from_compressed(
            0.into(),
            value,
            root_hash,
            &[[sister1, sister2]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_1_1() {
        let root_hash =
            parse_scalar("0x13c63ea4758034403aa8a8a31fd29c526ebebe779a2770488b7e3dddb51d632f");
        let value =
            parse_scalar("0x71f09f7f8c126f0fad998f73ef79a489f91b09ed820681a5dc8a88882d912d6b");
        let sister1 =
            parse_scalar("0x684d795929e259d083c80e20f7da73c18d237c3e948143bdf3321e0a0186fdfd");
        let sister2 =
            parse_scalar("0x2a63c64dec4a49d17d37f8d44d4d1bc2086668eb4fe6baa8550bd60cdfc18d54");
        let proof = Proof::<Scalar, Scalar, 3, 1>::from_compressed(
            1.into(),
            value,
            root_hash,
            &[[sister1, sister2]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_1_2() {
        let root_hash =
            parse_scalar("0x52d0f9cb9411af2424fadcf731aab2cf1607f0353f64bd1e9999091563498dd8");
        let value =
            parse_scalar("0x71f09f7f8c126f0fad998f73ef79a489f91b09ed820681a5dc8a88882d912d6b");
        let sister1 =
            parse_scalar("0x684d795929e259d083c80e20f7da73c18d237c3e948143bdf3321e0a0186fdfd");
        let sister2 =
            parse_scalar("0x2a63c64dec4a49d17d37f8d44d4d1bc2086668eb4fe6baa8550bd60cdfc18d54");
        let proof = Proof::<Scalar, Scalar, 3, 1>::from_compressed(
            2.into(),
            value,
            root_hash,
            &[[sister1, sister2]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_00() {
        let root_hash =
            parse_scalar("0x13d5ae0532ea3d3cb580d018d5b34032ae2f5ae0fcb65a5be52fa1571b850bf1");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            0.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_01() {
        let root_hash =
            parse_scalar("0x48a95b164672c05499318ccf8460866dcaf93239d9c2b59a17d61d2ce8a7961f");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            1.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_02() {
        let root_hash =
            parse_scalar("0x5f6e149be84c53ce56a462dd1e68bff5207427934c1958a0b934a4881299d61c");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            2.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_10() {
        let root_hash =
            parse_scalar("0x576a8cde458637a1cbb2c84d2ab63ac2ab35da71748652d7fbf2e9ab501fc73c");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            3.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_11() {
        let root_hash =
            parse_scalar("0x5ab5ab2b98fde21a9e580e336d27139060fce4c22af332331877006dadc1ff02");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            4.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_12() {
        let root_hash =
            parse_scalar("0x21324a4adf0d81c33c962194a46a8e96a91d779756e7410f6b6175b60c92349e");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            5.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_20() {
        let root_hash =
            parse_scalar("0x4f648fd87500ce5dd1d952f7cc59cb22051d055247addc4dc8c5895297a1b9ad");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            6.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_21() {
        let root_hash =
            parse_scalar("0x416afa3d0ce5b1e6ee5b87878a191bffda083f79072cc5bf812e407d741e5449");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            7.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_proof_3_2_22() {
        let root_hash =
            parse_scalar("0x593492c2a4c92e9088809dcd7604b1080343f61cd68b9c85fe6bd76bd1403f80");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            8.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.verify().is_ok());
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    struct TestValue {
        scalar: Scalar,
    }

    impl AsScalar for TestValue {
        fn as_scalar(&self) -> Scalar {
            self.scalar
        }
    }

    #[test]
    fn test_map_value() {
        let root_hash =
            parse_scalar("0x593492c2a4c92e9088809dcd7604b1080343f61cd68b9c85fe6bd76bd1403f80");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            8.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        let new_value = TestValue { scalar: value };
        let mapped = proof.map(new_value).unwrap();
        assert_eq!(*mapped.value(), new_value);
        assert!(mapped.verify().is_ok());
    }

    #[test]
    fn test_wrong_map_value() {
        let root_hash =
            parse_scalar("0x1816238696218e1fd51ec1377520694e1105c7af2bfe5d5a544f1a8fe0dfcd43");
        let value =
            parse_scalar("0x6a415c14a0a3e7984de056690c4f9c50d8aebb94c864dd688f361affc0177282");
        let sister1 =
            parse_scalar("0x50189e263ddcf54e4065c3178f46a4f9192b84822d769bf2da521fe3b091c29a");
        let sister2 =
            parse_scalar("0x3a1a2de3e638f28725fa2f81a526dd89d5cc143fa0be536cb4582289628942d1");
        let sister3 =
            parse_scalar("0x4d200e35fa5e95500d9b2355b78f8d44d0a910457d7e77d1a7194cc5e31b1b4d");
        let sister4 =
            parse_scalar("0x20f32112966a677427e5568ed79b599b0377c2e2ea89c6871b5bd6e4442a98dd");
        let proof = Proof::<Scalar, Scalar, 3, 2>::from_compressed(
            8.into(),
            value,
            root_hash,
            &[[sister1, sister2], [sister3, sister4]],
        )
        .unwrap();
        assert!(proof.map(TestValue { scalar: root_hash }).is_err());
    }
}
