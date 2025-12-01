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
            parse_scalar("0x15f1bd031385cb1aecad2c77f4da3a4243b00ea69e016264700b3234af534bd2");
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
            parse_scalar("0x15f1bd031385cb1aecad2c77f4da3a4243b00ea69e016264700b3234af534bd2");
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
            parse_scalar("0x58a7191f3e943e822142d1c20435045b738c6ce2c5eecc03c409c7e085f7595b");
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
            parse_scalar("0x4c6f7dc07674733cb1e1242761594ee7e6e96c7db66195621afb617f6a37abc6");
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
            parse_scalar("0x6a0587a5a714f506272f21ce74465930af42ebdf81a7ec48319446ffae936b2");
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
            parse_scalar("0x672524f01ed4038683f777005c7a456689183efff952da223ebcedf653b12971");
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
            parse_scalar("0x711210540a1ee4d2afe3d57e884ffd9efade03690be76058806ff4a199a82530");
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
            parse_scalar("0x1d6b13c4a1644ff68c31ca058eb75a5171b29e6241b0a2d033e4dab2ea03e8d9");
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
            parse_scalar("0x16a1218be3569c92e46bdc0486fbdf14501141714b09ed25fcb5403365a859f9");
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
            parse_scalar("0x69a82ac0fd061a27689fbfe725bee102d62ad04c20700dea2bda401c8a764791");
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
            parse_scalar("0xd73a9d800ba75ce067298ba5b0beb83af930d31700b0916ebae43742da91150");
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
            parse_scalar("0x4bfd0db6ae9ee3888f3e806d82f6433cec5c86f493b822f1bc26351a30c71a10");
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
            parse_scalar("0x27702d3591498eb488feefe493c2e447cf9d5e4d248db045c3f6de92698cf946");
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
            parse_scalar("0x1dbf358b5b87f5f2dc2e95d9dcac17b0a4f2111db6fda0709b96b67680801384");
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
            parse_scalar("0x22a8ace0acd6c07c726fb9ab1f97d6da64391f5b2b0dfa50158fd8f131d9207a");
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
            parse_scalar("0x3941042cc3b7fb4979b73e51080c48a4c671b0a7cc28bf0a78064a7e3d19a137");
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
            parse_scalar("0x2e9433225babc7d9ad8273fd6aa65d41494e7be91bf5ccba2818aa4313e2f0d");
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
        assert!(proof.verify().is_ok());
    }
}
