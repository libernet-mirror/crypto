use crate::fri::{Hash, Poseidon2Hash, Sha2Hash};
use crate::plonk::{self, Chip};
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::Field;
use starkom_bluesky::Scalar;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

/// Domain separator tag used in our HMAC / zkMAC scheme.
static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/hmac"));

/// Returns the public key corresponding to a private key in our zkMAC scheme.
///
/// The "public key" is calculated as the hash of the private key with a domain separator tag.
pub fn public_key(private_key: Scalar) -> Scalar {
    poseidon::hash_t3(&[*DST, private_key])
}

/// Proves the HMAC of a message.
///
/// NOTE: the generic parameter `N` is the length of the message and the generic parameter `M` MUST
/// be equal to `N+3`. `M` is used as the size of the internal HMAC hash and is equal to the size of
/// the signed message plus 3 scalars for: the DST, the private key, and the message length.
#[derive(Debug, Default, Clone)]
struct SignatureChip<const N: usize, const M: usize> {
    private_key: Scalar,
    public_key_hasher: poseidon::Chip<3, 2>,
    message_hasher: poseidon::Chip<3, M>,
}

impl<const N: usize, const M: usize> SignatureChip<N, M> {
    pub fn new(private_key: Scalar) -> Self {
        Self {
            private_key,
            public_key_hasher: poseidon::Chip::default(),
            message_hasher: poseidon::Chip::default(),
        }
    }
}

impl<const N: usize, const M: usize> plonk::Chip<N, 2> for SignatureChip<N, M> {
    fn build(
        &self,
        builder: &mut plonk::CircuitBuilder,
        inputs: [Option<plonk::Wire>; N],
    ) -> Result<[Option<plonk::Wire>; 2]> {
        let dst = builder.add_const_gate(*DST);
        let private_key = plonk::Wire::Out(builder.add_nop_gate(None, None, None));
        let length = builder.add_const_gate(Scalar::from_const(N as u64));
        let public_key = self
            .public_key_hasher
            .build(builder, [dst.into(), private_key.into()])?[0];
        let signature = self.message_hasher.build(
            builder,
            [dst.into(), private_key.into(), length.into()]
                .into_iter()
                .chain(inputs.into_iter())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )?[0];
        Ok([public_key, signature])
    }

    fn witness(
        &self,
        witness: &mut plonk::Witness,
        inputs: [plonk::WireOrUnconstrained; N],
    ) -> Result<[plonk::WireOrUnconstrained; 2]> {
        let dst = witness.assert_constant(*DST);
        let private_key = plonk::Wire::Out(witness.nop(
            Scalar::ZERO.into(),
            Scalar::ZERO.into(),
            self.private_key.into(),
        ));
        let length = witness.assert_constant(Scalar::from_const(N as u64));
        let public_key = self
            .public_key_hasher
            .witness(witness, [dst.into(), private_key.into()])?[0];
        let signature = self.message_hasher.witness(
            witness,
            [dst.into(), private_key.into(), length.into()]
                .into_iter()
                .chain(inputs.into_iter())
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        )?[0];
        Ok([public_key, signature])
    }
}

/// A PLONK circuit to sign messages with a private key using zkMAC.
#[derive(Debug, Clone)]
struct SignerCircuit<const N: usize, const M: usize> {
    chip: SignatureChip<N, M>,
    inner: plonk::Circuit,
    public_key_wire: plonk::Wire,
    message_wires: [plonk::Wire; N],
    signature_wire: plonk::Wire,
}

impl<const N: usize, const M: usize> SignerCircuit<N, M> {
    fn make(private_key: Option<Scalar>) -> Self {
        let mut builder = plonk::CircuitBuilder::default();
        let message: [Option<plonk::Wire>; N] =
            std::array::from_fn(|_| Some(plonk::Wire::Out(builder.add_nop_gate(None, None, None))));
        let chip = match private_key {
            Some(private_key) => SignatureChip::<N, M>::new(private_key),
            None => SignatureChip::<N, M>::default(),
        };
        let [public_key, signature] = chip.build(&mut builder, message).unwrap();
        builder.declare_public_gates(
            message
                .into_iter()
                .chain([public_key, signature])
                .map(|wire| wire.unwrap().gate()),
        );
        Self {
            chip,
            inner: builder.build(),
            public_key_wire: public_key.unwrap(),
            message_wires: message.map(|wire| wire.unwrap()),
            signature_wire: signature.unwrap(),
        }
    }

    fn new(private_key: Scalar) -> Self {
        Self::make(Some(private_key))
    }

    fn to_verifier<H: Hash>(self, blowup_log2: usize) -> VerifierCircuit<H, N> {
        VerifierCircuit {
            inner: self.inner.to_compressed::<H>(blowup_log2),
            public_key_wire: self.public_key_wire,
            message_wires: self.message_wires,
            signature_wire: self.signature_wire,
            _data: Default::default(),
        }
    }
}

impl<const N: usize, const M: usize> Default for SignerCircuit<N, M> {
    fn default() -> Self {
        Self::make(None)
    }
}

/// Dyn trait for a generic signer circuit.
///
/// This trait abstracts the generic parameters `N` and `M` away so that signers for all sizes can
/// be cached in the same data structure.
pub trait AbstractSignerCircuit<H: Hash>: Debug + Send + Sync {
    /// Signs the provided message and returns the signature scalar and the zkSTARK proof.
    fn witness(&self, message: &[Scalar], blowup_log2: usize) -> (Scalar, plonk::Proof<H>);
}

impl<H: Hash, const N: usize, const M: usize> AbstractSignerCircuit<H> for SignerCircuit<N, M> {
    fn witness(&self, message: &[Scalar], blowup_log2: usize) -> (Scalar, plonk::Proof<H>) {
        let mut witness = self.inner.make_witness();
        let message = std::array::from_fn(|i| {
            plonk::Wire::Out(witness.nop(
                Scalar::ZERO.into(),
                Scalar::ZERO.into(),
                message[i].into(),
            ))
            .into()
        });
        self.chip.witness(&mut witness, message).unwrap();
        let signature = witness.get(self.signature_wire);
        let proof = self.inner.prove::<H>(witness, blowup_log2).unwrap();
        (signature, proof)
    }
}

#[derive(Debug, Clone)]
struct VerifierCircuit<H: Hash, const N: usize> {
    inner: plonk::CompressedCircuit,
    public_key_wire: plonk::Wire,
    message_wires: [plonk::Wire; N],
    signature_wire: plonk::Wire,
    _data: PhantomData<H>,
}

/// Dyn trait for a generic verifier circuit.
///
/// This trait abstracts the generic parameter `N` away so that verifiers for all sizes can be
/// cached in the same data structure.
pub trait AbstractVerifierCircuit<H: Hash>: Debug + Send + Sync {
    fn verify(
        &self,
        public_key: Scalar,
        message: &[Scalar],
        signature: Scalar,
        proof: &plonk::Proof<H>,
    ) -> Result<()>;
}

impl<H: Hash + Debug + Send + Sync, const N: usize> AbstractVerifierCircuit<H>
    for VerifierCircuit<H, N>
{
    fn verify(
        &self,
        public_key: Scalar,
        message: &[Scalar],
        signature: Scalar,
        proof: &plonk::Proof<H>,
    ) -> Result<()> {
        let openings = self.inner.verify(proof)?;
        if openings[&self.public_key_wire] != public_key {
            return Err(anyhow!(
                "public key mismatch (got {}, want {})",
                openings[&self.public_key_wire],
                public_key
            ));
        }
        if self
            .message_wires
            .iter()
            .enumerate()
            .any(|(i, value)| openings[value] != message[i])
        {
            return Err(anyhow!("signed message mismatch"));
        }
        if openings[&self.signature_wire] != signature {
            return Err(anyhow!(
                "signature mismatch (got {}, want {})",
                openings[&self.signature_wire],
                signature
            ));
        }
        Ok(())
    }
}

/// Caches signer circuits.
#[derive(Debug)]
struct SignerCache<H: Hash> {
    /// The first component of the key is the private key used to sign; the second one is the size
    /// of the signed input, `N`.
    circuits: Mutex<BTreeMap<(Scalar, usize), Arc<OnceLock<Arc<dyn AbstractSignerCircuit<H>>>>>>,
    _data: PhantomData<H>,
}

impl<H: Hash> SignerCache<H> {
    fn make<const N: usize, const M: usize>(
        private_key: Scalar,
    ) -> Arc<dyn AbstractSignerCircuit<H>> {
        Arc::new(SignerCircuit::<N, M>::new(private_key))
    }

    fn make_monomorphic(private_key: Scalar, n: usize) -> Arc<dyn AbstractSignerCircuit<H>> {
        match n {
            1 => Self::make::<1, 4>(private_key),
            2 => Self::make::<2, 5>(private_key),
            3 => Self::make::<3, 6>(private_key),
            4 => Self::make::<4, 7>(private_key),
            5 => Self::make::<5, 8>(private_key),
            6 => Self::make::<6, 9>(private_key),
            7 => Self::make::<7, 10>(private_key),
            8 => Self::make::<8, 11>(private_key),
            9 => Self::make::<9, 12>(private_key),
            10 => Self::make::<10, 13>(private_key),
            11 => Self::make::<11, 14>(private_key),
            12 => Self::make::<12, 15>(private_key),
            13 => Self::make::<13, 16>(private_key),
            14 => Self::make::<14, 17>(private_key),
            15 => Self::make::<15, 18>(private_key),
            16 => Self::make::<16, 19>(private_key),
            17 => Self::make::<17, 20>(private_key),
            18 => Self::make::<18, 21>(private_key),
            19 => Self::make::<19, 22>(private_key),
            20 => Self::make::<20, 23>(private_key),
            _ => unimplemented!(),
        }
    }

    fn get_or_make(
        &self,
        private_key: Scalar,
        n: usize,
    ) -> Arc<OnceLock<Arc<dyn AbstractSignerCircuit<H>>>> {
        let key = (private_key, n);
        let mut circuits = self.circuits.lock().unwrap();
        if !circuits.contains_key(&key) {
            circuits.insert(key, Arc::default());
        }
        circuits.get(&key).unwrap().clone()
    }
}

impl SignerCache<Sha2Hash> {
    fn get(private_key: Scalar, n: usize) -> Arc<dyn AbstractSignerCircuit<Sha2Hash>> {
        static CACHE: LazyLock<SignerCache<Sha2Hash>> = LazyLock::new(|| SignerCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(private_key, n);
        once_lock
            .get_or_init(|| Self::make_monomorphic(private_key, n))
            .clone()
    }
}

impl SignerCache<Poseidon2Hash> {
    fn get(private_key: Scalar, n: usize) -> Arc<dyn AbstractSignerCircuit<Poseidon2Hash>> {
        static CACHE: LazyLock<SignerCache<Poseidon2Hash>> = LazyLock::new(|| SignerCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(private_key, n);
        once_lock
            .get_or_init(|| Self::make_monomorphic(private_key, n))
            .clone()
    }
}

/// Caches verifier circuits.
#[derive(Debug)]
struct VerifierCache<H: Hash + 'static> {
    /// The first component of the key is the size of the signed input, `N`; the second one is the
    /// log2 of the blowup factor for the circuit.
    circuits: Mutex<BTreeMap<(usize, usize), Arc<OnceLock<Arc<dyn AbstractVerifierCircuit<H>>>>>>,
    _data: PhantomData<H>,
}

impl<H: Hash + Debug + Send + Sync> VerifierCache<H> {
    fn make<const N: usize, const M: usize>(
        blowup_log2: usize,
    ) -> Arc<dyn AbstractVerifierCircuit<H>> {
        Arc::new(SignerCircuit::<N, M>::default().to_verifier(blowup_log2))
    }

    fn make_monomorphic(n: usize, blowup_log2: usize) -> Arc<dyn AbstractVerifierCircuit<H>> {
        match n {
            1 => Self::make::<1, 4>(blowup_log2),
            2 => Self::make::<2, 5>(blowup_log2),
            3 => Self::make::<3, 6>(blowup_log2),
            4 => Self::make::<4, 7>(blowup_log2),
            5 => Self::make::<5, 8>(blowup_log2),
            6 => Self::make::<6, 9>(blowup_log2),
            7 => Self::make::<7, 10>(blowup_log2),
            8 => Self::make::<8, 11>(blowup_log2),
            9 => Self::make::<9, 12>(blowup_log2),
            10 => Self::make::<10, 13>(blowup_log2),
            11 => Self::make::<11, 14>(blowup_log2),
            12 => Self::make::<12, 15>(blowup_log2),
            13 => Self::make::<13, 16>(blowup_log2),
            14 => Self::make::<14, 17>(blowup_log2),
            15 => Self::make::<15, 18>(blowup_log2),
            16 => Self::make::<16, 19>(blowup_log2),
            17 => Self::make::<17, 20>(blowup_log2),
            18 => Self::make::<18, 21>(blowup_log2),
            19 => Self::make::<19, 22>(blowup_log2),
            20 => Self::make::<20, 23>(blowup_log2),
            _ => unimplemented!(),
        }
    }

    fn get_or_make(
        &self,
        n: usize,
        blowup_log2: usize,
    ) -> Arc<OnceLock<Arc<dyn AbstractVerifierCircuit<H>>>> {
        let key = (n, blowup_log2);
        let mut circuits = self.circuits.lock().unwrap();
        if !circuits.contains_key(&key) {
            circuits.insert(key, Arc::default());
        }
        circuits.get(&key).unwrap().clone()
    }
}

impl VerifierCache<Sha2Hash> {
    fn get(n: usize, blowup_log2: usize) -> Arc<dyn AbstractVerifierCircuit<Sha2Hash>> {
        static CACHE: LazyLock<VerifierCache<Sha2Hash>> = LazyLock::new(|| VerifierCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(n, blowup_log2);
        once_lock
            .get_or_init(|| Self::make_monomorphic(n, blowup_log2))
            .clone()
    }
}

impl VerifierCache<Poseidon2Hash> {
    fn get(n: usize, blowup_log2: usize) -> Arc<dyn AbstractVerifierCircuit<Poseidon2Hash>> {
        static CACHE: LazyLock<VerifierCache<Poseidon2Hash>> = LazyLock::new(|| VerifierCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(n, blowup_log2);
        once_lock
            .get_or_init(|| Self::make_monomorphic(n, blowup_log2))
            .clone()
    }
}

/// Utility trait to fetch a circuit from the cache for all known hash backends.
///
/// For internal use only. It's declared as public because it needs to surface in the signature of
/// `sign`.
pub trait CachedSigner: Hash {
    fn get_signer_circuit(private_key: Scalar, n: usize) -> Arc<dyn AbstractSignerCircuit<Self>>;
}

impl CachedSigner for Sha2Hash {
    fn get_signer_circuit(private_key: Scalar, n: usize) -> Arc<dyn AbstractSignerCircuit<Self>> {
        SignerCache::<Sha2Hash>::get(private_key, n)
    }
}

impl CachedSigner for Poseidon2Hash {
    fn get_signer_circuit(private_key: Scalar, n: usize) -> Arc<dyn AbstractSignerCircuit<Self>> {
        SignerCache::<Poseidon2Hash>::get(private_key, n)
    }
}

/// Signs a message with the given private key using the zkMAC scheme, which consists of making a
/// zkSTARK proof of an HMAC (hash-based message authentication code).
///
/// The private key remains a private input of the zkSTARK circuit. Other parties can verify the
/// zkSTARK proof, and therefore the signature, without ever seeing the private key.
///
/// The returned pair contains the signature scalar and the zkSTARK proof.
pub fn sign<H: Hash + CachedSigner, const N: usize>(
    private_key: Scalar,
    message: &[Scalar; N],
    blowup_log2: usize,
) -> (Scalar, plonk::Proof<H>) {
    let circuit = H::get_signer_circuit(private_key, N);
    circuit.witness(message, blowup_log2)
}

/// Utility trait to fetch a circuit from the cache for all known hash backends.
///
/// For internal use only. It's declared as public because it needs to surface in the signature of
/// `verify`.
pub trait CachedVerifier: Hash {
    fn get_verifier_circuit(n: usize, blowup_log2: usize)
    -> Arc<dyn AbstractVerifierCircuit<Self>>;
}

impl CachedVerifier for Sha2Hash {
    fn get_verifier_circuit(
        n: usize,
        blowup_log2: usize,
    ) -> Arc<dyn AbstractVerifierCircuit<Self>> {
        VerifierCache::<Sha2Hash>::get(n, blowup_log2)
    }
}

impl CachedVerifier for Poseidon2Hash {
    fn get_verifier_circuit(
        n: usize,
        blowup_log2: usize,
    ) -> Arc<dyn AbstractVerifierCircuit<Self>> {
        VerifierCache::<Poseidon2Hash>::get(n, blowup_log2)
    }
}

/// Verifies a message signed with our zkMAC scheme.
///
/// The `public_key` is the same value returned by the `public_key()` function above for the private
/// key used to sign the message, and is one of the public inputs of the circuit. This function
/// verifies the zkSTARK proof and checks that the public key and message match the public inputs.
pub fn verify<H: Hash + CachedVerifier, const N: usize>(
    public_key: Scalar,
    message: &[Scalar; N],
    signature: Scalar,
    proof: &plonk::Proof<H>,
) -> Result<()> {
    let circuit = H::get_verifier_circuit(N, proof.blowup_log2());
    circuit.verify(public_key, message, signature, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::parse_scalar;

    const BLOWUP_LOG2: usize = 1;

    #[test]
    fn test_public_key() {
        assert_eq!(
            public_key(parse_scalar(
                "0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680"
            )),
            parse_scalar("0x4e734f913c0994020c5ae8d18ccbe627d3b60cb9e6843abfbc621eb91c6c3948")
        );
        assert_eq!(
            public_key(parse_scalar(
                "0x75b9be52955cd0933248b6324139bb988e9442fcf657c391b227de67f7d84561"
            )),
            parse_scalar("0x69b68d92098d4da91b486269cf648e7017ea62b330527aeed231cb77a789b492")
        );
    }

    #[test]
    fn test_signature_one_scalar_sha2() {
        let private_key =
            parse_scalar("0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680");
        let (signature, proof) = sign::<Sha2Hash, 1>(private_key, &[42.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x12586bd0764c32cba105a66535f812a04af334b8c85a16cb6d58884541a89ab5")
        );
        assert!(
            verify::<Sha2Hash, 1>(public_key(private_key), &[42.into()], signature, &proof).is_ok()
        );
    }

    #[test]
    fn test_signature_one_scalar_poseidon2() {
        let private_key =
            parse_scalar("0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680");
        let (signature, proof) = sign::<Poseidon2Hash, 1>(private_key, &[42.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x12586bd0764c32cba105a66535f812a04af334b8c85a16cb6d58884541a89ab5")
        );
        assert!(
            verify::<Poseidon2Hash, 1>(public_key(private_key), &[42.into()], signature, &proof)
                .is_ok()
        );
    }

    #[test]
    fn test_signature_one_scalar_different_key_sha2() {
        let private_key =
            parse_scalar("0x75b9be52955cd0933248b6324139bb988e9442fcf657c391b227de67f7d84561");
        let (signature, proof) = sign::<Sha2Hash, 1>(private_key, &[42.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x739316cdd2ab2e0b12371e50771cccbefdc2d96fb1f9e44ea688f7db8fef724b")
        );
        assert!(
            verify::<Sha2Hash, 1>(public_key(private_key), &[42.into()], signature, &proof).is_ok()
        );
    }

    #[test]
    fn test_signature_one_scalar_different_key_poseidon2() {
        let private_key =
            parse_scalar("0x75b9be52955cd0933248b6324139bb988e9442fcf657c391b227de67f7d84561");
        let (signature, proof) = sign::<Poseidon2Hash, 1>(private_key, &[42.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x739316cdd2ab2e0b12371e50771cccbefdc2d96fb1f9e44ea688f7db8fef724b")
        );
        assert!(
            verify::<Poseidon2Hash, 1>(public_key(private_key), &[42.into()], signature, &proof)
                .is_ok()
        );
    }

    #[test]
    fn test_signature_another_scalar_sha2() {
        let private_key =
            parse_scalar("0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680");
        let (signature, proof) = sign::<Sha2Hash, 1>(private_key, &[123.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x2f5b3bbe562312563a88568067fa93c9946a00790b0e65ebd5e170904ba66205")
        );
        assert!(
            verify::<Sha2Hash, 1>(public_key(private_key), &[123.into()], signature, &proof)
                .is_ok()
        );
    }

    #[test]
    fn test_signature_another_scalar_poseidon2() {
        let private_key =
            parse_scalar("0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680");
        let (signature, proof) = sign::<Poseidon2Hash, 1>(private_key, &[123.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x2f5b3bbe562312563a88568067fa93c9946a00790b0e65ebd5e170904ba66205")
        );
        assert!(
            verify::<Poseidon2Hash, 1>(public_key(private_key), &[123.into()], signature, &proof)
                .is_ok()
        );
    }

    #[test]
    fn test_signature_two_scalars_sha2() {
        let private_key =
            parse_scalar("0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680");
        let (signature, proof) =
            sign::<Sha2Hash, 2>(private_key, &[123.into(), 456.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x23ed26eabb33af669f2f64ad460783a0ea1c0259003294ff5839827c62617161")
        );
        assert!(
            verify::<Sha2Hash, 2>(
                public_key(private_key),
                &[123.into(), 456.into()],
                signature,
                &proof
            )
            .is_ok()
        );
    }

    #[test]
    fn test_signature_two_scalars_poseidon2() {
        let private_key =
            parse_scalar("0x57833b8d7c2e4b4fa73b9b701496c153628a211d802f02e3f948437627123680");
        let (signature, proof) =
            sign::<Poseidon2Hash, 2>(private_key, &[123.into(), 456.into()], BLOWUP_LOG2);
        assert_eq!(
            signature,
            parse_scalar("0x23ed26eabb33af669f2f64ad460783a0ea1c0259003294ff5839827c62617161")
        );
        assert!(
            verify::<Poseidon2Hash, 2>(
                public_key(private_key),
                &[123.into(), 456.into()],
                signature,
                &proof
            )
            .is_ok()
        );
    }
}
