use crate::bluesky::Scalar;
use crate::fri::{Hash, Poseidon2Hash, Sha2Hash};
use crate::plonk::{self, Chip};
use crate::poseidon;
use crate::utils;
use anyhow::Result;
use ff::Field;
use std::collections::BTreeMap;
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
#[derive(Debug, Default)]
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

/// Caches signer circuits.
#[derive(Debug)]
struct SignerCache<H: Hash> {
    /// The first component of the key is the private key used to sign; the second one is the size
    /// of the signed input, `N`.
    circuits: Mutex<BTreeMap<(Scalar, usize), Arc<OnceLock<plonk::Circuit>>>>,
    _data: PhantomData<H>,
}

impl<H: Hash> SignerCache<H> {
    fn make<const N: usize, const M: usize>(private_key: Scalar) -> plonk::Circuit {
        let mut builder = plonk::CircuitBuilder::default();
        let message: [Option<plonk::Wire>; N] =
            std::array::from_fn(|_| Some(plonk::Wire::Out(builder.add_nop_gate(None, None, None))));
        let chip = SignatureChip::<N, M>::new(private_key);
        let [public_key, signature] = chip.build(&mut builder, message).unwrap();
        builder.declare_public_gates(
            message
                .into_iter()
                .chain([public_key, signature])
                .map(|wire| wire.unwrap().gate()),
        );
        builder.build()
    }

    fn make_monomorphic(private_key: Scalar, n: usize) -> plonk::Circuit {
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

    fn get_or_make(&self, private_key: Scalar, n: usize) -> Arc<OnceLock<plonk::Circuit>> {
        let key = (private_key, n);
        let mut circuits = self.circuits.lock().unwrap();
        if !circuits.contains_key(&key) {
            circuits.insert(key, Arc::default());
        }
        circuits.get(&key).unwrap().clone()
    }
}

impl SignerCache<Sha2Hash> {
    fn get(private_key: Scalar, n: usize) -> &'static plonk::Circuit {
        static CACHE: LazyLock<SignerCache<Sha2Hash>> = LazyLock::new(|| SignerCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(private_key, n);
        let once_lock_ref: &'static OnceLock<plonk::Circuit> = unsafe {
            // SAFETY: The Arc is permanently stored in CACHE (a static), so the OnceLock allocation
            // lives for the duration of the program.
            &*Arc::as_ptr(&once_lock)
        };
        once_lock_ref.get_or_init(|| Self::make_monomorphic(private_key, n))
    }
}

impl SignerCache<Poseidon2Hash> {
    fn get(private_key: Scalar, n: usize) -> &'static plonk::Circuit {
        static CACHE: LazyLock<SignerCache<Poseidon2Hash>> = LazyLock::new(|| SignerCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(private_key, n);
        let once_lock_ref: &'static OnceLock<plonk::Circuit> = unsafe {
            // SAFETY: The Arc is permanently stored in CACHE (a static), so the OnceLock allocation
            // lives for the duration of the program.
            &*Arc::as_ptr(&once_lock)
        };
        once_lock_ref.get_or_init(|| Self::make_monomorphic(private_key, n))
    }
}

/// Caches verifier circuits.
#[derive(Debug)]
struct VerifierCache<H: Hash> {
    /// The first component of the key is the size of the signed input, `N`; the second one is the
    /// log2 of the blowup factor for the circuit.
    circuits: Mutex<BTreeMap<(usize, usize), Arc<OnceLock<plonk::CompressedCircuit>>>>,
    _data: PhantomData<H>,
}

impl<H: Hash> VerifierCache<H> {
    fn make<const N: usize, const M: usize>(blowup_log2: usize) -> plonk::CompressedCircuit {
        let mut builder = plonk::CircuitBuilder::default();
        let message: [Option<plonk::Wire>; N] =
            std::array::from_fn(|_| Some(plonk::Wire::Out(builder.add_nop_gate(None, None, None))));
        let chip = SignatureChip::<N, M>::default();
        let [public_key, signature] = chip.build(&mut builder, message).unwrap();
        builder.declare_public_gates(
            message
                .into_iter()
                .chain([public_key, signature])
                .map(|wire| wire.unwrap().gate()),
        );
        builder.build().to_compressed::<H>(blowup_log2)
    }

    fn make_monomorphic(n: usize, blowup_log2: usize) -> plonk::CompressedCircuit {
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

    fn get_or_make(&self, n: usize, blowup_log2: usize) -> Arc<OnceLock<plonk::CompressedCircuit>> {
        let key = (n, blowup_log2);
        let mut circuits = self.circuits.lock().unwrap();
        if !circuits.contains_key(&key) {
            circuits.insert(key, Arc::default());
        }
        circuits.get(&key).unwrap().clone()
    }
}

impl VerifierCache<Sha2Hash> {
    fn get(n: usize, blowup_log2: usize) -> &'static plonk::CompressedCircuit {
        static CACHE: LazyLock<VerifierCache<Sha2Hash>> = LazyLock::new(|| VerifierCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(n, blowup_log2);
        let once_lock_ref: &'static OnceLock<plonk::CompressedCircuit> = unsafe {
            // SAFETY: The Arc is permanently stored in CACHE (a static), so the OnceLock allocation
            // lives for the duration of the program.
            &*Arc::as_ptr(&once_lock)
        };
        once_lock_ref.get_or_init(|| Self::make_monomorphic(n, blowup_log2))
    }
}

impl VerifierCache<Poseidon2Hash> {
    fn get(n: usize, blowup_log2: usize) -> &'static plonk::CompressedCircuit {
        static CACHE: LazyLock<VerifierCache<Poseidon2Hash>> = LazyLock::new(|| VerifierCache {
            circuits: Mutex::default(),
            _data: Default::default(),
        });
        let once_lock = CACHE.get_or_make(n, blowup_log2);
        let once_lock_ref: &'static OnceLock<plonk::CompressedCircuit> = unsafe {
            // SAFETY: The Arc is permanently stored in CACHE (a static), so the OnceLock allocation
            // lives for the duration of the program.
            &*Arc::as_ptr(&once_lock)
        };
        once_lock_ref.get_or_init(|| Self::make_monomorphic(n, blowup_log2))
    }
}

/// Utility trait to fetch a circuit from the cache for all known hash backends.
///
/// For internal use only. It's declared as public because it needs to surface in the signature of
/// `sign`.
pub trait CachedSigner: Hash {
    fn get_signer_circuit(private_key: Scalar, n: usize) -> &'static plonk::Circuit;
}

impl CachedSigner for Sha2Hash {
    fn get_signer_circuit(private_key: Scalar, n: usize) -> &'static plonk::Circuit {
        SignerCache::<Sha2Hash>::get(private_key, n)
    }
}

impl CachedSigner for Poseidon2Hash {
    fn get_signer_circuit(private_key: Scalar, n: usize) -> &'static plonk::Circuit {
        SignerCache::<Poseidon2Hash>::get(private_key, n)
    }
}

pub fn sign<H: Hash + CachedSigner, const N: usize, const M: usize>(
    private_key: Scalar,
    message: &[Scalar; N],
    blowup_log2: usize,
) -> plonk::Proof<H> {
    let circuit = H::get_signer_circuit(private_key, N);
    let mut witness = circuit.make_witness();
    // TODO
    todo!()
}

/// Utility trait to fetch a circuit from the cache for all known hash backends.
///
/// For internal use only. It's declared as public because it needs to surface in the signature of
/// `verify`.
pub trait CachedVerifier: Hash {
    fn get_verifier_circuit(n: usize, blowup_log2: usize) -> &'static plonk::CompressedCircuit;
}

impl CachedVerifier for Sha2Hash {
    fn get_verifier_circuit(n: usize, blowup_log2: usize) -> &'static plonk::CompressedCircuit {
        VerifierCache::<Sha2Hash>::get(n, blowup_log2)
    }
}

impl CachedVerifier for Poseidon2Hash {
    fn get_verifier_circuit(n: usize, blowup_log2: usize) -> &'static plonk::CompressedCircuit {
        VerifierCache::<Poseidon2Hash>::get(n, blowup_log2)
    }
}

pub fn verify<H: Hash + CachedVerifier, const N: usize>(
    public_key: Scalar,
    message: &[Scalar; N],
    signature: &plonk::Proof<H>,
) -> Result<()> {
    let circuit = H::get_verifier_circuit(N, signature.blowup_log2());
    let openings = circuit.verify(signature)?;
    // TODO
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::parse_scalar;

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

    // TODO
}
