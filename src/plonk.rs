use crate::kzg;
use crate::poly::Polynomial;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G1Projective, Scalar};
use ff::Field;
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::sync::LazyLock;

fn witness_hash_dst() -> Scalar {
    static TAG: LazyLock<Scalar> =
        LazyLock::new(|| utils::hash_to_scalar(b"libernet/plonk/witness_hash"));
    *TAG
}

fn beta_challenge_dst() -> Scalar {
    static TAG: LazyLock<Scalar> =
        LazyLock::new(|| utils::hash_to_scalar(b"libernet/plonk/beta_challenge"));
    *TAG
}

fn gamma_challenge_dst() -> Scalar {
    static TAG: LazyLock<Scalar> =
        LazyLock::new(|| utils::hash_to_scalar(b"libernet/plonk/gamma_challenge"));
    *TAG
}

fn k1() -> Scalar {
    71.into()
}

fn k2() -> Scalar {
    104.into()
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct GateConstraint {
    ql: Scalar,
    qr: Scalar,
    qo: Scalar,
    qm: Scalar,
    qc: Scalar,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Wire {
    LeftIn(u32),
    RightIn(u32),
    Out(u32),
}

impl Wire {
    fn sigma_index(&self, n: usize) -> usize {
        match self {
            Wire::LeftIn(index) => *index as usize,
            Wire::RightIn(index) => *index as usize + n,
            Wire::Out(index) => *index as usize + n * 2,
        }
    }
}

struct NodeIterator<'a> {
    inner: btree_map::Iter<'a, usize, BTreeSet<Wire>>,
}

impl<'a> Iterator for NodeIterator<'a> {
    type Item = &'a BTreeSet<Wire>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, node)| node)
    }
}

/// Keeps all the wires of a circuit organized in partitions, i.e. sets of interconnected wires.
///
/// Since all the wires in a partition are connected to each other, in this context a partition
/// represents a node of the circuit, so we call partitions "nodes".
///
/// This data structure allows determining the subsets of the sigma polynomials to permute.
#[derive(Debug, Default, Clone)]
struct WirePartitioning {
    /// Next available node ID.
    next_id: usize,

    /// Keys are incremental node IDs, values are nodes.
    nodes: BTreeMap<usize, BTreeSet<Wire>>,

    /// Keys are wires, values are the ID of the node that wire is connected to.
    ///
    /// If a wire is not found here it's implied that it belongs to a partition containing only
    /// that wire, i.e. it's unconstrained.
    node_by_wire: BTreeMap<Wire, usize>,
}

impl WirePartitioning {
    fn connect(&mut self, wire1: Wire, wire2: Wire) {
        if let Some(node_id1) = self.node_by_wire.get(&wire1) {
            if let Some(node_id2) = self.node_by_wire.get(&wire2) {
                if *node_id1 != *node_id2 {
                    let mut node2 = self.nodes.remove(&node_id2).unwrap();
                    let node1 = self.nodes.get_mut(node_id1).unwrap();
                    node1.append(&mut node2);
                    self.node_by_wire.insert(wire2, *node_id1);
                }
            } else {
                let node = self.nodes.get_mut(node_id1).unwrap();
                node.insert(wire2);
                self.node_by_wire.insert(wire2, *node_id1);
            }
        } else {
            if let Some(node_id) = self.node_by_wire.get(&wire2) {
                let node = self.nodes.get_mut(node_id).unwrap();
                node.insert(wire1);
                self.node_by_wire.insert(wire1, *node_id);
            } else {
                let id = self.next_id;
                self.next_id += 1;
                self.nodes.insert(id, BTreeSet::from([wire1, wire2]));
                self.node_by_wire.insert(wire1, id);
                self.node_by_wire.insert(wire2, id);
            }
        }
    }

    fn iter_nodes(&self) -> NodeIterator<'_> {
        NodeIterator {
            inner: self.nodes.iter(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct CircuitBuilder {
    gates: Vec<GateConstraint>,
    wires: WirePartitioning,
    public_inputs: BTreeSet<Wire>,
}

impl CircuitBuilder {
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    pub fn add_gate(&mut self, ql: Scalar, qr: Scalar, qo: Scalar, qm: Scalar, qc: Scalar) -> u32 {
        assert!(self.gates.len() < u32::MAX as usize);
        let index = self.gates.len() as u32;
        self.gates.push(GateConstraint { ql, qr, qo, qm, qc });
        index
    }

    pub fn add_sum(&mut self) -> u32 {
        self.add_gate(1.into(), 1.into(), -Scalar::from(1), 0.into(), 0.into())
    }

    pub fn add_sub(&mut self) -> u32 {
        self.add_gate(
            1.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            0.into(),
            0.into(),
        )
    }

    pub fn add_mul(&mut self) -> u32 {
        self.add_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into())
    }

    pub fn add_bool_check(&mut self) -> u32 {
        self.add_gate(-Scalar::from(1), 0.into(), 0.into(), 1.into(), 0.into())
    }

    pub fn add_not(&mut self) -> u32 {
        self.add_gate(
            -Scalar::from(1),
            0.into(),
            -Scalar::from(1),
            0.into(),
            1.into(),
        )
    }

    pub fn add_and(&mut self) -> u32 {
        self.add_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into())
    }

    pub fn add_or(&mut self) -> u32 {
        self.add_gate(
            1.into(),
            1.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            0.into(),
        )
    }

    pub fn add_xor(&mut self) -> u32 {
        self.add_gate(
            1.into(),
            1.into(),
            -Scalar::from(1),
            -Scalar::from(2),
            0.into(),
        )
    }

    pub fn connect(&mut self, wire1: Wire, wire2: Wire) {
        self.wires.connect(wire1, wire2);
    }

    pub fn declare_public_inputs<I: IntoIterator<Item = Wire>>(&mut self, wires: I) {
        self.public_inputs = BTreeSet::from_iter(wires);
    }

    fn build_identity_permutation(&self) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
        let n = self.gates.len().next_power_of_two();
        let mut x = vec![Scalar::ZERO; n * 3];
        if n > 0 {
            x[0] = 1.into();
            x[n] = k1();
            x[n * 2] = k2();
        }
        let omega = Polynomial::domain_element(1, n);
        for i in 1..n {
            x[i] = x[i - 1] * omega;
            x[i + n] = x[i + n - 1] * omega;
            x[i + n * 2] = x[i + n * 2 - 1] * omega;
        }
        for node in self.wires.iter_nodes() {
            let indices: Vec<usize> = node.iter().map(|wire| wire.sigma_index(n)).collect();
            let mut permuted: Vec<Scalar> = indices.iter().map(|i| x[*i]).collect();
            utils::shuffle(permuted.as_mut_slice());
            for i in 0..indices.len() {
                x[indices[i]] = permuted[i];
            }
        }
        (
            x[0..n].to_vec(),
            x[n..(n * 2)].to_vec(),
            x[(n * 2)..(n * 3)].to_vec(),
        )
    }

    pub fn build(self) -> Circuit {
        let n = self.gates.len().next_power_of_two();
        let pad = n - self.gates.len();
        let ql = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.ql)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qr = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qr)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qo = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qo)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qm = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qm)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qc = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qc)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let ql_c = ql.commitment();
        let qr_c = qr.commitment();
        let qo_c = qo.commitment();
        let qm_c = qm.commitment();
        let qc_c = qc.commitment();
        let (sl_values, sr_values, so_values) = self.build_identity_permutation();
        let sl = Polynomial::encode_list(sl_values.clone());
        let sr = Polynomial::encode_list(sr_values.clone());
        let so = Polynomial::encode_list(so_values.clone());
        let sl_c = sl.commitment();
        let sr_c = sr.commitment();
        let so_c = so.commitment();
        Circuit {
            size: self.gates.len(),
            public_inputs: self.public_inputs,
            ql,
            qr,
            qo,
            qm,
            qc,
            ql_c,
            qr_c,
            qo_c,
            qm_c,
            qc_c,
            sl_values,
            sr_values,
            so_values,
            sl,
            sr,
            so,
            sl_c,
            sr_c,
            so_c,
        }
    }

    pub fn check_witness(
        &self,
        left_in: &[Scalar],
        right_in: &[Scalar],
        out: &[Scalar],
    ) -> Result<()> {
        let size = self.gates.len();
        if left_in.len() != size {
            return Err(anyhow!(
                "the LHS input witness column has incorrect length (got {}, want {})",
                left_in.len(),
                size
            ));
        }
        if right_in.len() != size {
            return Err(anyhow!(
                "the RHS input witness column has incorrect length (got {}, want {})",
                right_in.len(),
                size
            ));
        }
        if out.len() != size {
            return Err(anyhow!(
                "the output witness column has incorrect length (got {}, want {})",
                out.len(),
                size
            ));
        }
        for i in 0..size {
            let lhs = left_in[i];
            let rhs = right_in[i];
            let out = out[i];
            let (ql, qr, qo, qm, qc) = match &self.gates[i] {
                GateConstraint { ql, qr, qo, qm, qc } => (ql, qr, qo, qm, qc),
            };
            if ql * lhs + qr * rhs + qo * out + qm * lhs * rhs + qc != 0.into() {
                return Err(anyhow!("gate constraint {} violated", i));
            }
        }
        for node in self.wires.iter_nodes() {
            let mut iter = node.iter();
            let value = match *iter.next().unwrap() {
                Wire::LeftIn(index) => left_in[index as usize],
                Wire::RightIn(index) => right_in[index as usize],
                Wire::Out(index) => out[index as usize],
            };
            while let Some(wire) = iter.next() {
                let next = match *wire {
                    Wire::LeftIn(index) => left_in[index as usize],
                    Wire::RightIn(index) => right_in[index as usize],
                    Wire::Out(index) => out[index as usize],
                };
                if next != value {
                    return Err(anyhow!("wire constraint violated"));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Proof {
    witness_proofs: [kzg::CommittedValueProof; 3],
    public_inputs: BTreeMap<Wire, kzg::ValueProof>,
    gate_constraint_coefficient_proofs: [kzg::ValueProof; 5],
    gate_constraint_quotient_proof: kzg::CommittedValueProof,
    permutation_accumulator_commitment: G1Affine,
    permutation_accumulator_fixpoint_proof: kzg::Proof,
    permutation_accumulator_proof: kzg::ValueProof,
    permutation_accumulator_next_proof: kzg::ValueProof,
    permutation_sigma_proofs: [kzg::ValueProof; 3],
    permutation_quotient_proof: kzg::CommittedValueProof,
}

#[derive(Debug, Clone)]
pub struct Circuit {
    size: usize,
    public_inputs: BTreeSet<Wire>,
    ql: Polynomial,
    qr: Polynomial,
    qo: Polynomial,
    qm: Polynomial,
    qc: Polynomial,
    ql_c: G1Projective,
    qr_c: G1Projective,
    qo_c: G1Projective,
    qm_c: G1Projective,
    qc_c: G1Projective,
    sl_values: Vec<Scalar>,
    sr_values: Vec<Scalar>,
    so_values: Vec<Scalar>,
    sl: Polynomial,
    sr: Polynomial,
    so: Polynomial,
    sl_c: G1Projective,
    sr_c: G1Projective,
    so_c: G1Projective,
}

impl Circuit {
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn compress(&self) -> CompressedCircuit {
        CompressedCircuit {
            original_size: self.size,
            ql: self.ql_c,
            qr: self.qr_c,
            qo: self.qo_c,
            qm: self.qm_c,
            qc: self.qc_c,
            sl: self.sl_c,
            sr: self.sr_c,
            so: self.so_c,
        }
    }

    pub fn to_compressed(self) -> CompressedCircuit {
        CompressedCircuit {
            original_size: self.size,
            ql: self.ql_c,
            qr: self.qr_c,
            qo: self.qo_c,
            qm: self.qm_c,
            qc: self.qc_c,
            sl: self.sl_c,
            sr: self.sr_c,
            so: self.so_c,
        }
    }

    fn get_challenges(witness_commitments: &[G1Affine]) -> (Scalar, Scalar, Scalar) {
        let witness_hash = utils::poseidon_hash(&[
            witness_hash_dst(),
            utils::hash_g1_to_scalar(witness_commitments[0]),
            utils::hash_g1_to_scalar(witness_commitments[1]),
            utils::hash_g1_to_scalar(witness_commitments[2]),
        ]);
        let beta = utils::poseidon_hash(&[beta_challenge_dst(), witness_hash, 1.into()]);
        let gamma = utils::poseidon_hash(&[gamma_challenge_dst(), witness_hash, 2.into()]);
        (witness_hash, beta, gamma)
    }

    /// Builds the two polynomials used in the permutation argument. The components of the returned
    /// tuple are the coordinate pair accumulator and the recurrence constraint, respectively.
    fn build_permutation_argument(
        &self,
        l: &[Scalar],
        r: &[Scalar],
        o: &[Scalar],
        beta: Scalar,
        gamma: Scalar,
    ) -> Result<(Polynomial, Polynomial)> {
        let n = self.size.next_power_of_two();
        let k1 = k1();
        let k2 = k2();

        let sl = self.sl_values.as_slice();
        let sr = self.sr_values.as_slice();
        let so = self.so_values.as_slice();

        let mut accumulator = vec![Scalar::ZERO; n + 1];
        let mut numerator1 = vec![Scalar::ZERO; n];
        let mut numerator2 = vec![Scalar::ZERO; n];
        let mut numerator3 = vec![Scalar::ZERO; n];
        let mut denominator1 = vec![Scalar::ZERO; n];
        let mut denominator2 = vec![Scalar::ZERO; n];
        let mut denominator3 = vec![Scalar::ZERO; n];

        accumulator[0] = 1.into();
        for i in 0..n {
            let x = Polynomial::domain_element(i, n);
            numerator1[i] = l[i] + beta * x + gamma;
            numerator2[i] = r[i] + beta * k1 * x + gamma;
            numerator3[i] = o[i] + beta * k2 * x + gamma;
            denominator1[i] = l[i] + beta * sl[i] + gamma;
            denominator2[i] = r[i] + beta * sr[i] + gamma;
            denominator3[i] = o[i] + beta * so[i] + gamma;
            accumulator[i + 1] = accumulator[i]
                * numerator1[i]
                * numerator2[i]
                * numerator3[i]
                * (denominator1[i] * denominator2[i] * denominator3[i])
                    .invert()
                    .into_option()
                    .context("division by zero in permutation accumulator")?;
        }

        if accumulator.pop().unwrap() != 1.into() {
            return Err(anyhow!("permutation accumulator wraparound check failed"));
        }

        let accumulator = Polynomial::encode_list(accumulator);
        let numerator1 = Polynomial::encode_list(numerator1);
        let numerator2 = Polynomial::encode_list(numerator2);
        let numerator3 = Polynomial::encode_list(numerator3);
        let denominator1 = Polynomial::encode_list(denominator1);
        let denominator2 = Polynomial::encode_list(denominator2);
        let denominator3 = Polynomial::encode_list(denominator3);

        let shifted = {
            let mut coefficients = accumulator.clone().take();
            let omega = Polynomial::domain_element(1, n);
            let mut x = Scalar::from(1);
            for coefficient in coefficients.iter_mut() {
                *coefficient *= x;
                x *= omega;
            }
            Polynomial::with_coefficients(coefficients)
        };

        let recurrence_constraint =
            Polynomial::multiply_many([shifted, denominator1, denominator2, denominator3])?
                - Polynomial::multiply_many([
                    accumulator.clone(),
                    numerator1,
                    numerator2,
                    numerator3,
                ])?;

        Ok((accumulator, recurrence_constraint))
    }

    pub fn prove(
        &self,
        mut left_in: Vec<Scalar>,
        mut right_in: Vec<Scalar>,
        mut out: Vec<Scalar>,
    ) -> Result<Proof> {
        if left_in.len() != self.size {
            return Err(anyhow!(
                "the LHS input witness column has incorrect length (got {}, want {})",
                left_in.len(),
                self.size
            ));
        }
        if right_in.len() != self.size {
            return Err(anyhow!(
                "the RHS input witness column has incorrect length (got {}, want {})",
                right_in.len(),
                self.size
            ));
        }
        if out.len() != self.size {
            return Err(anyhow!(
                "the output witness column has incorrect length (got {}, want {})",
                out.len(),
                self.size
            ));
        }

        let n = self.size.next_power_of_two();
        left_in.resize(n, Scalar::ZERO);
        right_in.resize(n, Scalar::ZERO);
        out.resize(n, Scalar::ZERO);

        let l = Polynomial::encode_list(left_in.clone());
        let r = Polynomial::encode_list(right_in.clone());
        let o = Polynomial::encode_list(out.clone());

        let witness_commitments = [
            l.commitment().into(),
            r.commitment().into(),
            o.commitment().into(),
        ];

        let public_inputs = BTreeMap::from_iter(self.public_inputs.iter().map(|wire| {
            let (p, i) = match wire {
                Wire::LeftIn(index) => (&l, *index),
                Wire::RightIn(index) => (&r, *index),
                Wire::Out(index) => (&o, *index),
            };
            (
                *wire,
                kzg::ValueProof::new(p, Polynomial::domain_element(i as usize, n)),
            )
        }));

        let (witness_hash, beta, gamma) = Self::get_challenges(&witness_commitments);

        let witness_proofs = [
            kzg::CommittedValueProof::with_commitment(&l, witness_commitments[0], witness_hash),
            kzg::CommittedValueProof::with_commitment(&r, witness_commitments[1], witness_hash),
            kzg::CommittedValueProof::with_commitment(&o, witness_commitments[2], witness_hash),
        ];

        let gate_constraint_coefficient_proofs = [
            kzg::ValueProof::new(&self.ql, witness_hash),
            kzg::ValueProof::new(&self.qr, witness_hash),
            kzg::ValueProof::new(&self.qo, witness_hash),
            kzg::ValueProof::new(&self.qm, witness_hash),
            kzg::ValueProof::new(&self.qc, witness_hash),
        ];
        let gate_constraint_quotient = {
            let lr = l.clone().multiply(r.clone())?;
            let gate_constraint = self.ql.clone().multiply(l)?
                + self.qr.clone().multiply(r)?
                + self.qo.clone().multiply(o)?
                + self.qm.clone().multiply(lr)?
                + self.qc.clone();
            gate_constraint.divide_by_zero(n)?
        };
        let gate_constraint_quotient_proof =
            kzg::CommittedValueProof::new(&gate_constraint_quotient, witness_hash);

        let (permutation_accumulator, recurrence_constraint) = self.build_permutation_argument(
            left_in.as_slice(),
            right_in.as_slice(),
            out.as_slice(),
            beta,
            gamma,
        )?;

        let permutation_accumulator_commitment = permutation_accumulator.commitment().into();

        let (permutation_accumulator_fixpoint_proof, permutation_accumulator_start_value) =
            kzg::Proof::new(&permutation_accumulator, 1.into());
        if permutation_accumulator_start_value != 1.into() {
            return Err(anyhow!("bad permutation accumulator start point"));
        }

        let permutation_accumulator_proof =
            kzg::ValueProof::new(&permutation_accumulator, witness_hash);

        let omega = Polynomial::domain_element(1, n);
        let permutation_accumulator_next_proof =
            kzg::ValueProof::new(&permutation_accumulator, witness_hash * omega);

        let permutation_sigma_proofs = [
            kzg::ValueProof::new(&self.sl, witness_hash),
            kzg::ValueProof::new(&self.sr, witness_hash),
            kzg::ValueProof::new(&self.so, witness_hash),
        ];

        let permutation_quotient_proof = {
            let permutation_quotient = recurrence_constraint.divide_by_zero(n)?;
            kzg::CommittedValueProof::new(&permutation_quotient, witness_hash)
        };

        Ok(Proof {
            witness_proofs,
            public_inputs,
            gate_constraint_coefficient_proofs,
            gate_constraint_quotient_proof,
            permutation_accumulator_commitment,
            permutation_accumulator_fixpoint_proof,
            permutation_accumulator_proof,
            permutation_accumulator_next_proof,
            permutation_sigma_proofs,
            permutation_quotient_proof,
        })
    }

    pub fn verify(&self, proof: &Proof) -> Result<BTreeMap<Wire, Scalar>> {
        self.compress().verify(proof)
    }
}

#[derive(Debug, Clone)]
pub struct CompressedCircuit {
    original_size: usize,
    ql: G1Projective,
    qr: G1Projective,
    qo: G1Projective,
    qm: G1Projective,
    qc: G1Projective,
    sl: G1Projective,
    sr: G1Projective,
    so: G1Projective,
}

impl CompressedCircuit {
    pub fn original_size(&self) -> usize {
        self.original_size
    }

    pub fn verify(&self, proof: &Proof) -> Result<BTreeMap<Wire, Scalar>> {
        let n = self.original_size.next_power_of_two();

        let (witness_hash, beta, gamma) =
            Circuit::get_challenges(&proof.witness_proofs.map(|proof| proof.c()));

        proof.witness_proofs[0].verify(witness_hash)?;
        proof.witness_proofs[1].verify(witness_hash)?;
        proof.witness_proofs[2].verify(witness_hash)?;

        for (wire, public_input) in &proof.public_inputs {
            let (c, i) = match wire {
                Wire::LeftIn(index) => (proof.witness_proofs[0].c(), *index),
                Wire::RightIn(index) => (proof.witness_proofs[1].c(), *index),
                Wire::Out(index) => (proof.witness_proofs[2].c(), *index),
            };
            let z = Polynomial::domain_element(i as usize, n);
            public_input.verify(c, z)?;
        }

        let l = proof.witness_proofs[0].v();
        let r = proof.witness_proofs[1].v();
        let o = proof.witness_proofs[2].v();
        let zero_value = witness_hash.pow_vartime([n as u64, 0, 0, 0]) - Scalar::from(1);

        proof.gate_constraint_coefficient_proofs[0].verify(self.ql, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[1].verify(self.qr, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[2].verify(self.qo, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[3].verify(self.qm, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[4].verify(self.qc, witness_hash)?;

        proof.gate_constraint_quotient_proof.verify(witness_hash)?;

        let ql = proof.gate_constraint_coefficient_proofs[0].v();
        let qr = proof.gate_constraint_coefficient_proofs[1].v();
        let qo = proof.gate_constraint_coefficient_proofs[2].v();
        let qm = proof.gate_constraint_coefficient_proofs[3].v();
        let qc = proof.gate_constraint_coefficient_proofs[4].v();
        let gate_constraint_value = ql * l + qr * r + qo * o + qm * l * r + qc;
        if gate_constraint_value != zero_value * proof.gate_constraint_quotient_proof.v() {
            return Err(anyhow!("gate constraint violation"));
        }

        proof.permutation_accumulator_fixpoint_proof.verify(
            proof.permutation_accumulator_commitment,
            1.into(),
            1.into(),
        )?;

        proof
            .permutation_accumulator_proof
            .verify(proof.permutation_accumulator_commitment, witness_hash)?;

        let omega = Polynomial::domain_element(1, n);
        proof.permutation_accumulator_next_proof.verify(
            proof.permutation_accumulator_commitment,
            witness_hash * omega,
        )?;

        proof.permutation_sigma_proofs[0].verify(self.sl, witness_hash)?;
        proof.permutation_sigma_proofs[1].verify(self.sr, witness_hash)?;
        proof.permutation_sigma_proofs[2].verify(self.so, witness_hash)?;

        proof.permutation_quotient_proof.verify(witness_hash)?;

        let k1 = k1();
        let k2 = k2();
        let permutation_accumulator = proof.permutation_accumulator_proof.v();
        let shifted_permutation_accumulator = proof.permutation_accumulator_next_proof.v();
        let permutation_numerator = (l + beta * witness_hash + gamma)
            * (r + beta * k1 * witness_hash + gamma)
            * (o + beta * k2 * witness_hash + gamma);
        let permutation_denominator = {
            let sl = proof.permutation_sigma_proofs[0].v();
            let sr = proof.permutation_sigma_proofs[1].v();
            let so = proof.permutation_sigma_proofs[2].v();
            (l + beta * sl + gamma) * (r + beta * sr + gamma) * (o + beta * so + gamma)
        };
        let permutation_quotient = proof.permutation_quotient_proof.v();
        if shifted_permutation_accumulator * permutation_denominator
            - permutation_accumulator * permutation_numerator
            != zero_value * permutation_quotient
        {
            return Err(anyhow!("copy constraint violation"));
        }

        Ok(proof
            .public_inputs
            .iter()
            .map(|(wire, proof)| (*wire, proof.v()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the circuit at https://vitalik.eth.limo/general/2019/09/22/plonk.html.
    fn build_test_circuit() -> (Circuit, u32) {
        let mut builder = CircuitBuilder::default();
        let gate1 = builder.add_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into());
        builder.connect(Wire::LeftIn(gate1), Wire::RightIn(gate1));
        let gate2 = builder.add_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into());
        builder.connect(Wire::LeftIn(gate2), Wire::Out(gate1));
        builder.connect(Wire::RightIn(gate2), Wire::LeftIn(gate1));
        let gate3 = builder.add_gate(1.into(), 1.into(), -Scalar::from(1), 0.into(), 0.into());
        builder.connect(Wire::LeftIn(gate3), Wire::LeftIn(gate1));
        builder.connect(Wire::RightIn(gate3), Wire::Out(gate2));
        let gate4 = builder.add_gate(1.into(), 1.into(), -Scalar::from(1), 0.into(), 0.into());
        builder.connect(Wire::LeftIn(gate4), Wire::Out(gate3));
        builder.declare_public_inputs([Wire::RightIn(gate4), Wire::Out(gate4)]);
        (builder.build(), gate4)
    }

    #[test]
    fn test_circuit1() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            )
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_helpers() {
        let mut builder = CircuitBuilder::default();
        let gate1 = builder.add_mul();
        builder.connect(Wire::LeftIn(gate1), Wire::RightIn(gate1));
        let gate2 = builder.add_mul();
        builder.connect(Wire::LeftIn(gate2), Wire::Out(gate1));
        builder.connect(Wire::RightIn(gate2), Wire::LeftIn(gate1));
        let gate3 = builder.add_sum();
        builder.connect(Wire::LeftIn(gate3), Wire::LeftIn(gate1));
        builder.connect(Wire::RightIn(gate3), Wire::Out(gate2));
        let gate4 = builder.add_sum();
        builder.connect(Wire::LeftIn(gate4), Wire::Out(gate3));
        builder.declare_public_inputs([Wire::RightIn(gate4), Wire::Out(gate4)]);
        let circuit = builder.build();
        let proof = circuit
            .prove(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            )
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate4)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate4)).unwrap(), 35.into());
    }

    #[test]
    fn test_circuit2() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(
                vec![4.into(), 16.into(), 4.into(), 68.into()],
                vec![4.into(), 4.into(), 64.into(), 5.into()],
                vec![16.into(), 64.into(), 68.into(), 73.into()],
            )
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 73.into());
    }

    #[test]
    fn test_gate_constraint_violation() {
        let (circuit, _) = build_test_circuit();
        assert!(
            circuit
                .prove(
                    vec![4.into(), 16.into(), 4.into(), 68.into()],
                    vec![4.into(), 4.into(), 64.into(), 5.into()],
                    vec![16.into(), 64.into(), 68.into(), 35.into()],
                )
                .is_err()
        );
    }

    #[test]
    fn test_compressed_circuit1() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            )
            .unwrap();
        let circuit = circuit.to_compressed();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_compressed_circuit2() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(
                vec![4.into(), 16.into(), 4.into(), 68.into()],
                vec![4.into(), 4.into(), 64.into(), 5.into()],
                vec![16.into(), 64.into(), 68.into(), 73.into()],
            )
            .unwrap();
        let circuit = circuit.to_compressed();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 73.into());
    }

    // TODO
}
