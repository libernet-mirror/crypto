use crate::kzg;
use crate::poly::Polynomial;
use crate::poseidon;
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

fn alpha_challenge_dst() -> Scalar {
    static TAG: LazyLock<Scalar> =
        LazyLock::new(|| utils::hash_to_scalar(b"libernet/plonk/alpha_challenge"));
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

fn padded_size(n: usize) -> usize {
    std::cmp::max(2, n.next_power_of_two())
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

#[derive(Debug, Default)]
pub struct GateSet {
    gates: Vec<u32>,
    index: usize,
}

impl GateSet {
    pub fn count(&self) -> usize {
        self.gates.len()
    }

    pub fn is_empty(&self) -> bool {
        assert!(self.index <= self.gates.len());
        self.index == self.gates.len()
    }

    pub fn push(&mut self, gate: u32) {
        self.gates.push(gate);
    }

    pub fn pop(&mut self) -> u32 {
        let gate = self.gates[self.index];
        self.index += 1;
        gate
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    size: usize,
    left: Vec<Scalar>,
    right: Vec<Scalar>,
    out: Vec<Scalar>,
}

impl Witness {
    pub fn new(size: usize) -> Self {
        let padded_size = padded_size(size);
        Self {
            size,
            left: vec![Scalar::ZERO; padded_size],
            right: vec![Scalar::ZERO; padded_size],
            out: vec![Scalar::ZERO; padded_size],
        }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn get(&self, wire: Wire) -> Scalar {
        match wire {
            Wire::LeftIn(index) => self.left[index as usize],
            Wire::RightIn(index) => self.right[index as usize],
            Wire::Out(index) => self.out[index as usize],
        }
    }

    pub fn set(&mut self, wire: Wire, value: Scalar) {
        match wire {
            Wire::LeftIn(index) => self.left[index as usize] = value,
            Wire::RightIn(index) => self.right[index as usize] = value,
            Wire::Out(index) => self.out[index as usize] = value,
        };
    }

    pub fn copy(&mut self, from: Wire, to: Wire) -> Scalar {
        let value = self.get(from);
        self.set(to, value);
        value
    }

    pub fn assert_constant(&mut self, gate: u32, value: Scalar) -> Wire {
        let wire = Wire::Out(gate);
        self.set(wire, value);
        wire
    }

    pub fn add(&mut self, gate: u32, lhs: Wire, rhs: Wire) -> Wire {
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs + rhs);
        out
    }

    pub fn add_const(&mut self, gate: u32, lhs: Wire, rhs: Scalar) -> Wire {
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs + rhs);
        out
    }

    pub fn sub(&mut self, gate: u32, lhs: Wire, rhs: Wire) -> Wire {
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs - rhs);
        out
    }

    pub fn sub_const(&mut self, gate: u32, lhs: Wire, rhs: Scalar) -> Wire {
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs - rhs);
        out
    }

    pub fn sub_from_const(&mut self, gate: u32, lhs: Scalar, rhs: Wire) -> Wire {
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs - rhs);
        out
    }

    pub fn mul(&mut self, gate: u32, lhs: Wire, rhs: Wire) -> Wire {
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs * rhs);
        out
    }

    pub fn mul_by_const(&mut self, gate: u32, lhs: Wire, rhs: Scalar) -> Wire {
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs * rhs);
        out
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

    pub fn add_const(&mut self, value: Scalar) -> u32 {
        self.add_gate(0.into(), 0.into(), 1.into(), 0.into(), -value)
    }

    pub fn add_sum(&mut self) -> u32 {
        self.add_gate(1.into(), 1.into(), -Scalar::from(1), 0.into(), 0.into())
    }

    pub fn add_sum_with_const(&mut self, c: Scalar) -> u32 {
        self.add_gate(1.into(), 0.into(), -Scalar::from(1), 0.into(), c)
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

    pub fn add_sub_const(&mut self, c: Scalar) -> u32 {
        self.add_gate(1.into(), 0.into(), -Scalar::from(1), 0.into(), -c)
    }

    pub fn add_sub_from_const(&mut self, c: Scalar) -> u32 {
        self.add_gate(0.into(), -Scalar::from(1), -Scalar::from(1), 0.into(), c)
    }

    pub fn add_mul(&mut self) -> u32 {
        self.add_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into())
    }

    pub fn add_mul_by_const(&mut self, c: Scalar) -> u32 {
        self.add_gate(0.into(), 0.into(), -Scalar::from(1), c, 0.into())
    }

    pub fn add_bool_assertion(&mut self) -> u32 {
        let gate = self.add_gate(1.into(), 0.into(), 0.into(), -Scalar::from(1), 0.into());
        self.connect(Wire::LeftIn(gate), Wire::RightIn(gate));
        gate
    }

    pub fn add_not(&mut self) -> u32 {
        let gate = self.add_gate(
            -Scalar::from(1),
            0.into(),
            -Scalar::from(1),
            0.into(),
            1.into(),
        );
        self.connect(Wire::LeftIn(gate), Wire::RightIn(gate));
        gate
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
        let n = padded_size(self.gates.len());
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
            permuted.rotate_left(1);
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
        let n = padded_size(self.gates.len());
        let pad = n - self.gates.len();
        let ql = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.ql)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
            false,
        );
        let qr = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qr)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
            false,
        );
        let qo = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qo)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
            false,
        );
        let qm = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qm)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
            false,
        );
        let qc = Polynomial::encode_list(
            self.gates
                .iter()
                .map(|gate| gate.qc)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
            false,
        );
        let ql_c = ql.commitment();
        let qr_c = qr.commitment();
        let qo_c = qo.commitment();
        let qm_c = qm.commitment();
        let qc_c = qc.commitment();
        let (sl_values, sr_values, so_values) = self.build_identity_permutation();
        let sl = Polynomial::encode_list(sl_values.clone(), false);
        let sr = Polynomial::encode_list(sr_values.clone(), false);
        let so = Polynomial::encode_list(so_values.clone(), false);
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

    pub fn check_witness(&self, witness: &Witness) -> Result<()> {
        let size = self.gates.len();
        if witness.size() != size {
            return Err(anyhow!(
                "incorrect witness size (got {}, want {})",
                witness.size(),
                size
            ));
        }
        for i in 0..size {
            let lhs = witness.left[i];
            let rhs = witness.right[i];
            let out = witness.out[i];
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
                Wire::LeftIn(index) => witness.left[index as usize],
                Wire::RightIn(index) => witness.right[index as usize],
                Wire::Out(index) => witness.out[index as usize],
            };
            while let Some(wire) = iter.next() {
                let next = match *wire {
                    Wire::LeftIn(index) => witness.left[index as usize],
                    Wire::RightIn(index) => witness.right[index as usize],
                    Wire::Out(index) => witness.out[index as usize],
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
    permutation_accumulator_commitment: G1Affine,
    permutation_accumulator_proof: kzg::MultiValueProof<2>,
    permutation_sigma_proofs: [kzg::ValueProof; 3],
    constraint_quotient_proof: kzg::CommittedValueProof,
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
            ql: self.ql_c.into(),
            qr: self.qr_c.into(),
            qo: self.qo_c.into(),
            qm: self.qm_c.into(),
            qc: self.qc_c.into(),
            sl: self.sl_c.into(),
            sr: self.sr_c.into(),
            so: self.so_c.into(),
        }
    }

    pub fn to_compressed(self) -> CompressedCircuit {
        CompressedCircuit {
            original_size: self.size,
            ql: self.ql_c.into(),
            qr: self.qr_c.into(),
            qo: self.qo_c.into(),
            qm: self.qm_c.into(),
            qc: self.qc_c.into(),
            sl: self.sl_c.into(),
            sr: self.sr_c.into(),
            so: self.so_c.into(),
        }
    }

    fn get_challenges(witness_commitments: &[G1Affine]) -> (Scalar, Scalar, Scalar, Scalar) {
        let witness_hash = poseidon::hash_t4(&[
            witness_hash_dst(),
            utils::hash_g1_to_scalar(witness_commitments[0]),
            utils::hash_g1_to_scalar(witness_commitments[1]),
            utils::hash_g1_to_scalar(witness_commitments[2]),
        ]);
        let alpha = poseidon::hash_t4(&[alpha_challenge_dst(), witness_hash, 1.into()]);
        let beta = poseidon::hash_t4(&[beta_challenge_dst(), witness_hash, 2.into()]);
        let gamma = poseidon::hash_t4(&[gamma_challenge_dst(), witness_hash, 3.into()]);
        (witness_hash, alpha, beta, gamma)
    }

    /// Builds the two polynomials used in the permutation argument. The components of the returned
    /// tuple are the coordinate pair accumulator and the recurrence constraint, respectively.
    fn build_permutation_argument(
        &self,
        witness: &Witness,
        l: &Polynomial,
        r: &Polynomial,
        o: &Polynomial,
        alpha: Scalar,
        beta: Scalar,
        gamma: Scalar,
    ) -> Result<(Polynomial, Polynomial)> {
        let n = padded_size(self.size);
        let k1 = k1();
        let k2 = k2();

        let sl = self.sl_values.as_slice();
        let sr = self.sr_values.as_slice();
        let so = self.so_values.as_slice();

        let mut accumulator = vec![Scalar::ZERO; n + 1];

        accumulator[0] = 1.into();
        for i in 0..n {
            let x = Polynomial::domain_element(i, n);
            accumulator[i + 1] = accumulator[i]
                * (witness.left[i] + beta * x + gamma)
                * (witness.right[i] + beta * k1 * x + gamma)
                * (witness.out[i] + beta * k2 * x + gamma)
                * ((witness.left[i] + beta * sl[i] + gamma)
                    * (witness.right[i] + beta * sr[i] + gamma)
                    * (witness.out[i] + beta * so[i] + gamma))
                    .invert()
                    .into_option()
                    .context("division by zero in permutation accumulator")?;
        }

        if accumulator.pop().unwrap() != 1.into() {
            return Err(anyhow!("permutation accumulator wraparound check failed"));
        }

        let accumulator = Polynomial::encode_list(accumulator, true);

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

        let recurrence_constraint = Polynomial::multiply_many([
            shifted,
            l.clone() + self.sl.clone() * beta + gamma,
            r.clone() + self.sr.clone() * beta + gamma,
            o.clone() + self.so.clone() * beta + gamma,
        ])? - Polynomial::multiply_many([
            accumulator.clone(),
            l.clone() + Polynomial::with_coefficients(vec![gamma, beta]),
            r.clone() + Polynomial::with_coefficients(vec![gamma, beta * k1]),
            o.clone() + Polynomial::with_coefficients(vec![gamma, beta * k2]),
        ])?;

        let permutation_constraint = recurrence_constraint * alpha
            + (accumulator.clone() - Scalar::from(1)).multiply(Polynomial::lagrange0(n).clone())?
                * alpha.square();

        Ok((accumulator, permutation_constraint))
    }

    pub fn prove(&self, witness: Witness) -> Result<Proof> {
        if witness.size() != self.size {
            return Err(anyhow!(
                "incorrect witness size (got {}, want {})",
                witness.size(),
                self.size
            ));
        }

        let n = padded_size(self.size);

        let l = Polynomial::encode_list(witness.left.clone(), true);
        let r = Polynomial::encode_list(witness.right.clone(), true);
        let o = Polynomial::encode_list(witness.out.clone(), true);

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

        let (witness_hash, alpha, beta, gamma) = Self::get_challenges(&witness_commitments);

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

        let (permutation_accumulator, permutation_constraint) =
            self.build_permutation_argument(&witness, &l, &r, &o, alpha, beta, gamma)?;

        let permutation_accumulator_commitment = permutation_accumulator.commitment().into();

        let omega = Polynomial::domain_element(1, n);
        let permutation_accumulator_proof = kzg::MultiValueProof::new(
            &permutation_accumulator,
            &[witness_hash, witness_hash * omega],
        )?;

        let permutation_sigma_proofs = [
            kzg::ValueProof::new(&self.sl, witness_hash),
            kzg::ValueProof::new(&self.sr, witness_hash),
            kzg::ValueProof::new(&self.so, witness_hash),
        ];

        let constraint_quotient_proof = {
            let gate_constraint = self.ql.clone().multiply(l.clone())?
                + self.qr.clone().multiply(r.clone())?
                + self.qo.clone().multiply(o)?
                + Polynomial::multiply_many([self.qm.clone(), l, r])?
                + self.qc.clone();
            let constraint = gate_constraint + permutation_constraint;
            let quotient = constraint.divide_by_zero(n)?;
            kzg::CommittedValueProof::new(&quotient, witness_hash)
        };

        Ok(Proof {
            witness_proofs,
            public_inputs,
            gate_constraint_coefficient_proofs,
            permutation_accumulator_commitment,
            permutation_accumulator_proof,
            permutation_sigma_proofs,
            constraint_quotient_proof,
        })
    }

    pub fn verify(&self, proof: &Proof) -> Result<BTreeMap<Wire, Scalar>> {
        self.compress().verify(proof)
    }
}

#[derive(Debug, Clone)]
pub struct CompressedCircuit {
    original_size: usize,
    ql: G1Affine,
    qr: G1Affine,
    qo: G1Affine,
    qm: G1Affine,
    qc: G1Affine,
    sl: G1Affine,
    sr: G1Affine,
    so: G1Affine,
}

impl CompressedCircuit {
    pub fn original_size(&self) -> usize {
        self.original_size
    }

    fn lagrange0(x: Scalar, n: usize) -> Scalar {
        let one = Scalar::from(1);
        (x.pow_vartime([n as u64, 0, 0, 0]) - one)
            * (Scalar::from(n as u64) * (x - one))
                .invert()
                .into_option()
                .unwrap()
    }

    pub fn verify(&self, proof: &Proof) -> Result<BTreeMap<Wire, Scalar>> {
        let n = padded_size(self.original_size);

        let (witness_hash, alpha, beta, gamma) =
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

        proof.gate_constraint_coefficient_proofs[0].verify(self.ql, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[1].verify(self.qr, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[2].verify(self.qo, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[3].verify(self.qm, witness_hash)?;
        proof.gate_constraint_coefficient_proofs[4].verify(self.qc, witness_hash)?;

        let omega = Polynomial::domain_element(1, n);
        proof.permutation_accumulator_proof.verify(
            proof.permutation_accumulator_commitment,
            &[witness_hash, witness_hash * omega],
        )?;

        proof.permutation_sigma_proofs[0].verify(self.sl, witness_hash)?;
        proof.permutation_sigma_proofs[1].verify(self.sr, witness_hash)?;
        proof.permutation_sigma_proofs[2].verify(self.so, witness_hash)?;

        proof.constraint_quotient_proof.verify(witness_hash)?;

        let ql = proof.gate_constraint_coefficient_proofs[0].v();
        let qr = proof.gate_constraint_coefficient_proofs[1].v();
        let qo = proof.gate_constraint_coefficient_proofs[2].v();
        let qm = proof.gate_constraint_coefficient_proofs[3].v();
        let qc = proof.gate_constraint_coefficient_proofs[4].v();
        let gate_constraint = ql * l + qr * r + qo * o + qm * l * r + qc;
        let k1 = k1();
        let k2 = k2();
        let (permutation_accumulator, shifted_permutation_accumulator) =
            match proof.permutation_accumulator_proof.values() {
                [permutation_accumulator, shifted_permutation_accumulator] => {
                    (*permutation_accumulator, *shifted_permutation_accumulator)
                }
            };
        let permutation_numerator = (l + beta * witness_hash + gamma)
            * (r + beta * k1 * witness_hash + gamma)
            * (o + beta * k2 * witness_hash + gamma);
        let permutation_denominator = {
            let sl = proof.permutation_sigma_proofs[0].v();
            let sr = proof.permutation_sigma_proofs[1].v();
            let so = proof.permutation_sigma_proofs[2].v();
            (l + beta * sl + gamma) * (r + beta * sr + gamma) * (o + beta * so + gamma)
        };
        let permutation_constraint = shifted_permutation_accumulator * permutation_denominator
            - permutation_accumulator * permutation_numerator;
        let permutation_fixpoint =
            (permutation_accumulator - Scalar::from(1)) * Self::lagrange0(witness_hash, n);

        let constraint = gate_constraint
            + alpha * permutation_constraint
            + alpha.square() * permutation_fixpoint;
        let zero_value = witness_hash.pow_vartime([n as u64, 0, 0, 0]) - Scalar::from(1);
        let quotient = proof.constraint_quotient_proof.v();
        if constraint != zero_value * quotient {
            return Err(anyhow!("constraint violation"));
        }

        Ok(proof
            .public_inputs
            .iter()
            .map(|(wire, proof)| (*wire, proof.v()))
            .collect())
    }
}

pub trait Chip<const I: usize, const O: usize> {
    fn build(&mut self, builder: &mut CircuitBuilder, inputs: [Wire; I]) -> Result<[Wire; O]>;

    fn witness(
        &mut self,
        witness: &mut Witness,
        inputs: [Wire; I],
        outputs: [Wire; O],
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_set_initial_state() {
        let set = GateSet::default();
        assert_eq!(set.count(), 0);
        assert!(set.is_empty());
    }

    #[test]
    fn test_gate_set_push_one() {
        let mut set = GateSet::default();
        set.push(12);
        assert_eq!(set.count(), 1);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_gate_set_push_two() {
        let mut set = GateSet::default();
        set.push(34);
        set.push(56);
        assert_eq!(set.count(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_gate_set_pop_one() {
        let mut set = GateSet::default();
        set.push(34);
        set.push(56);
        assert_eq!(set.pop(), 34);
        assert_eq!(set.count(), 2);
        assert!(!set.is_empty());
    }

    #[test]
    fn test_gate_set_pop_two() {
        let mut set = GateSet::default();
        set.push(34);
        set.push(56);
        assert_eq!(set.pop(), 34);
        assert_eq!(set.pop(), 56);
        assert_eq!(set.count(), 2);
        assert!(set.is_empty());
    }

    #[test]
    fn test_witness_one_row_initial_state() {
        let witness = Witness::new(1);
        assert_eq!(witness.size(), 1);
        assert_eq!(witness.get(Wire::LeftIn(0)), 0.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 0.into());
        assert_eq!(witness.get(Wire::Out(0)), 0.into());
    }

    #[test]
    fn test_witness_two_rows_initial_state() {
        let witness = Witness::new(2);
        assert_eq!(witness.size(), 2);
        assert_eq!(witness.get(Wire::LeftIn(0)), 0.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 0.into());
        assert_eq!(witness.get(Wire::Out(0)), 0.into());
        assert_eq!(witness.get(Wire::LeftIn(1)), 0.into());
        assert_eq!(witness.get(Wire::RightIn(1)), 0.into());
        assert_eq!(witness.get(Wire::Out(1)), 0.into());
    }

    #[test]
    fn test_witness_one_row_update() {
        let mut witness = Witness::new(1);
        witness.set(Wire::LeftIn(0), 12.into());
        witness.set(Wire::RightIn(0), 34.into());
        witness.set(Wire::Out(0), 56.into());
        assert_eq!(witness.size(), 1);
        assert_eq!(witness.get(Wire::LeftIn(0)), 12.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 34.into());
        assert_eq!(witness.get(Wire::Out(0)), 56.into());
    }

    #[test]
    fn test_witness_two_rows_update() {
        let mut witness = Witness::new(2);
        witness.set(Wire::LeftIn(0), 65.into());
        witness.set(Wire::RightIn(0), 43.into());
        witness.set(Wire::Out(0), 21.into());
        witness.set(Wire::LeftIn(1), 12.into());
        witness.set(Wire::RightIn(1), 34.into());
        witness.set(Wire::Out(1), 56.into());
        assert_eq!(witness.size(), 2);
        assert_eq!(witness.get(Wire::LeftIn(0)), 65.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 43.into());
        assert_eq!(witness.get(Wire::Out(0)), 21.into());
        assert_eq!(witness.get(Wire::LeftIn(1)), 12.into());
        assert_eq!(witness.get(Wire::RightIn(1)), 34.into());
        assert_eq!(witness.get(Wire::Out(1)), 56.into());
    }

    #[test]
    fn test_witness_copy_within_same_row() {
        let mut witness = Witness::new(1);
        witness.set(Wire::LeftIn(0), 12.into());
        witness.set(Wire::RightIn(0), 34.into());
        assert_eq!(witness.copy(Wire::RightIn(0), Wire::Out(0)), 34.into());
        assert_eq!(witness.size(), 1);
        assert_eq!(witness.get(Wire::LeftIn(0)), 12.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 34.into());
        assert_eq!(witness.get(Wire::Out(0)), 34.into());
    }

    #[test]
    fn test_witness_copy_across_rows() {
        let mut witness = Witness::new(2);
        witness.set(Wire::LeftIn(0), 12.into());
        witness.set(Wire::RightIn(0), 34.into());
        witness.set(Wire::Out(0), 56.into());
        assert_eq!(witness.copy(Wire::RightIn(0), Wire::LeftIn(1)), 34.into());
        assert_eq!(witness.copy(Wire::LeftIn(0), Wire::RightIn(1)), 12.into());
        witness.set(Wire::Out(1), 56.into());
        assert_eq!(witness.size(), 2);
        assert_eq!(witness.get(Wire::LeftIn(0)), 12.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 34.into());
        assert_eq!(witness.get(Wire::Out(0)), 56.into());
        assert_eq!(witness.get(Wire::LeftIn(1)), 34.into());
        assert_eq!(witness.get(Wire::RightIn(1)), 12.into());
        assert_eq!(witness.get(Wire::Out(1)), 56.into());
    }

    #[test]
    fn test_witness_assert_constant() {
        let mut witness = Witness::new(1);
        let wire = witness.assert_constant(0, 42.into());
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 42.into());
    }

    #[test]
    fn test_witness_add() {
        let mut witness = Witness::new(1);
        let lhs = Wire::LeftIn(0);
        let rhs = Wire::RightIn(0);
        witness.set(lhs, 12.into());
        witness.set(rhs, 34.into());
        let wire = witness.add(0, lhs, rhs);
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 46.into());
    }

    #[test]
    fn test_witness_add_const() {
        let mut witness = Witness::new(1);
        let lhs = Wire::LeftIn(0);
        witness.set(lhs, 12.into());
        let wire = witness.add_const(0, lhs, 34.into());
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 46.into());
    }

    #[test]
    fn test_witness_sub() {
        let mut witness = Witness::new(1);
        let lhs = Wire::LeftIn(0);
        let rhs = Wire::RightIn(0);
        witness.set(lhs, 34.into());
        witness.set(rhs, 12.into());
        let wire = witness.sub(0, lhs, rhs);
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 22.into());
    }

    #[test]
    fn test_witness_sub_const() {
        let mut witness = Witness::new(1);
        let lhs = Wire::LeftIn(0);
        witness.set(lhs, 34.into());
        let wire = witness.sub_const(0, lhs, 12.into());
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 22.into());
    }

    #[test]
    fn test_witness_sub_from_const() {
        let mut witness = Witness::new(1);
        let rhs = Wire::LeftIn(0);
        witness.set(rhs, 12.into());
        let wire = witness.sub_from_const(0, 34.into(), rhs);
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 22.into());
    }

    #[test]
    fn test_witness_mul() {
        let mut witness = Witness::new(1);
        let lhs = Wire::LeftIn(0);
        let rhs = Wire::RightIn(0);
        witness.set(lhs, 12.into());
        witness.set(rhs, 34.into());
        let wire = witness.mul(0, lhs, rhs);
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 408.into());
    }

    #[test]
    fn test_witness_mul_by_const() {
        let mut witness = Witness::new(1);
        let lhs = Wire::LeftIn(0);
        witness.set(lhs, 12.into());
        let wire = witness.mul_by_const(0, lhs, 34.into());
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), 408.into());
    }

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

    fn witness(mut left: Vec<Scalar>, mut right: Vec<Scalar>, mut out: Vec<Scalar>) -> Witness {
        let original_size = left.len();
        assert_eq!(original_size, right.len());
        assert_eq!(original_size, out.len());
        let padded_size = padded_size(original_size);
        left.resize(padded_size, Scalar::ZERO);
        right.resize(padded_size, Scalar::ZERO);
        out.resize(padded_size, Scalar::ZERO);
        Witness {
            size: original_size,
            left,
            right,
            out,
        }
    }

    #[test]
    fn test_circuit1() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            ))
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_circuit1_with_helpers() {
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
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            ))
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate4)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate4)).unwrap(), 35.into());
    }

    #[test]
    fn test_circuit2() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(witness(
                vec![4.into(), 16.into(), 4.into(), 68.into()],
                vec![4.into(), 4.into(), 64.into(), 5.into()],
                vec![16.into(), 64.into(), 68.into(), 73.into()],
            ))
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
                .prove(witness(
                    vec![4.into(), 16.into(), 4.into(), 68.into()],
                    vec![4.into(), 4.into(), 64.into(), 5.into()],
                    vec![16.into(), 64.into(), 68.into(), 35.into()],
                ))
                .is_err()
        );
    }

    #[test]
    fn test_compressed_circuit1() {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            ))
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
            .prove(witness(
                vec![4.into(), 16.into(), 4.into(), 68.into()],
                vec![4.into(), 4.into(), 64.into(), 5.into()],
                vec![16.into(), 64.into(), 68.into(), 73.into()],
            ))
            .unwrap();
        let circuit = circuit.to_compressed();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 73.into());
    }

    #[test]
    fn test_compile_separately() {
        let (prover_circuit, _) = build_test_circuit();
        let proof = prover_circuit
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            ))
            .unwrap();
        let (verifier_circuit, gate) = build_test_circuit();
        let public_inputs = verifier_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_compile_and_compress_separately() {
        let (prover_circuit, _) = build_test_circuit();
        let proof = prover_circuit
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 30.into()],
                vec![3.into(), 3.into(), 27.into(), 5.into()],
                vec![9.into(), 27.into(), 30.into(), 35.into()],
            ))
            .unwrap();
        let (verifier_circuit, gate) = build_test_circuit();
        let verifier_circuit = verifier_circuit.to_compressed();
        let public_inputs = verifier_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    fn test_gate(circuit: &Circuit, left: u64, right: u64, out: u64) -> Result<()> {
        let proof = circuit.prove(witness(
            vec![left.into()],
            vec![right.into()],
            vec![out.into()],
        ))?;
        circuit.verify(&proof).unwrap();
        Ok(())
    }

    #[test]
    fn test_const_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_const(42.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 41).is_err());
        assert!(test_gate(&circuit, 0, 0, 42).is_ok());
        assert!(test_gate(&circuit, 0, 0, 43).is_err());
    }

    #[test]
    fn test_sum_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_sum();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 34, 46).is_ok());
        assert!(test_gate(&circuit, 34, 12, 46).is_ok());
        assert!(test_gate(&circuit, 56, 78, 134).is_ok());
        assert!(test_gate(&circuit, 56, 34, 45).is_err());
        assert!(test_gate(&circuit, 12, 56, 46).is_err());
        assert!(test_gate(&circuit, 12, 34, 56).is_err());
    }

    #[test]
    fn test_sum_with_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_sum_with_const(12.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 0, 46).is_ok());
        assert!(test_gate(&circuit, 56, 0, 68).is_ok());
        assert!(test_gate(&circuit, 78, 0, 45).is_err());
        assert!(test_gate(&circuit, 90, 0, 45).is_err());
    }

    #[test]
    fn test_sum_with_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_sum_with_const(34.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 0, 68).is_ok());
        assert!(test_gate(&circuit, 56, 0, 90).is_ok());
        assert!(test_gate(&circuit, 78, 0, 45).is_err());
        assert!(test_gate(&circuit, 90, 0, 46).is_err());
    }

    #[test]
    fn test_sub_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 12, 22).is_ok());
        assert!(test_gate(&circuit, 56, 12, 44).is_ok());
        assert!(test_gate(&circuit, 56, 12, 22).is_err());
        assert!(test_gate(&circuit, 34, 56, 22).is_err());
        assert!(test_gate(&circuit, 34, 12, 56).is_err());
    }

    #[test]
    fn test_sub_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_const(12.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 0, 22).is_ok());
        assert!(test_gate(&circuit, 56, 0, 44).is_ok());
        assert!(test_gate(&circuit, 78, 0, 45).is_err());
        assert!(test_gate(&circuit, 90, 0, 46).is_err());
    }

    #[test]
    fn test_sub_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_const(34.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 0, 0).is_ok());
        assert!(test_gate(&circuit, 56, 0, 22).is_ok());
        assert!(test_gate(&circuit, 78, 0, 45).is_err());
        assert!(test_gate(&circuit, 90, 0, 46).is_err());
    }

    #[test]
    fn test_mul_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_mul();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 34, 408).is_ok());
        assert!(test_gate(&circuit, 34, 12, 408).is_ok());
        assert!(test_gate(&circuit, 56, 78, 4368).is_ok());
        assert!(test_gate(&circuit, 56, 34, 408).is_err());
        assert!(test_gate(&circuit, 12, 56, 408).is_err());
        assert!(test_gate(&circuit, 12, 34, 56).is_err());
    }

    #[test]
    fn test_mul_by_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_mul_by_const(12.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 1, 144).is_ok());
        assert!(test_gate(&circuit, 34, 1, 408).is_ok());
        assert!(test_gate(&circuit, 56, 1, 409).is_err());
        assert!(test_gate(&circuit, 78, 1, 410).is_err());
    }

    #[test]
    fn test_mul_by_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_mul_by_const(34.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 1, 408).is_ok());
        assert!(test_gate(&circuit, 34, 1, 1156).is_ok());
        assert!(test_gate(&circuit, 56, 1, 1157).is_err());
        assert!(test_gate(&circuit, 78, 1, 1158).is_err());
    }

    #[test]
    fn test_bool_assertion_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_bool_assertion();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 0).is_ok());
        assert!(test_gate(&circuit, 0, 1, 0).is_err());
        assert!(test_gate(&circuit, 1, 0, 0).is_err());
        assert!(test_gate(&circuit, 1, 1, 0).is_ok());
        assert!(test_gate(&circuit, 2, 2, 0).is_err());
        assert!(test_gate(&circuit, 3, 3, 0).is_err());
        assert!(test_gate(&circuit, 123, 123, 0).is_err());
    }

    #[test]
    fn test_not_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_not();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 0).is_err());
        assert!(test_gate(&circuit, 0, 0, 1).is_ok());
        assert!(test_gate(&circuit, 0, 1, 0).is_err());
        assert!(test_gate(&circuit, 0, 1, 1).is_err());
        assert!(test_gate(&circuit, 1, 0, 0).is_err());
        assert!(test_gate(&circuit, 1, 0, 1).is_err());
        assert!(test_gate(&circuit, 1, 1, 0).is_ok());
        assert!(test_gate(&circuit, 1, 1, 1).is_err());
    }

    #[test]
    fn test_and_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_and();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 0).is_ok());
        assert!(test_gate(&circuit, 0, 0, 1).is_err());
        assert!(test_gate(&circuit, 0, 1, 0).is_ok());
        assert!(test_gate(&circuit, 0, 1, 1).is_err());
        assert!(test_gate(&circuit, 1, 0, 0).is_ok());
        assert!(test_gate(&circuit, 1, 0, 1).is_err());
        assert!(test_gate(&circuit, 1, 1, 0).is_err());
        assert!(test_gate(&circuit, 1, 1, 1).is_ok());
    }

    #[test]
    fn test_or_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_or();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 0).is_ok());
        assert!(test_gate(&circuit, 0, 0, 1).is_err());
        assert!(test_gate(&circuit, 0, 1, 0).is_err());
        assert!(test_gate(&circuit, 0, 1, 1).is_ok());
        assert!(test_gate(&circuit, 1, 0, 0).is_err());
        assert!(test_gate(&circuit, 1, 0, 1).is_ok());
        assert!(test_gate(&circuit, 1, 1, 0).is_err());
        assert!(test_gate(&circuit, 1, 1, 1).is_ok());
    }

    #[test]
    fn test_xor_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_xor();
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 0).is_ok());
        assert!(test_gate(&circuit, 0, 0, 1).is_err());
        assert!(test_gate(&circuit, 0, 1, 0).is_err());
        assert!(test_gate(&circuit, 0, 1, 1).is_ok());
        assert!(test_gate(&circuit, 1, 0, 0).is_err());
        assert!(test_gate(&circuit, 1, 0, 1).is_ok());
        assert!(test_gate(&circuit, 1, 1, 0).is_ok());
        assert!(test_gate(&circuit, 1, 1, 1).is_err());
    }

    /// A slight variation of Vitalik's circuit. This one proves knowledge of three numbers x, y,
    /// and z such that x^3 + xy + 5 = z. Valid combinations are (3, 4, 44) and (4, 3, 81). This
    /// test circuit is meaningful because its size is not a power of 2 (it's 5), so it tests
    /// padding.
    fn build_uneven_size_circuit() -> (Circuit, u32) {
        let mut builder = CircuitBuilder::default();
        let gate1 = builder.add_mul();
        builder.connect(Wire::LeftIn(gate1), Wire::RightIn(gate1));
        let gate2 = builder.add_mul();
        builder.connect(Wire::LeftIn(gate2), Wire::Out(gate1));
        builder.connect(Wire::RightIn(gate2), Wire::LeftIn(gate1));
        let gate3 = builder.add_mul();
        builder.connect(Wire::LeftIn(gate3), Wire::LeftIn(gate1));
        let gate4 = builder.add_sum();
        builder.connect(Wire::LeftIn(gate4), Wire::Out(gate3));
        builder.connect(Wire::RightIn(gate4), Wire::Out(gate2));
        let gate5 = builder.add_sum();
        builder.connect(Wire::RightIn(gate5), Wire::Out(gate4));
        builder.declare_public_inputs([Wire::LeftIn(gate5), Wire::Out(gate5)]);
        (builder.build(), gate5)
    }

    #[test]
    fn test_uneven_size_circuit1() {
        let (circuit, gate) = build_uneven_size_circuit();
        let proof = circuit
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 12.into(), 5.into()],
                vec![3.into(), 3.into(), 4.into(), 27.into(), 39.into()],
                vec![9.into(), 27.into(), 12.into(), 39.into(), 44.into()],
            ))
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 44.into());
    }

    #[test]
    fn test_uneven_size_circuit2() {
        let (circuit, gate) = build_uneven_size_circuit();
        let proof = circuit
            .prove(witness(
                vec![4.into(), 16.into(), 4.into(), 12.into(), 5.into()],
                vec![4.into(), 4.into(), 3.into(), 64.into(), 76.into()],
                vec![16.into(), 64.into(), 12.into(), 76.into(), 81.into()],
            ))
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 81.into());
    }

    #[test]
    fn test_compile_uneven_size_circuit_separately() {
        let (prover_circuit, _) = build_uneven_size_circuit();
        let proof = prover_circuit
            .prove(witness(
                vec![3.into(), 9.into(), 3.into(), 12.into(), 5.into()],
                vec![3.into(), 3.into(), 4.into(), 27.into(), 39.into()],
                vec![9.into(), 27.into(), 12.into(), 39.into(), 44.into()],
            ))
            .unwrap();
        let (verifier_circuit, gate) = build_uneven_size_circuit();
        let public_inputs = verifier_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 44.into());
    }

    #[test]
    fn test_compile_and_compress_uneven_size_circuit_separately() {
        let (prover_circuit, _) = build_uneven_size_circuit();
        let proof = prover_circuit
            .prove(witness(
                vec![4.into(), 16.into(), 4.into(), 12.into(), 5.into()],
                vec![4.into(), 4.into(), 3.into(), 64.into(), 76.into()],
                vec![16.into(), 64.into(), 12.into(), 76.into(), 81.into()],
            ))
            .unwrap();
        let (verifier_circuit, gate) = build_uneven_size_circuit();
        let verifier_circuit = verifier_circuit.to_compressed();
        let public_inputs = verifier_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 81.into());
    }
}
