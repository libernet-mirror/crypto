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
    fn gate(&self) -> u32 {
        match *self {
            Self::LeftIn(gate) => gate,
            Self::RightIn(gate) => gate,
            Self::Out(gate) => gate,
        }
    }

    fn sigma_index(&self, n: usize) -> usize {
        match self {
            Wire::LeftIn(index) => *index as usize,
            Wire::RightIn(index) => *index as usize + n,
            Wire::Out(index) => *index as usize + n * 2,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireOrUnconstrained {
    Wire(Wire),
    Unconstrained(Scalar),
}

impl From<Wire> for WireOrUnconstrained {
    fn from(wire: Wire) -> Self {
        WireOrUnconstrained::Wire(wire)
    }
}

impl From<Scalar> for WireOrUnconstrained {
    fn from(value: Scalar) -> Self {
        WireOrUnconstrained::Unconstrained(value)
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

#[derive(Debug, Clone)]
pub struct Witness {
    size: usize,
    gate_counter: u32,
    left: Vec<Scalar>,
    right: Vec<Scalar>,
    out: Vec<Scalar>,
}

impl PartialEq for Witness {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size
            && self.left == other.left
            && self.right == other.right
            && self.out == other.out
    }
}

impl Eq for Witness {}

impl Witness {
    pub fn new(size: usize) -> Self {
        assert!(size <= u32::MAX as usize);
        let padded_size = padded_size(size);
        Self {
            size,
            gate_counter: 0,
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

    pub fn copy(&mut self, from: WireOrUnconstrained, to: Wire) -> Scalar {
        let value = match from {
            WireOrUnconstrained::Wire(from) => self.get(from),
            WireOrUnconstrained::Unconstrained(value) => value,
        };
        self.set(to, value);
        value
    }

    pub fn pop_gate(&mut self) -> u32 {
        let gate = self.gate_counter;
        self.gate_counter += 1;
        gate
    }

    pub fn assert_constant(&mut self, value: Scalar) -> Wire {
        let wire = Wire::Out(self.pop_gate());
        self.set(wire, value);
        wire
    }

    pub fn add(&mut self, lhs: WireOrUnconstrained, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs + rhs);
        out
    }

    pub fn add_const(&mut self, lhs: WireOrUnconstrained, rhs: Scalar) -> Wire {
        let gate = self.pop_gate();
        self.copy(lhs, Wire::LeftIn(gate));
        let lhs = self.copy(lhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs + rhs);
        out
    }

    pub fn sub(&mut self, lhs: WireOrUnconstrained, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs - rhs);
        out
    }

    pub fn sub_const(&mut self, lhs: WireOrUnconstrained, rhs: Scalar) -> Wire {
        let gate = self.pop_gate();
        self.copy(lhs, Wire::LeftIn(gate));
        let lhs = self.copy(lhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs - rhs);
        out
    }

    pub fn sub_from_const(&mut self, lhs: Scalar, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        self.copy(rhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs - rhs);
        out
    }

    pub fn mul(&mut self, lhs: WireOrUnconstrained, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs * rhs);
        out
    }

    pub fn square(&mut self, wire: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(wire, Wire::LeftIn(gate));
        let rhs = self.copy(wire, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs * rhs);
        out
    }

    pub fn mul_by_const(&mut self, lhs: WireOrUnconstrained, rhs: Scalar) -> Wire {
        let gate = self.pop_gate();
        self.copy(lhs, Wire::LeftIn(gate));
        let lhs = self.copy(lhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs * rhs);
        out
    }

    pub fn combine(
        &mut self,
        c1: Scalar,
        lhs: WireOrUnconstrained,
        c2: Scalar,
        rhs: WireOrUnconstrained,
    ) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, c1 * lhs + c2 * rhs);
        out
    }

    pub fn not(&mut self, input: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        self.copy(input, Wire::LeftIn(gate));
        let input = self.copy(input, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, Scalar::from(1) - input);
        out
    }

    pub fn and(&mut self, lhs: WireOrUnconstrained, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs * rhs);
        out
    }

    pub fn or(&mut self, lhs: WireOrUnconstrained, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs + rhs - lhs * rhs);
        out
    }

    pub fn xor(&mut self, lhs: WireOrUnconstrained, rhs: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        let lhs = self.copy(lhs, Wire::LeftIn(gate));
        let rhs = self.copy(rhs, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, lhs + rhs - Scalar::from(2) * lhs * rhs);
        out
    }
}

#[derive(Debug, Default)]
pub struct CircuitBuilder {
    gates: Vec<GateConstraint>,
    wires: WirePartitioning,
    public_inputs: BTreeSet<Wire>,
}

impl CircuitBuilder {
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    pub fn gate_count(&self) -> u32 {
        let len = self.len();
        assert!(len <= u32::MAX as usize);
        len as u32
    }

    pub fn add_raw_gate(
        &mut self,
        ql: Scalar,
        qr: Scalar,
        qo: Scalar,
        qm: Scalar,
        qc: Scalar,
    ) -> u32 {
        let index = self.gates.len();
        assert!(index <= u32::MAX as usize);
        self.gates.push(GateConstraint { ql, qr, qo, qm, qc });
        index as u32
    }

    pub fn connect(&mut self, wire1: Wire, wire2: Wire) {
        self.wires.connect(wire1, wire2);
    }

    pub fn add_unary_gate(
        &mut self,
        ql: Scalar,
        qr: Scalar,
        qo: Scalar,
        qm: Scalar,
        qc: Scalar,
        input: Option<Wire>,
    ) -> Wire {
        let gate = self.add_raw_gate(ql, qr, qo, qm, qc);
        self.connect(Wire::LeftIn(gate), Wire::RightIn(gate));
        if let Some(input) = input {
            self.connect(input, Wire::LeftIn(gate));
        }
        Wire::Out(gate)
    }

    pub fn add_binary_gate(
        &mut self,
        ql: Scalar,
        qr: Scalar,
        qo: Scalar,
        qm: Scalar,
        qc: Scalar,
        lhs: Option<Wire>,
        rhs: Option<Wire>,
    ) -> Wire {
        let gate = self.add_raw_gate(ql, qr, qo, qm, qc);
        if let Some(lhs) = lhs {
            self.connect(lhs, Wire::LeftIn(gate));
        }
        if let Some(rhs) = rhs {
            self.connect(rhs, Wire::RightIn(gate));
        }
        Wire::Out(gate)
    }

    pub fn add_const_gate(&mut self, value: Scalar) -> Wire {
        Wire::Out(self.add_raw_gate(0.into(), 0.into(), 1.into(), 0.into(), -value))
    }

    pub fn add_sum_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            1.into(),
            1.into(),
            -Scalar::from(1),
            0.into(),
            0.into(),
            lhs,
            rhs,
        )
    }

    pub fn add_sum_with_const_gate(&mut self, lhs: Option<Wire>, c: Scalar) -> Wire {
        self.add_unary_gate(1.into(), 0.into(), -Scalar::from(1), 0.into(), c, lhs)
    }

    pub fn add_sub_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            1.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            0.into(),
            0.into(),
            lhs,
            rhs,
        )
    }

    pub fn add_sub_const_gate(&mut self, lhs: Option<Wire>, c: Scalar) -> Wire {
        self.add_unary_gate(1.into(), 0.into(), -Scalar::from(1), 0.into(), -c, lhs)
    }

    pub fn add_sub_from_const_gate(&mut self, c: Scalar, rhs: Option<Wire>) -> Wire {
        self.add_unary_gate(
            0.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            0.into(),
            c,
            rhs,
        )
    }

    pub fn add_mul_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            0.into(),
            0.into(),
            -Scalar::from(1),
            1.into(),
            0.into(),
            lhs,
            rhs,
        )
    }

    pub fn add_square_gate(&mut self, input: Option<Wire>) -> Wire {
        self.add_unary_gate(
            0.into(),
            0.into(),
            1.into(),
            -Scalar::from(1),
            0.into(),
            input,
        )
    }

    pub fn add_mul_by_const_gate(&mut self, lhs: Option<Wire>, c: Scalar) -> Wire {
        self.add_unary_gate(c, 0.into(), -Scalar::from(1), 0.into(), 0.into(), lhs)
    }

    pub fn add_linear_combination_gate(
        &mut self,
        c1: Scalar,
        lhs: Option<Wire>,
        c2: Scalar,
        rhs: Option<Wire>,
    ) -> Wire {
        self.add_binary_gate(c1, c2, -Scalar::from(1), 0.into(), 0.into(), lhs, rhs)
    }

    pub fn add_bool_assertion_gate(&mut self, input: Option<Wire>) {
        self.add_unary_gate(
            1.into(),
            0.into(),
            0.into(),
            -Scalar::from(1),
            0.into(),
            input,
        );
    }

    pub fn add_not_gate(&mut self, input: Option<Wire>) -> Wire {
        self.add_unary_gate(
            -Scalar::from(1),
            0.into(),
            -Scalar::from(1),
            0.into(),
            1.into(),
            input,
        )
    }

    pub fn add_and_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            0.into(),
            0.into(),
            -Scalar::from(1),
            1.into(),
            0.into(),
            lhs,
            rhs,
        )
    }

    pub fn add_or_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            1.into(),
            1.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            0.into(),
            lhs,
            rhs,
        )
    }

    pub fn add_xor_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            1.into(),
            1.into(),
            -Scalar::from(1),
            -Scalar::from(2),
            0.into(),
            lhs,
            rhs,
        )
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
    fn build(
        &self,
        builder: &mut CircuitBuilder,
        inputs: [Option<Wire>; I],
    ) -> Result<[Option<Wire>; O]>;

    fn witness(
        &self,
        witness: &mut Witness,
        inputs: [WireOrUnconstrained; I],
    ) -> Result<[WireOrUnconstrained; O]>;
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            witness.copy(Wire::RightIn(0).into(), Wire::Out(0)),
            34.into()
        );
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
        assert_eq!(
            witness.copy(Wire::RightIn(0).into(), Wire::LeftIn(1)),
            34.into()
        );
        assert_eq!(
            witness.copy(Wire::LeftIn(0).into(), Wire::RightIn(1)),
            12.into()
        );
        witness.set(Wire::Out(1), 56.into());
        assert_eq!(witness.size(), 2);
        assert_eq!(witness.get(Wire::LeftIn(0)), 12.into());
        assert_eq!(witness.get(Wire::RightIn(0)), 34.into());
        assert_eq!(witness.get(Wire::Out(0)), 56.into());
        assert_eq!(witness.get(Wire::LeftIn(1)), 34.into());
        assert_eq!(witness.get(Wire::RightIn(1)), 12.into());
        assert_eq!(witness.get(Wire::Out(1)), 56.into());
    }

    fn test_witness_assert_constant_impl(value: u64) {
        let mut witness = Witness::new(1);
        let wire = witness.assert_constant(value.into());
        assert_eq!(wire, Wire::Out(0));
        assert_eq!(witness.get(wire), value.into());
    }

    #[test]
    fn test_witness_assert_constant() {
        test_witness_assert_constant_impl(42);
        test_witness_assert_constant_impl(43);
        test_witness_assert_constant_impl(44);
    }

    fn test_witness_add_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(2);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.add(Wire::LeftIn(0).into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_add() {
        test_witness_add_impl(12, 34, 46);
        test_witness_add_impl(34, 12, 46);
        test_witness_add_impl(56, 78, 134);
    }

    fn test_witness_unconstrained_add_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        assert_eq!(
            witness.add(
                WireOrUnconstrained::Unconstrained(lhs.into()),
                WireOrUnconstrained::Unconstrained(rhs.into())
            ),
            Wire::Out(0)
        );
        assert_eq!(witness.get(Wire::LeftIn(0)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(0)), rhs.into());
        assert_eq!(witness.get(Wire::Out(0)), out.into());
    }

    #[test]
    fn test_witness_unconstrained_add() {
        test_witness_unconstrained_add_impl(12, 34, 46);
        test_witness_unconstrained_add_impl(34, 12, 46);
        test_witness_unconstrained_add_impl(56, 78, 134);
    }

    fn test_witness_add_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        assert_eq!(
            witness.add_const(Wire::LeftIn(0).into(), rhs.into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_add_const() {
        test_witness_add_const_impl(12, 34, 46);
        test_witness_add_const_impl(34, 12, 46);
        test_witness_add_const_impl(56, 78, 134);
    }

    fn test_witness_unconstrained_add_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.set(Wire::LeftIn(0), lhs.into());
        assert_eq!(
            witness.add_const(WireOrUnconstrained::Unconstrained(lhs.into()), rhs.into()),
            Wire::Out(0)
        );
        assert_eq!(witness.get(Wire::LeftIn(0)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(0)), lhs.into());
        assert_eq!(witness.get(Wire::Out(0)), out.into());
    }

    #[test]
    fn test_witness_unconstrained_add_const() {
        test_witness_unconstrained_add_const_impl(12, 34, 46);
        test_witness_unconstrained_add_const_impl(34, 12, 46);
        test_witness_unconstrained_add_const_impl(56, 78, 134);
    }

    fn test_witness_sub_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(2);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.sub(Wire::LeftIn(0).into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_sub() {
        test_witness_sub_impl(34, 12, 22);
        test_witness_sub_impl(78, 56, 22);
        test_witness_sub_impl(78, 34, 44);
    }

    fn test_witness_sub_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        assert_eq!(
            witness.sub_const(Wire::LeftIn(0).into(), rhs.into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_sub_const() {
        test_witness_sub_const_impl(34, 12, 22);
        test_witness_sub_const_impl(78, 56, 22);
        test_witness_sub_const_impl(78, 34, 44);
    }

    fn test_witness_sub_from_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.sub_from_const(lhs.into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_sub_from_const() {
        test_witness_sub_from_const_impl(34, 12, 22);
        test_witness_sub_from_const_impl(78, 56, 22);
        test_witness_sub_from_const_impl(78, 34, 44);
    }

    fn test_witness_mul_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.mul(Wire::LeftIn(0).into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_mul() {
        test_witness_mul_impl(12, 34, 408);
        test_witness_mul_impl(34, 12, 408);
        test_witness_mul_impl(56, 78, 4368);
    }

    fn test_witness_square_impl(input: u64, output: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), input.into());
        assert_eq!(witness.square(Wire::LeftIn(0).into()), Wire::Out(1));
        assert_eq!(witness.get(Wire::LeftIn(1)), input.into());
        assert_eq!(witness.get(Wire::RightIn(1)), input.into());
        assert_eq!(witness.get(Wire::Out(1)), output.into());
    }

    #[test]
    fn test_witness_square() {
        test_witness_square_impl(0, 0);
        test_witness_square_impl(1, 1);
        test_witness_square_impl(2, 4);
        test_witness_square_impl(3, 9);
    }

    fn test_witness_mul_by_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        assert_eq!(
            witness.mul_by_const(Wire::LeftIn(0).into(), rhs.into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_mul_by_const() {
        test_witness_mul_by_const_impl(12, 34, 408);
        test_witness_mul_by_const_impl(34, 12, 408);
        test_witness_mul_by_const_impl(56, 78, 4368);
    }

    fn test_witness_combine_impl(c1: u64, lhs: u64, c2: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.combine(
                c1.into(),
                Wire::LeftIn(0).into(),
                c2.into(),
                Wire::RightIn(0).into()
            ),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_combine() {
        test_witness_combine_impl(1, 2, 3, 4, 14);
        test_witness_combine_impl(5, 6, 7, 8, 86);
        test_witness_combine_impl(12, 34, 56, 78, 4776);
        test_witness_combine_impl(34, 12, 56, 78, 4776);
        test_witness_combine_impl(12, 34, 78, 56, 4776);
        test_witness_combine_impl(56, 78, 12, 34, 4776);
    }

    fn test_witness_not_impl(input: Scalar, output: Scalar) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), input.into());
        assert_eq!(witness.not(input.into()), Wire::Out(1));
        assert_eq!(witness.get(Wire::LeftIn(1)), input.into());
        assert_eq!(witness.get(Wire::RightIn(1)), input.into());
        assert_eq!(witness.get(Wire::Out(1)), output.into());
    }

    #[test]
    fn test_witness_not() {
        test_witness_not_impl(0.into(), 1.into());
        test_witness_not_impl(1.into(), 0.into());
    }

    fn test_witness_and_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.and(Wire::LeftIn(0).into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_and() {
        test_witness_and_impl(0, 0, 0);
        test_witness_and_impl(0, 1, 0);
        test_witness_and_impl(1, 0, 0);
        test_witness_and_impl(1, 1, 1);
    }

    fn test_witness_or_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.or(Wire::LeftIn(0).into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_or() {
        test_witness_or_impl(0, 0, 0);
        test_witness_or_impl(0, 1, 1);
        test_witness_or_impl(1, 0, 1);
        test_witness_or_impl(1, 1, 1);
    }

    fn test_witness_xor_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), lhs.into());
        witness.set(Wire::RightIn(0), rhs.into());
        assert_eq!(
            witness.xor(Wire::LeftIn(0).into(), Wire::RightIn(0).into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(1)), rhs.into());
        assert_eq!(witness.get(Wire::Out(1)), out.into());
    }

    #[test]
    fn test_witness_xor() {
        test_witness_xor_impl(0, 0, 0);
        test_witness_xor_impl(0, 1, 1);
        test_witness_xor_impl(1, 0, 1);
        test_witness_xor_impl(1, 1, 0);
    }

    /// Builds the circuit at https://vitalik.eth.limo/general/2019/09/22/plonk.html.
    fn build_test_circuit() -> (Circuit, u32) {
        let mut builder = CircuitBuilder::default();
        let gate1 = builder.add_raw_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into());
        builder.connect(Wire::LeftIn(gate1), Wire::RightIn(gate1));
        let gate2 = builder.add_raw_gate(0.into(), 0.into(), -Scalar::from(1), 1.into(), 0.into());
        builder.connect(Wire::LeftIn(gate2), Wire::Out(gate1));
        builder.connect(Wire::RightIn(gate2), Wire::LeftIn(gate1));
        let gate3 = builder.add_raw_gate(1.into(), 1.into(), -Scalar::from(1), 0.into(), 0.into());
        builder.connect(Wire::LeftIn(gate3), Wire::LeftIn(gate1));
        builder.connect(Wire::RightIn(gate3), Wire::Out(gate2));
        let gate4 = builder.add_raw_gate(1.into(), 1.into(), -Scalar::from(1), 0.into(), 0.into());
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
            gate_counter: 0,
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
        let input = Wire::LeftIn(builder.gate_count());
        let gate1 = builder.add_square_gate(input.into());
        let gate2 = builder.add_mul_gate(gate1.into(), input.into());
        let gate3 = builder.add_sum_gate(input.into(), gate2.into());
        let gate4 = builder.add_sum_with_const_gate(gate3.into(), 5.into());
        builder.declare_public_inputs([gate4]);
        let witness = witness(
            vec![3.into(), 9.into(), 3.into(), 30.into()],
            vec![3.into(), 3.into(), 27.into(), 30.into()],
            vec![9.into(), 27.into(), 30.into(), 35.into()],
        );
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&gate4).unwrap(), 35.into());
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

    fn test_connected_unary_gate(circuit: &Circuit, input: u64, output: u64) -> Result<()> {
        let proof = circuit.prove(witness(
            vec![0.into(), input.into()],
            vec![0.into(), input.into()],
            vec![input.into(), output.into()],
        ))?;
        circuit.verify(&proof).unwrap();
        Ok(())
    }

    fn test_connected_binary_gate(
        circuit: &Circuit,
        left: u64,
        right: u64,
        out: u64,
    ) -> Result<()> {
        let proof = circuit.prove(witness(
            vec![0.into(), 0.into(), left.into()],
            vec![0.into(), 0.into(), right.into()],
            vec![left.into(), right.into(), out.into()],
        ))?;
        circuit.verify(&proof).unwrap();
        Ok(())
    }

    #[test]
    fn test_const_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_const_gate(42.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 0, 0, 41).is_err());
        assert!(test_gate(&circuit, 0, 0, 42).is_ok());
        assert!(test_gate(&circuit, 0, 0, 43).is_err());
    }

    #[test]
    fn test_sum_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_sum_gate(None, None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 34, 46).is_ok());
        assert!(test_gate(&circuit, 34, 12, 46).is_ok());
        assert!(test_gate(&circuit, 56, 78, 134).is_ok());
        assert!(test_gate(&circuit, 56, 34, 45).is_err());
        assert!(test_gate(&circuit, 12, 56, 46).is_err());
        assert!(test_gate(&circuit, 12, 34, 56).is_err());
    }

    #[test]
    fn test_connected_sum_gate() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(123.into());
        let rhs = builder.add_const_gate(456.into());
        builder.add_sum_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 123, 456, 579).is_ok());
        assert!(test_connected_binary_gate(&circuit, 123, 456, 975).is_err());
        assert!(test_connected_binary_gate(&circuit, 321, 456, 579).is_err());
        assert!(test_connected_binary_gate(&circuit, 123, 654, 579).is_err());
    }

    #[test]
    fn test_sum_with_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_sum_with_const_gate(None, 12.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 34, 46).is_ok());
        assert!(test_gate(&circuit, 34, 56, 46).is_err());
        assert!(test_gate(&circuit, 56, 56, 68).is_ok());
        assert!(test_gate(&circuit, 56, 78, 68).is_err());
        assert!(test_gate(&circuit, 78, 78, 45).is_err());
        assert!(test_gate(&circuit, 90, 90, 45).is_err());
    }

    #[test]
    fn test_sum_with_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_sum_with_const_gate(None, 34.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 34, 68).is_ok());
        assert!(test_gate(&circuit, 34, 56, 68).is_err());
        assert!(test_gate(&circuit, 56, 56, 90).is_ok());
        assert!(test_gate(&circuit, 56, 78, 90).is_err());
        assert!(test_gate(&circuit, 78, 78, 45).is_err());
        assert!(test_gate(&circuit, 90, 90, 46).is_err());
    }

    #[test]
    fn test_connected_sum_with_const_gate1() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(34.into());
        builder.add_sum_with_const_gate(input.into(), 12.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 34, 46).is_ok());
        assert!(test_connected_unary_gate(&circuit, 34, 56).is_err());
    }

    #[test]
    fn test_connected_sum_with_const_gate2() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(56.into());
        builder.add_sum_with_const_gate(input.into(), 34.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 56, 90).is_ok());
        assert!(test_connected_unary_gate(&circuit, 56, 78).is_err());
    }

    #[test]
    fn test_sub_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_gate(None, None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 12, 22).is_ok());
        assert!(test_gate(&circuit, 56, 12, 44).is_ok());
        assert!(test_gate(&circuit, 56, 12, 22).is_err());
        assert!(test_gate(&circuit, 34, 56, 22).is_err());
        assert!(test_gate(&circuit, 34, 12, 56).is_err());
    }

    #[test]
    fn test_connected_sub_gate() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(456.into());
        let rhs = builder.add_const_gate(123.into());
        builder.add_sub_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 456, 123, 333).is_ok());
        assert!(test_connected_binary_gate(&circuit, 456, 123, 999).is_err());
        assert!(test_connected_binary_gate(&circuit, 654, 123, 333).is_err());
        assert!(test_connected_binary_gate(&circuit, 456, 321, 333).is_err());
    }

    #[test]
    fn test_sub_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_const_gate(None, 12.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 34, 22).is_ok());
        assert!(test_gate(&circuit, 34, 56, 22).is_err());
        assert!(test_gate(&circuit, 56, 56, 44).is_ok());
        assert!(test_gate(&circuit, 56, 78, 44).is_err());
        assert!(test_gate(&circuit, 78, 78, 45).is_err());
        assert!(test_gate(&circuit, 90, 90, 46).is_err());
    }

    #[test]
    fn test_sub_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_const_gate(None, 34.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 34, 0).is_ok());
        assert!(test_gate(&circuit, 34, 56, 0).is_err());
        assert!(test_gate(&circuit, 56, 56, 22).is_ok());
        assert!(test_gate(&circuit, 56, 78, 22).is_err());
        assert!(test_gate(&circuit, 78, 78, 45).is_err());
        assert!(test_gate(&circuit, 90, 90, 46).is_err());
    }

    #[test]
    fn test_connected_sub_const_gate1() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(34.into());
        builder.add_sub_const_gate(input.into(), 12.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 34, 22).is_ok());
        assert!(test_connected_unary_gate(&circuit, 34, 56).is_err());
    }

    #[test]
    fn test_connected_sub_const_gate2() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(56.into());
        builder.add_sub_const_gate(input.into(), 34.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 56, 22).is_ok());
        assert!(test_connected_unary_gate(&circuit, 56, 78).is_err());
    }

    #[test]
    fn test_sub_from_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_from_const_gate(90.into(), None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 34, 56).is_ok());
        assert!(test_gate(&circuit, 34, 56, 56).is_err());
        assert!(test_gate(&circuit, 56, 56, 34).is_ok());
        assert!(test_gate(&circuit, 56, 78, 34).is_err());
        assert!(test_gate(&circuit, 78, 78, 13).is_err());
        assert!(test_gate(&circuit, 90, 90, 14).is_err());
    }

    #[test]
    fn test_sub_from_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_sub_from_const_gate(78.into(), None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 12, 66).is_ok());
        assert!(test_gate(&circuit, 12, 34, 66).is_err());
        assert!(test_gate(&circuit, 34, 34, 44).is_ok());
        assert!(test_gate(&circuit, 34, 56, 44).is_err());
        assert!(test_gate(&circuit, 56, 56, 23).is_err());
        assert!(test_gate(&circuit, 78, 78, 24).is_err());
    }

    #[test]
    fn test_connected_sub_from_const_gate1() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(34.into());
        builder.add_sub_from_const_gate(90.into(), input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 34, 56).is_ok());
        assert!(test_connected_unary_gate(&circuit, 34, 78).is_err());
    }

    #[test]
    fn test_connected_sub_from_const_gate2() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(12.into());
        builder.add_sub_from_const_gate(78.into(), input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 12, 66).is_ok());
        assert!(test_connected_unary_gate(&circuit, 12, 34).is_err());
    }

    #[test]
    fn test_mul_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_mul_gate(None, None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 34, 408).is_ok());
        assert!(test_gate(&circuit, 34, 12, 408).is_ok());
        assert!(test_gate(&circuit, 56, 78, 4368).is_ok());
        assert!(test_gate(&circuit, 56, 34, 408).is_err());
        assert!(test_gate(&circuit, 12, 56, 408).is_err());
        assert!(test_gate(&circuit, 12, 34, 56).is_err());
    }

    #[test]
    fn test_connected_mul_gate() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(12.into());
        let rhs = builder.add_const_gate(34.into());
        builder.add_mul_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 12, 34, 408).is_ok());
        assert!(test_connected_binary_gate(&circuit, 12, 34, 804).is_err());
    }

    #[test]
    fn test_mul_by_const_gate1() {
        let mut builder = CircuitBuilder::default();
        builder.add_mul_by_const_gate(None, 12.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 12, 144).is_ok());
        assert!(test_gate(&circuit, 12, 34, 144).is_err());
        assert!(test_gate(&circuit, 34, 34, 408).is_ok());
        assert!(test_gate(&circuit, 34, 56, 408).is_err());
        assert!(test_gate(&circuit, 56, 56, 409).is_err());
        assert!(test_gate(&circuit, 78, 78, 410).is_err());
    }

    #[test]
    fn test_mul_by_const_gate2() {
        let mut builder = CircuitBuilder::default();
        builder.add_mul_by_const_gate(None, 34.into());
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 12, 408).is_ok());
        assert!(test_gate(&circuit, 12, 34, 408).is_err());
        assert!(test_gate(&circuit, 34, 34, 1156).is_ok());
        assert!(test_gate(&circuit, 34, 56, 1156).is_err());
        assert!(test_gate(&circuit, 56, 56, 1157).is_err());
        assert!(test_gate(&circuit, 78, 78, 1158).is_err());
    }

    #[test]
    fn test_connected_mul_by_const_gate1() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(12.into());
        builder.add_mul_by_const_gate(lhs.into(), 34.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 12, 408).is_ok());
        assert!(test_connected_unary_gate(&circuit, 12, 804).is_err());
    }

    #[test]
    fn test_connected_mul_by_const_gate2() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(34.into());
        builder.add_mul_by_const_gate(lhs.into(), 12.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 34, 408).is_ok());
        assert!(test_connected_unary_gate(&circuit, 34, 804).is_err());
    }

    #[test]
    fn test_linear_combination_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_linear_combination_gate(12.into(), None, 56.into(), None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 34, 78, 4776).is_ok());
        assert!(test_gate(&circuit, 78, 90, 5976).is_ok());
        assert!(test_gate(&circuit, 42, 78, 4776).is_err());
        assert!(test_gate(&circuit, 34, 42, 4776).is_err());
        assert!(test_gate(&circuit, 34, 78, 42).is_err());
    }

    #[test]
    fn test_connected_linear_combination_gate() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(34.into());
        let rhs = builder.add_const_gate(78.into());
        builder.add_linear_combination_gate(12.into(), lhs.into(), 56.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 34, 78, 4776).is_ok());
        assert!(test_connected_binary_gate(&circuit, 34, 78, 7647).is_err());
    }

    #[test]
    fn test_bool_assertion_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_bool_assertion_gate(None);
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
    fn test_connected_bool_assertion_gate1() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(0.into());
        builder.add_bool_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 0, 0).is_ok());
    }

    #[test]
    fn test_connected_bool_assertion_gate2() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(1.into());
        builder.add_bool_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 1, 0).is_ok());
    }

    #[test]
    fn test_connected_bool_assertion_gate3() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(2.into());
        builder.add_bool_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 2, 0).is_err());
    }

    #[test]
    fn test_not_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_not_gate(None);
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
    fn test_connected_not_gate() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(0.into());
        builder.add_not_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 0, 1).is_ok());
        assert!(test_connected_unary_gate(&circuit, 1, 1).is_err());
        assert!(test_connected_unary_gate(&circuit, 0, 0).is_err());
    }

    #[test]
    fn test_and_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_and_gate(None, None);
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
    fn test_connected_and_gate1() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(0.into());
        let rhs = builder.add_const_gate(1.into());
        builder.add_and_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 0, 1, 0).is_ok());
        assert!(test_connected_binary_gate(&circuit, 0, 1, 1).is_err());
    }

    #[test]
    fn test_connected_and_gate2() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(1.into());
        let rhs = builder.add_const_gate(1.into());
        builder.add_and_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 1, 1, 1).is_ok());
        assert!(test_connected_binary_gate(&circuit, 1, 1, 0).is_err());
    }

    #[test]
    fn test_or_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_or_gate(None, None);
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
    fn test_connected_or_gate1() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(0.into());
        let rhs = builder.add_const_gate(0.into());
        builder.add_or_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 0, 0, 0).is_ok());
        assert!(test_connected_binary_gate(&circuit, 0, 0, 1).is_err());
    }

    #[test]
    fn test_connected_or_gate2() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(0.into());
        let rhs = builder.add_const_gate(1.into());
        builder.add_or_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 0, 1, 1).is_ok());
        assert!(test_connected_binary_gate(&circuit, 0, 1, 0).is_err());
    }

    #[test]
    fn test_xor_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_xor_gate(None, None);
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

    #[test]
    fn test_connected_xor_gate1() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(0.into());
        let rhs = builder.add_const_gate(1.into());
        builder.add_xor_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 0, 1, 1).is_ok());
        assert!(test_connected_binary_gate(&circuit, 0, 1, 0).is_err());
    }

    #[test]
    fn test_connected_xor_gate2() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(1.into());
        let rhs = builder.add_const_gate(1.into());
        builder.add_xor_gate(lhs.into(), rhs.into());
        let circuit = builder.build();
        assert!(test_connected_binary_gate(&circuit, 1, 1, 0).is_ok());
        assert!(test_connected_binary_gate(&circuit, 1, 1, 1).is_err());
    }

    /// A slight variation of Vitalik's circuit. This one proves knowledge of three numbers x, y,
    /// and z such that x^3 + xy + 5 = z. Valid combinations are (3, 4, 44) and (4, 3, 81). This
    /// test circuit is meaningful because its size is not a power of 2 (it's 5), so it tests
    /// padding.
    fn build_uneven_size_circuit() -> (Circuit, u32) {
        let mut builder = CircuitBuilder::default();
        let input = Wire::LeftIn(builder.gate_count());
        let gate1 = builder.add_square_gate(input.into());
        let gate2 = builder.add_mul_gate(gate1.into(), input.into());
        let gate3 = builder.add_mul_gate(input.into(), None);
        let gate4 = builder.add_sum_gate(gate3.into(), gate2.into());
        let gate5 = builder.add_sum_gate(None, gate4.into());
        builder.declare_public_inputs([Wire::LeftIn(gate5.gate()), gate5]);
        (builder.build(), gate5.gate())
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
