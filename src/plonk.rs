use crate::bluesky::Scalar;
use crate::pcs;
use crate::poly;
use anyhow::Result;
use ff::Field;
use std::collections::{BTreeMap, BTreeSet, btree_map};

type Polynomial = poly::Polynomial<Scalar>;

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

/// A "wire" is the left input, right input, or output termination of a gate.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Wire {
    LeftIn(u32),
    RightIn(u32),
    Out(u32),
}

impl Wire {
    pub fn gate(&self) -> u32 {
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

    pub fn poly2(
        &mut self,
        c1: Scalar,
        c2: Scalar,
        c3: Scalar,
        input: WireOrUnconstrained,
    ) -> Wire {
        let gate = self.pop_gate();
        self.copy(input, Wire::LeftIn(gate));
        let input = self.copy(input, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, c1 * input.square() + c2 * input + c3);
        out
    }

    pub fn assert_bit(&mut self, input: WireOrUnconstrained) {
        let gate = self.pop_gate();
        self.copy(input, Wire::LeftIn(gate));
        self.copy(input, Wire::RightIn(gate));
    }

    pub fn assert_trit(&mut self, input: WireOrUnconstrained) {
        let lhs = self.poly2(1.into(), -Scalar::from(3), 2.into(), input);
        let gate = self.pop_gate();
        self.copy(lhs.into(), Wire::LeftIn(gate));
        self.copy(input, Wire::RightIn(gate));
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
    /// Returns the size of the circuit built so far.
    pub fn len(&self) -> usize {
        self.gates.len()
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

    pub fn add_poly2_gate(
        &mut self,
        c1: Scalar,
        c2: Scalar,
        c3: Scalar,
        input: Option<Wire>,
    ) -> Wire {
        self.add_unary_gate(c2, 0.into(), -Scalar::from(1), c1, c3, input)
    }

    pub fn add_bit_assertion_gate(&mut self, input: Option<Wire>) {
        self.add_unary_gate(
            1.into(),
            0.into(),
            0.into(),
            -Scalar::from(1),
            0.into(),
            input,
        );
    }

    pub fn add_trit_assertion_gate(&mut self, input: Option<Wire>) {
        let lhs = self.add_poly2_gate(1.into(), -Scalar::from(3), 2.into(), input);
        self.add_binary_gate(
            0.into(),
            0.into(),
            0.into(),
            1.into(),
            0.into(),
            lhs.into(),
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
        let omega = Polynomial::domain_element2(1, n);
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
        let ql = self
            .gates
            .iter()
            .map(|gate| gate.ql)
            .chain(std::iter::repeat_n(Scalar::ZERO, pad))
            .collect();
        let qr = self
            .gates
            .iter()
            .map(|gate| gate.qr)
            .chain(std::iter::repeat_n(Scalar::ZERO, pad))
            .collect();
        let qo = self
            .gates
            .iter()
            .map(|gate| gate.qo)
            .chain(std::iter::repeat_n(Scalar::ZERO, pad))
            .collect();
        let qm = self
            .gates
            .iter()
            .map(|gate| gate.qm)
            .chain(std::iter::repeat_n(Scalar::ZERO, pad))
            .collect();
        let qc = self
            .gates
            .iter()
            .map(|gate| gate.qc)
            .chain(std::iter::repeat_n(Scalar::ZERO, pad))
            .collect();
        let (sl, sr, so) = self.build_identity_permutation();
        Circuit {
            size: n,
            public_inputs: self.public_inputs,
            ql,
            qr,
            qo,
            qm,
            qc,
            sl,
            sr,
            so,
        }
    }

    pub fn check_witness(&self, witness: &Witness) -> Result<()> {
        // TODO
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct Proof<H: pcs::Hash> {
    witness_commitments: [pcs::Commitment; 3],
    public_inputs: BTreeMap<Wire, Scalar>,
    permutation_accumulator_commitment: pcs::Commitment,
    quotient_commitment: pcs::Commitment,
    proof: pcs::Proof<H>,
}

#[derive(Debug, Clone)]
pub struct Circuit {
    size: usize,
    public_inputs: BTreeSet<Wire>,
    ql: Vec<Scalar>,
    qr: Vec<Scalar>,
    qo: Vec<Scalar>,
    qm: Vec<Scalar>,
    qc: Vec<Scalar>,
    sl: Vec<Scalar>,
    sr: Vec<Scalar>,
    so: Vec<Scalar>,
}

impl Circuit {
    pub fn size(&self) -> usize {
        self.size
    }

    // TODO
}

#[derive(Debug, Clone)]
pub struct CompressedCircuit {
    original_size: usize,
    ql: pcs::Commitment,
    qr: pcs::Commitment,
    qo: pcs::Commitment,
    qm: pcs::Commitment,
    qc: pcs::Commitment,
    sl: pcs::Commitment,
    sr: pcs::Commitment,
    so: pcs::Commitment,
}

impl CompressedCircuit {
    pub fn original_size(&self) -> usize {
        self.original_size
    }

    // TODO
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
        let mut witness = Witness::new(2);
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

    fn test_witness_unconstrained_sub_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        assert_eq!(
            witness.sub(
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
    fn test_witness_unconstrained_sub() {
        test_witness_unconstrained_sub_impl(34, 12, 22);
        test_witness_unconstrained_sub_impl(78, 56, 22);
        test_witness_unconstrained_sub_impl(78, 34, 44);
    }

    fn test_witness_sub_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(2);
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

    fn test_witness_unconstrained_sub_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.set(Wire::LeftIn(0), lhs.into());
        assert_eq!(
            witness.sub_const(WireOrUnconstrained::Unconstrained(lhs.into()), rhs.into()),
            Wire::Out(0)
        );
        assert_eq!(witness.get(Wire::LeftIn(0)), lhs.into());
        assert_eq!(witness.get(Wire::RightIn(0)), lhs.into());
        assert_eq!(witness.get(Wire::Out(0)), out.into());
    }

    #[test]
    fn test_witness_unconstrained_sub_const() {
        test_witness_unconstrained_sub_const_impl(34, 12, 22);
        test_witness_unconstrained_sub_const_impl(78, 56, 22);
        test_witness_unconstrained_sub_const_impl(78, 34, 44);
    }

    fn test_witness_sub_from_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(2);
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

    fn test_witness_unconstrained_sub_from_const_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        witness.set(Wire::LeftIn(0), lhs.into());
        assert_eq!(
            witness.sub_from_const(lhs.into(), WireOrUnconstrained::Unconstrained(rhs.into())),
            Wire::Out(0)
        );
        assert_eq!(witness.get(Wire::LeftIn(0)), rhs.into());
        assert_eq!(witness.get(Wire::RightIn(0)), rhs.into());
        assert_eq!(witness.get(Wire::Out(0)), out.into());
    }

    #[test]
    fn test_witness_unconstrained_sub_from_const() {
        test_witness_unconstrained_sub_from_const_impl(34, 12, 22);
        test_witness_unconstrained_sub_from_const_impl(78, 56, 22);
        test_witness_unconstrained_sub_from_const_impl(78, 34, 44);
    }

    fn test_witness_mul_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(2);
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

    fn test_witness_unconstrained_mul_impl(lhs: u64, rhs: u64, out: u64) {
        let mut witness = Witness::new(1);
        assert_eq!(
            witness.mul(
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
    fn test_witness_unconstrained_mul() {
        test_witness_unconstrained_mul_impl(12, 34, 408);
        test_witness_unconstrained_mul_impl(34, 12, 408);
        test_witness_unconstrained_mul_impl(56, 78, 4368);
    }

    fn test_witness_square_impl(input: u64, output: u64) {
        let mut witness = Witness::new(2);
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
        let mut witness = Witness::new(2);
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
        let mut witness = Witness::new(2);
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

    fn test_witness_poly2_impl(input: Scalar, output: Scalar) {
        let mut witness = Witness::new(2);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), input.into());
        assert_eq!(
            witness.poly2(12.into(), 34.into(), 56.into(), input.into()),
            Wire::Out(1)
        );
        assert_eq!(witness.get(Wire::LeftIn(1)), input.into());
        assert_eq!(witness.get(Wire::RightIn(1)), input.into());
        assert_eq!(witness.get(Wire::Out(1)), output.into());
    }

    #[test]
    fn test_witness_poly2() {
        test_witness_poly2_impl(42.into(), 22652.into());
        test_witness_poly2_impl(43.into(), 23706.into());
    }

    fn test_witness_assert_bit_impl(input: Scalar) {
        let mut witness = Witness::new(2);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), input.into());
        witness.assert_bit(Wire::LeftIn(0).into());
        assert_eq!(witness.get(Wire::LeftIn(1)), input.into());
        assert_eq!(witness.get(Wire::RightIn(1)), input.into());
    }

    #[test]
    fn test_witness_assert_bit() {
        test_witness_assert_bit_impl(0.into());
        test_witness_assert_bit_impl(1.into());
    }

    fn test_witness_assert_trit_impl(input: Scalar) {
        let mut witness = Witness::new(3);
        witness.pop_gate();
        witness.set(Wire::LeftIn(0), input.into());
        witness.assert_trit(Wire::LeftIn(0).into());
        assert_eq!(witness.get(Wire::LeftIn(1)), input);
        assert_eq!(witness.get(Wire::RightIn(1)), input);
    }

    #[test]
    fn test_witness_assert_trit() {
        test_witness_assert_trit_impl(0.into());
        test_witness_assert_trit_impl(1.into());
        test_witness_assert_trit_impl(2.into());
    }

    fn test_witness_not_impl(input: Scalar, output: Scalar) {
        let mut witness = Witness::new(2);
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
        let mut witness = Witness::new(2);
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
        let mut witness = Witness::new(2);
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
        let mut witness = Witness::new(2);
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
        // let proof = circuit
        //     .prove(witness(
        //         vec![3.into(), 9.into(), 3.into(), 30.into()],
        //         vec![3.into(), 3.into(), 27.into(), 5.into()],
        //         vec![9.into(), 27.into(), 30.into(), 35.into()],
        //     ))
        //     .unwrap();
        // let public_inputs = circuit.verify(&proof).unwrap();
        // assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        // assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    // TODO
}
