use crate::bluesky::Scalar;
use crate::pcs;
use crate::poly;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use ff::Field;
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::sync::LazyLock;

/// Re-export the available hash backends.
pub use pcs::{Hash, Poseidon2Hash, Sha2Hash};

type Polynomial = poly::Polynomial<Scalar>;

/// Number of extra rows that implicitly added to all circuits and witnesses for blinding.
///
/// Blinding rows are appended at the end using NOP gates and random scalars in the witness.
///
/// The reason why PLONK requires 3 of them is that they must be strictly more than the number of
/// off-domain locations opened in the underlying polynomial commitment scheme, and PLONK requires
/// opening two such locations: the Fiat-Shamir challenge xi and also xi*omega (the latter is for
/// the coordinate pair accumulator polynomial of the permutation argument, which contains the
/// witness columns in its definition).
pub const NUM_BLINDING_ROWS: usize = 3;

/// Domain separator tag used for the main Fiat-Shamir challenge.
static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/plonk/challenge"));

const K1: Scalar = Scalar::from_const(71);
const K2: Scalar = Scalar::from_const(104);

const COMMIT_INDEX_CIRCUIT: usize = 0;
const COMMIT_INDEX_WITNESS: usize = 1;
const COMMIT_INDEX_PERMUTATION_ARGUMENT: usize = 2;
const COMMIT_INDEX_QUOTIENT: usize = 3;
const NUM_COMMIT_INDICES: usize = 4;

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
    LeftIn(usize),
    RightIn(usize),
    Out(usize),
}

impl Wire {
    pub fn gate(&self) -> usize {
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
    gate_counter: usize,
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

    pub fn pop_gate(&mut self) -> usize {
        let gate = self.gate_counter;
        self.gate_counter += 1;
        gate
    }

    pub fn nop(
        &mut self,
        lhs: WireOrUnconstrained,
        rhs: WireOrUnconstrained,
        out: WireOrUnconstrained,
    ) -> usize {
        let gate = self.pop_gate();
        self.copy(lhs, Wire::LeftIn(gate));
        self.copy(rhs, Wire::RightIn(gate));
        self.copy(out, Wire::Out(gate));
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
        let lhs = self.poly2(
            Scalar::from_const(1),
            -Scalar::from_const(3),
            Scalar::from_const(2),
            input,
        );
        let gate = self.pop_gate();
        self.copy(lhs.into(), Wire::LeftIn(gate));
        self.copy(input, Wire::RightIn(gate));
    }

    pub fn not(&mut self, input: WireOrUnconstrained) -> Wire {
        let gate = self.pop_gate();
        self.copy(input, Wire::LeftIn(gate));
        let input = self.copy(input, Wire::RightIn(gate));
        let out = Wire::Out(gate);
        self.set(out, Scalar::from_const(1) - input);
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
        self.set(out, lhs + rhs - Scalar::from_const(2) * lhs * rhs);
        out
    }

    fn blind_row(&mut self) {
        let gate = self.pop_gate();
        self.set(Wire::LeftIn(gate), utils::get_random_scalar());
        self.set(Wire::RightIn(gate), utils::get_random_scalar());
        self.set(Wire::Out(gate), utils::get_random_scalar());
    }

    fn blind(&mut self) {
        self.blind_row();
        self.blind_row();
        self.blind_row();
    }
}

#[derive(Debug, Default)]
pub struct CircuitBuilder {
    gates: Vec<GateConstraint>,
    wires: WirePartitioning,
    public_gates: BTreeSet<usize>,
}

impl CircuitBuilder {
    /// Returns the size of the circuit built so far.
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    /// Returns the number of gates added so far.
    ///
    /// This is exactly the same as `len()`.
    pub fn gate_count(&self) -> usize {
        self.len()
    }

    pub fn add_raw_gate(
        &mut self,
        ql: Scalar,
        qr: Scalar,
        qo: Scalar,
        qm: Scalar,
        qc: Scalar,
    ) -> usize {
        let index = self.gates.len();
        self.gates.push(GateConstraint { ql, qr, qo, qm, qc });
        index
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

    pub fn add_nop_gate(
        &mut self,
        lhs: Option<Wire>,
        rhs: Option<Wire>,
        out: Option<Wire>,
    ) -> usize {
        let gate = self.add_raw_gate(
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
        );
        if let Some(lhs) = lhs {
            self.connect(lhs, Wire::LeftIn(gate));
        }
        if let Some(rhs) = rhs {
            self.connect(rhs, Wire::RightIn(gate));
        }
        if let Some(out) = out {
            self.connect(out, Wire::Out(gate));
        }
        gate
    }

    pub fn add_const_gate(&mut self, value: Scalar) -> Wire {
        Wire::Out(self.add_raw_gate(
            Scalar::from_const(0),
            Scalar::from_const(0),
            Scalar::from_const(1),
            Scalar::from_const(0),
            -value,
        ))
    }

    pub fn add_sum_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            Scalar::from_const(1),
            Scalar::from_const(1),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    pub fn add_sum_with_const_gate(&mut self, lhs: Option<Wire>, c: Scalar) -> Wire {
        self.add_unary_gate(
            Scalar::from_const(1),
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            c,
            lhs,
        )
    }

    pub fn add_sub_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            Scalar::from_const(1),
            -Scalar::from_const(1),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    pub fn add_sub_const_gate(&mut self, lhs: Option<Wire>, c: Scalar) -> Wire {
        self.add_unary_gate(
            Scalar::from_const(1),
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            -c,
            lhs,
        )
    }

    pub fn add_sub_from_const_gate(&mut self, c: Scalar, rhs: Option<Wire>) -> Wire {
        self.add_unary_gate(
            Scalar::from_const(0),
            -Scalar::from_const(1),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            c,
            rhs,
        )
    }

    pub fn add_mul_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            Scalar::from_const(0),
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(1),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    pub fn add_square_gate(&mut self, input: Option<Wire>) -> Wire {
        self.add_unary_gate(
            Scalar::from_const(0),
            Scalar::from_const(0),
            Scalar::from_const(1),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            input,
        )
    }

    pub fn add_mul_by_const_gate(&mut self, lhs: Option<Wire>, c: Scalar) -> Wire {
        self.add_unary_gate(
            c,
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            Scalar::from_const(0),
            lhs,
        )
    }

    pub fn add_linear_combination_gate(
        &mut self,
        c1: Scalar,
        lhs: Option<Wire>,
        c2: Scalar,
        rhs: Option<Wire>,
    ) -> Wire {
        self.add_binary_gate(
            c1,
            c2,
            -Scalar::from_const(1),
            Scalar::from_const(0),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    pub fn add_poly2_gate(
        &mut self,
        c1: Scalar,
        c2: Scalar,
        c3: Scalar,
        input: Option<Wire>,
    ) -> Wire {
        self.add_unary_gate(
            c2,
            Scalar::from_const(0),
            -Scalar::from_const(1),
            c1,
            c3,
            input,
        )
    }

    pub fn add_bit_assertion_gate(&mut self, input: Option<Wire>) {
        self.add_unary_gate(
            Scalar::from_const(1),
            Scalar::from_const(0),
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            input,
        );
    }

    pub fn add_trit_assertion_gate(&mut self, input: Option<Wire>) {
        let lhs = self.add_poly2_gate(
            Scalar::from_const(1),
            -Scalar::from_const(3),
            Scalar::from_const(2),
            input,
        );
        self.add_binary_gate(
            Scalar::from_const(0),
            Scalar::from_const(0),
            Scalar::from_const(0),
            Scalar::from_const(1),
            Scalar::from_const(0),
            lhs.into(),
            input,
        );
    }

    pub fn add_not_gate(&mut self, input: Option<Wire>) -> Wire {
        self.add_unary_gate(
            -Scalar::from_const(1),
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            Scalar::from_const(1),
            input,
        )
    }

    pub fn add_and_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            Scalar::from_const(0),
            Scalar::from_const(0),
            -Scalar::from_const(1),
            Scalar::from_const(1),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    pub fn add_or_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            Scalar::from_const(1),
            Scalar::from_const(1),
            -Scalar::from_const(1),
            -Scalar::from_const(1),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    pub fn add_xor_gate(&mut self, lhs: Option<Wire>, rhs: Option<Wire>) -> Wire {
        self.add_binary_gate(
            Scalar::from_const(1),
            Scalar::from_const(1),
            -Scalar::from_const(1),
            -Scalar::from_const(2),
            Scalar::from_const(0),
            lhs,
            rhs,
        )
    }

    fn add_blinding_gates(&mut self) {
        self.add_nop_gate(None, None, None);
        self.add_nop_gate(None, None, None);
        self.add_nop_gate(None, None, None);
    }

    pub fn declare_public_gates<I: IntoIterator<Item = usize>>(&mut self, gates: I) {
        self.public_gates = BTreeSet::from_iter(gates);
    }

    fn build_identity_permutation(&self) -> (Vec<Scalar>, Vec<Scalar>, Vec<Scalar>) {
        let n = padded_size(self.gates.len());
        let mut x = vec![Scalar::ZERO; n * 3];
        if n > 0 {
            x[0] = Scalar::ONE;
            x[n] = K1;
            x[n * 2] = K2;
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

    pub fn build(mut self) -> Circuit {
        self.add_blinding_gates();
        let n = padded_size(self.gates.len());
        let pad = n - self.gates.len();
        let ql = Polynomial::encode2(
            self.gates
                .iter()
                .map(|gate| gate.ql)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qr = Polynomial::encode2(
            self.gates
                .iter()
                .map(|gate| gate.qr)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qo = Polynomial::encode2(
            self.gates
                .iter()
                .map(|gate| gate.qo)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qm = Polynomial::encode2(
            self.gates
                .iter()
                .map(|gate| gate.qm)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let qc = Polynomial::encode2(
            self.gates
                .iter()
                .map(|gate| gate.qc)
                .chain(std::iter::repeat_n(Scalar::ZERO, pad))
                .collect(),
        );
        let (sl_values, sr_values, so_values) = self.build_identity_permutation();
        let sl = Polynomial::encode2(sl_values.clone());
        let sr = Polynomial::encode2(sr_values.clone());
        let so = Polynomial::encode2(so_values.clone());
        Circuit {
            size: self.gates.len(),
            public_gates: self.public_gates,
            ql,
            qr,
            qo,
            qm,
            qc,
            sl_values,
            sl,
            sr_values,
            sr,
            so_values,
            so,
        }
    }

    pub fn check_witness(&self, witness: &Witness) -> Result<()> {
        let size = self.gates.len();
        if witness.size() != size + NUM_BLINDING_ROWS {
            return Err(anyhow!(
                "incorrect witness size (got {}, want {})",
                witness.size(),
                size + NUM_BLINDING_ROWS
            ));
        }
        for i in 0..size {
            let lhs = witness.left[i];
            let rhs = witness.right[i];
            let out = witness.out[i];
            let (ql, qr, qo, qm, qc) = match self.gates[i] {
                GateConstraint { ql, qr, qo, qm, qc } => (ql, qr, qo, qm, qc),
            };
            if ql * lhs + qr * rhs + qo * out + qm * lhs * rhs + qc != Scalar::ZERO {
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
pub struct Proof<H: pcs::Hash> {
    commitment: pcs::Commitment,
    inner_proof: pcs::Proof<H>,
}

impl<H: Hash> Proof<H> {
    pub fn blowup_log2(&self) -> usize {
        self.inner_proof.blowup_log2()
    }
}

#[derive(Debug, Clone)]
pub struct Circuit {
    size: usize,
    public_gates: BTreeSet<usize>,
    ql: Polynomial,
    qr: Polynomial,
    qo: Polynomial,
    qm: Polynomial,
    qc: Polynomial,
    sl_values: Vec<Scalar>,
    sl: Polynomial,
    sr_values: Vec<Scalar>,
    sr: Polynomial,
    so_values: Vec<Scalar>,
    so: Polynomial,
}

impl Circuit {
    pub fn size(&self) -> usize {
        self.size
    }

    pub fn make_witness(&self) -> Witness {
        Witness::new(self.size)
    }

    /// Constructs a `CompressedCircuit` from this circuit.
    ///
    /// NOTE: compressed circuits are specific to a given blowup factor.
    pub fn compress<H: Hash>(&self, blowup_log2: usize) -> CompressedCircuit {
        let circuit_commitment = {
            let degree_bound = padded_size(self.size);
            let committer = pcs::Committer::<H>::new(
                degree_bound,
                blowup_log2,
                vec![
                    self.ql.clone(),
                    self.qr.clone(),
                    self.qo.clone(),
                    self.qm.clone(),
                    self.qc.clone(),
                    self.sl.clone(),
                    self.sr.clone(),
                    self.so.clone(),
                ],
            );
            committer.root_hash(0)
        };
        CompressedCircuit {
            original_size: self.size,
            blowup_log2,
            public_gates: self.public_gates.clone(),
            circuit_commitment,
        }
    }

    /// Converts this circuit into a compressed one.
    ///
    /// NOTE: compressed circuits are specific to a given blowup factor.
    pub fn to_compressed<H: Hash>(self, blowup_log2: usize) -> CompressedCircuit {
        let circuit_commitment = {
            let degree_bound = padded_size(self.size);
            let committer = pcs::Committer::<H>::new(
                degree_bound,
                blowup_log2,
                vec![
                    self.ql, self.qr, self.qo, self.qm, self.qc, self.sl, self.sr, self.so,
                ],
            );
            committer.root_hash(0)
        };
        CompressedCircuit {
            original_size: self.size,
            blowup_log2,
            public_gates: self.public_gates,
            circuit_commitment,
        }
    }

    /// Builds the two polynomials used in the permutation argument. The components of the returned
    /// tuple are, respectively: the coordinate pair accumulator, the fixpoint constraint, and the
    /// recurrence constraint.
    fn build_permutation_argument(
        &self,
        witness: &Witness,
        left: &Polynomial,
        right: &Polynomial,
        out: &Polynomial,
        beta: Scalar,
        gamma: Scalar,
    ) -> Result<(Polynomial, Polynomial, Polynomial)> {
        let n = padded_size(self.size);

        let sl = self.sl_values.as_slice();
        let sr = self.sr_values.as_slice();
        let so = self.so_values.as_slice();

        let mut accumulator = vec![Scalar::ZERO; n + 1];

        accumulator[0] = Scalar::ONE;
        for i in 0..n {
            let x = Polynomial::domain_element2(i, n);
            accumulator[i + 1] = accumulator[i]
                * (witness.left[i] + beta * x + gamma)
                * (witness.right[i] + beta * K1 * x + gamma)
                * (witness.out[i] + beta * K2 * x + gamma)
                * ((witness.left[i] + beta * sl[i] + gamma)
                    * (witness.right[i] + beta * sr[i] + gamma)
                    * (witness.out[i] + beta * so[i] + gamma))
                    .invert()
                    .into_option()
                    .context("division by zero in permutation accumulator")?;
        }

        if accumulator.pop().unwrap() != Scalar::ONE {
            return Err(anyhow!("permutation accumulator wraparound check failed"));
        }

        let accumulator = Polynomial::encode2(accumulator);

        let shifted = {
            let mut coefficients = accumulator.clone().take();
            let omega = Polynomial::domain_element2(1, n);
            let mut x = Scalar::ONE;
            for coefficient in coefficients.iter_mut() {
                *coefficient *= x;
                x *= omega;
            }
            Polynomial::with_coefficients(coefficients)
        };

        let recurrence_constraint = Polynomial::multiply_many([
            shifted,
            left.clone() + self.sl.clone() * beta + gamma,
            right.clone() + self.sr.clone() * beta + gamma,
            out.clone() + self.so.clone() * beta + gamma,
        ]) - Polynomial::multiply_many([
            accumulator.clone(),
            left.clone() + Polynomial::with_coefficients(vec![gamma, beta]),
            right.clone() + Polynomial::with_coefficients(vec![gamma, beta * K1]),
            out.clone() + Polynomial::with_coefficients(vec![gamma, beta * K2]),
        ]);

        let fixpoint_constraint =
            (accumulator.clone() - Scalar::ONE) * Polynomial::lagrange0(n).clone();

        Ok((accumulator, fixpoint_constraint, recurrence_constraint))
    }

    fn split_polynomial(polynomial: Polynomial, n: usize) -> (Polynomial, Polynomial, Polynomial) {
        let mut coefficients = polynomial.take();
        coefficients.resize(n * 3, Scalar::ZERO);
        let low = Vec::from(&coefficients[0..n]);
        let mid = Vec::from(&coefficients[n..(n * 2)]);
        let high = Vec::from(&coefficients[(n * 2)..(n * 3)]);
        (
            Polynomial::with_coefficients(low),
            Polynomial::with_coefficients(mid),
            Polynomial::with_coefficients(high),
        )
    }

    pub fn prove<H: Hash>(&self, mut witness: Witness, blowup_log2: usize) -> Result<Proof<H>> {
        witness.blind();
        if witness.size() != self.size {
            return Err(anyhow!(
                "incorrect witness size (got {}, want {})",
                witness.size(),
                self.size
            ));
        }

        let degree_bound = padded_size(self.size);

        let left = Polynomial::encode2(witness.left.clone());
        let right = Polynomial::encode2(witness.right.clone());
        let out = Polynomial::encode2(witness.out.clone());

        let mut committer = pcs::Committer::<H>::new(
            degree_bound,
            blowup_log2,
            vec![
                self.ql.clone(),
                self.qr.clone(),
                self.qo.clone(),
                self.qm.clone(),
                self.qc.clone(),
                self.sl.clone(),
                self.sr.clone(),
                self.so.clone(),
            ],
        );

        let witness_commit_index =
            committer.add_batch(vec![left.clone(), right.clone(), out.clone()]);
        assert_eq!(witness_commit_index, COMMIT_INDEX_WITNESS);
        let beta = H::hash_raw(
            *DST,
            committer.root_hash(witness_commit_index),
            Scalar::from_const(1),
        );
        let gamma = H::hash_raw(
            *DST,
            committer.root_hash(witness_commit_index),
            Scalar::from_const(2),
        );

        let (
            permutation_accumulator,
            permutation_fixpoint_constraint,
            permutation_recurrence_constraint,
        ) = self.build_permutation_argument(&witness, &left, &right, &out, beta, gamma)?;

        let permutation_commit_index = committer.add_batch(vec![permutation_accumulator]);
        assert_eq!(permutation_commit_index, COMMIT_INDEX_PERMUTATION_ARGUMENT);
        let alpha = H::hash_raw(
            *DST,
            committer.root_hash(permutation_commit_index),
            Scalar::ZERO,
        );

        let quotient = {
            let gate_constraint = self.ql.clone() * left.clone()
                + self.qr.clone() * right.clone()
                + self.qo.clone() * out.clone()
                + Polynomial::multiply_many([self.qm.clone(), left.clone(), right.clone()])
                + self.qc.clone();
            let constraint = gate_constraint
                + permutation_fixpoint_constraint * alpha
                + permutation_recurrence_constraint * alpha.square();
            constraint.divide_by_zero(degree_bound)?
        };

        let omega = Polynomial::domain_element2(1, degree_bound);

        let (quotient_low, quotient_mid, quotient_high) =
            Self::split_polynomial(quotient, degree_bound);

        let quotient_commit_index =
            committer.add_batch(vec![quotient_low, quotient_mid, quotient_high]);
        assert_eq!(quotient_commit_index, COMMIT_INDEX_QUOTIENT);
        let xi = H::hash_raw(
            *DST,
            committer.root_hash(quotient_commit_index),
            Scalar::ZERO,
        );

        let (commitment, prover) = committer.commit(BTreeSet::from_iter(
            [xi, xi * omega].into_iter().chain(
                self.public_gates
                    .iter()
                    .map(|&row| omega.pow_vartime([row as u64, 0, 0, 0])),
            ),
        ));
        let inner_proof = prover.prove(&commitment);

        Ok(Proof {
            commitment,
            inner_proof,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CompressedCircuit {
    original_size: usize,
    blowup_log2: usize,
    public_gates: BTreeSet<usize>,
    circuit_commitment: Scalar,
}

impl CompressedCircuit {
    pub fn original_size(&self) -> usize {
        self.original_size
    }

    pub fn blowup_log2(&self) -> usize {
        self.blowup_log2
    }

    pub fn commitment(&self) -> Scalar {
        self.circuit_commitment
    }

    fn lagrange0(x: Scalar, n: usize) -> Scalar {
        (x.pow_vartime([n as u64, 0, 0, 0]) - Scalar::ONE)
            * (Scalar::from(n as u64) * (x - Scalar::ONE))
                .invert()
                .into_option()
                .unwrap()
    }

    pub fn verify<H: Hash>(&self, proof: &Proof<H>) -> Result<BTreeMap<Wire, Scalar>> {
        let commitment = &proof.commitment;
        let inner_proof = &proof.inner_proof;

        if commitment.tree_roots().len() != NUM_COMMIT_INDICES {
            return Err(anyhow!(
                "wrong number of Merkle roots (got {}, want {})",
                commitment.tree_roots().len(),
                NUM_COMMIT_INDICES
            ));
        }
        if commitment.tree_roots()[0] != self.circuit_commitment {
            return Err(anyhow!(
                "wrong circuit commitment (got {}, want {})",
                commitment.tree_roots()[0],
                self.circuit_commitment
            ));
        }

        let n = padded_size(self.original_size);
        if inner_proof.degree_bound() != n {
            return Err(anyhow!(
                "wrong degree bound (got {}, want {})",
                inner_proof.degree_bound(),
                n
            ));
        }
        if inner_proof.blowup_log2() != self.blowup_log2 {
            return Err(anyhow!(
                "blowup factor mismatch (got {}, want {})",
                1usize << inner_proof.blowup_log2(),
                1usize << self.blowup_log2
            ));
        }
        if inner_proof.num_polys() != 15 {
            return Err(anyhow!(
                "incorrect number of committed polynomials (got {}, want 17)",
                inner_proof.num_polys()
            ));
        }

        let omega = Polynomial::domain_element2(1, n);

        let beta = H::hash_raw(
            *DST,
            commitment.tree_roots()[COMMIT_INDEX_WITNESS],
            Scalar::from_const(1),
        );
        let gamma = H::hash_raw(
            *DST,
            commitment.tree_roots()[COMMIT_INDEX_WITNESS],
            Scalar::from_const(2),
        );
        let alpha = H::hash_raw(
            *DST,
            commitment.tree_roots()[COMMIT_INDEX_PERMUTATION_ARGUMENT],
            Scalar::ZERO,
        );
        let xi = H::hash_raw(
            *DST,
            commitment.tree_roots()[COMMIT_INDEX_QUOTIENT],
            Scalar::ZERO,
        );

        let points = inner_proof.points();
        if !points.contains_key(&xi) {
            return Err(anyhow!(
                "the proof doesn't have an opening for the Fiat-Shamir challenge value"
            ));
        }
        if !points.contains_key(&(xi * omega)) {
            return Err(anyhow!(
                "the proof doesn't have an opening for the shifted Fiat-Shamir challenge value"
            ));
        }
        for &gate in &self.public_gates {
            let z = omega.pow_vartime([gate as u64, 0, 0, 0]);
            if !points.contains_key(&z) {
                return Err(anyhow!(
                    "the proof doesn't have an opening for public gate {gate}"
                ));
            }
        }

        inner_proof.verify(&commitment)?;

        let ql = points[&xi][0];
        let qr = points[&xi][1];
        let qo = points[&xi][2];
        let qm = points[&xi][3];
        let qc = points[&xi][4];
        let sl = points[&xi][5];
        let sr = points[&xi][6];
        let so = points[&xi][7];

        let left = points[&xi][8];
        let right = points[&xi][9];
        let out = points[&xi][10];

        let xi_n = xi.pow_vartime([n as u64, 0, 0, 0]);
        let xi_2n = xi.pow_vartime([n as u64 * 2, 0, 0, 0]);

        let permutation_accumulator = points[&xi][11];
        let shifted_permutation_accumulator = points[&(xi * omega)][11];
        let quotient = {
            let quotient_low = points[&xi][12];
            let quotient_mid = points[&xi][13];
            let quotient_high = points[&xi][14];
            quotient_low + xi_n * quotient_mid + xi_2n * quotient_high
        };
        let zero = xi_n - Scalar::ONE;

        let gate_constraint = ql * left + qr * right + qo * out + qm * left * right + qc;

        let permutation_numerator = (left + beta * xi + gamma)
            * (right + beta * K1 * xi + gamma)
            * (out + beta * K2 * xi + gamma);
        let permutation_denominator = {
            (left + beta * sl + gamma) * (right + beta * sr + gamma) * (out + beta * so + gamma)
        };
        let permutation_recurrence_constraint = shifted_permutation_accumulator
            * permutation_denominator
            - permutation_accumulator * permutation_numerator;
        let permutation_fixpoint_constraint =
            (permutation_accumulator - Scalar::from_const(1)) * Self::lagrange0(xi, n);

        let full_constraint = gate_constraint
            + alpha * permutation_fixpoint_constraint
            + alpha.square() * permutation_recurrence_constraint;
        if full_constraint != quotient * zero {
            return Err(anyhow!("constraint violation"));
        }

        Ok(BTreeMap::from_iter(
            self.public_gates
                .iter()
                .map(|&gate| {
                    let z = omega.pow_vartime([gate as u64, 0, 0, 0]);
                    [
                        (Wire::LeftIn(gate), points[&z][8]),
                        (Wire::RightIn(gate), points[&z][9]),
                        (Wire::Out(gate), points[&z][10]),
                    ]
                    .into_iter()
                })
                .flatten(),
        ))
    }
}

/// Represents a reusable PLONK chip that you can use to build circuits.
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
    fn build_test_circuit() -> (Circuit, usize) {
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
        builder.declare_public_gates([gate4]);
        (builder.build(), gate4)
    }

    fn witness(mut left: Vec<Scalar>, mut right: Vec<Scalar>, mut out: Vec<Scalar>) -> Witness {
        let original_size = left.len();
        assert_eq!(original_size, right.len());
        assert_eq!(original_size, out.len());
        let blinded_size = original_size + NUM_BLINDING_ROWS;
        let padded_size = padded_size(blinded_size);
        left.resize(padded_size, Scalar::ZERO);
        right.resize(padded_size, Scalar::ZERO);
        out.resize(padded_size, Scalar::ZERO);
        Witness {
            size: blinded_size,
            gate_counter: original_size,
            left,
            right,
            out,
        }
    }

    fn test_circuit1<H: Hash>(blowup_log2: usize) {
        let (circuit, gate) = build_test_circuit();
        let compressed_circuit = circuit.compress::<H>(blowup_log2);
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![3.into(), 9.into(), 3.into(), 30.into()],
                    vec![3.into(), 3.into(), 27.into(), 5.into()],
                    vec![9.into(), 27.into(), 30.into(), 35.into()],
                ),
                blowup_log2,
            )
            .unwrap();
        let public_inputs = compressed_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_circuit1_blowup_2() {
        test_circuit1::<Sha2Hash>(1);
        test_circuit1::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_circuit1_blowup_4() {
        test_circuit1::<Sha2Hash>(2);
        test_circuit1::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_circuit1_blowup_8() {
        test_circuit1::<Sha2Hash>(3);
        test_circuit1::<Poseidon2Hash>(3);
    }

    #[test]
    fn test_circuit1_blowup_16() {
        test_circuit1::<Sha2Hash>(4);
        test_circuit1::<Poseidon2Hash>(4);
    }

    #[test]
    fn test_circuit1_blowup_32() {
        test_circuit1::<Sha2Hash>(5);
        test_circuit1::<Poseidon2Hash>(5);
    }

    #[test]
    fn test_circuit1_blowup_64() {
        test_circuit1::<Sha2Hash>(6);
        test_circuit1::<Poseidon2Hash>(6);
    }

    #[test]
    fn test_circuit1_blowup_128() {
        test_circuit1::<Sha2Hash>(7);
        test_circuit1::<Poseidon2Hash>(7);
    }

    #[test]
    fn test_circuit1_blowup_256() {
        test_circuit1::<Sha2Hash>(8);
        test_circuit1::<Poseidon2Hash>(8);
    }

    fn test_circuit1_with_helpers<H: Hash>(blowup_log2: usize) {
        let mut builder = CircuitBuilder::default();
        let input = Wire::LeftIn(builder.gate_count());
        let gate1 = builder.add_square_gate(input.into());
        let gate2 = builder.add_mul_gate(gate1.into(), input.into());
        let gate3 = builder.add_sum_gate(input.into(), gate2.into());
        let gate4 = builder.add_sum_with_const_gate(gate3.into(), 5.into());
        builder.declare_public_gates([gate4.gate()]);
        let witness = witness(
            vec![3.into(), 9.into(), 3.into(), 30.into()],
            vec![3.into(), 3.into(), 27.into(), 30.into()],
            vec![9.into(), 27.into(), 30.into(), 35.into()],
        );
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let compressed_circuit = circuit.compress::<H>(blowup_log2);
        let proof = circuit.prove::<H>(witness, blowup_log2).unwrap();
        let public_inputs = compressed_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&gate4).unwrap(), 35.into());
    }

    #[test]
    fn test_circuit1_with_helpers_blowup_2() {
        test_circuit1_with_helpers::<Sha2Hash>(1);
        test_circuit1_with_helpers::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_circuit1_with_helpers_blowup_4() {
        test_circuit1_with_helpers::<Sha2Hash>(2);
        test_circuit1_with_helpers::<Poseidon2Hash>(2);
    }

    fn test_circuit2<H: Hash>(blowup_log2: usize) {
        let (circuit, gate) = build_test_circuit();
        let compressed_circuit = circuit.compress::<H>(blowup_log2);
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![4.into(), 16.into(), 4.into(), 68.into()],
                    vec![4.into(), 4.into(), 64.into(), 5.into()],
                    vec![16.into(), 64.into(), 68.into(), 73.into()],
                ),
                blowup_log2,
            )
            .unwrap();
        let public_inputs = compressed_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 73.into());
    }

    #[test]
    fn test_circuit2_blowup_2() {
        test_circuit2::<Sha2Hash>(1);
        test_circuit2::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_circuit2_blowup_4() {
        test_circuit2::<Sha2Hash>(2);
        test_circuit2::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_circuit2_blowup_8() {
        test_circuit2::<Sha2Hash>(3);
        test_circuit2::<Poseidon2Hash>(3);
    }

    fn test_gate_constraint_violation<H: Hash>(blowup_log2: usize) {
        let (circuit, _) = build_test_circuit();
        assert!(
            circuit
                .prove::<H>(
                    witness(
                        vec![4.into(), 16.into(), 4.into(), 68.into()],
                        vec![4.into(), 4.into(), 64.into(), 5.into()],
                        vec![16.into(), 64.into(), 68.into(), 35.into()],
                    ),
                    blowup_log2
                )
                .is_err()
        );
    }

    #[test]
    fn test_gate_constraint_violation_blowup_2() {
        test_gate_constraint_violation::<Sha2Hash>(1);
        test_gate_constraint_violation::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_gate_constraint_violation_blowup_4() {
        test_gate_constraint_violation::<Sha2Hash>(2);
        test_gate_constraint_violation::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_gate_constraint_violation_blowup_8() {
        test_gate_constraint_violation::<Sha2Hash>(3);
        test_gate_constraint_violation::<Poseidon2Hash>(3);
    }

    fn test_compressed_circuit1<H: Hash>(blowup_log2: usize) {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![3.into(), 9.into(), 3.into(), 30.into()],
                    vec![3.into(), 3.into(), 27.into(), 5.into()],
                    vec![9.into(), 27.into(), 30.into(), 35.into()],
                ),
                blowup_log2,
            )
            .unwrap();
        let circuit = circuit.to_compressed::<H>(blowup_log2);
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_compressed_circuit1_blowup_2() {
        test_compressed_circuit1::<Sha2Hash>(1);
        test_compressed_circuit1::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_compressed_circuit1_blowup_4() {
        test_compressed_circuit1::<Sha2Hash>(2);
        test_compressed_circuit1::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_compressed_circuit1_blowup_8() {
        test_compressed_circuit1::<Sha2Hash>(3);
        test_compressed_circuit1::<Poseidon2Hash>(3);
    }

    fn test_compressed_circuit2<H: Hash>(blowup_log2: usize) {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![4.into(), 16.into(), 4.into(), 68.into()],
                    vec![4.into(), 4.into(), 64.into(), 5.into()],
                    vec![16.into(), 64.into(), 68.into(), 73.into()],
                ),
                blowup_log2,
            )
            .unwrap();
        let circuit = circuit.to_compressed::<H>(blowup_log2);
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 73.into());
    }

    #[test]
    fn test_compressed_circuit2_blowup_2() {
        test_compressed_circuit2::<Sha2Hash>(1);
        test_compressed_circuit2::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_compressed_circuit2_blowup_4() {
        test_compressed_circuit2::<Sha2Hash>(2);
        test_compressed_circuit2::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_compressed_circuit2_blowup_8() {
        test_compressed_circuit2::<Sha2Hash>(3);
        test_compressed_circuit2::<Poseidon2Hash>(3);
    }

    fn test_compile_separately<H: Hash>(blowup_log2: usize) {
        let (prover_circuit, _) = build_test_circuit();
        let proof = prover_circuit
            .prove::<H>(
                witness(
                    vec![3.into(), 9.into(), 3.into(), 30.into()],
                    vec![3.into(), 3.into(), 27.into(), 5.into()],
                    vec![9.into(), 27.into(), 30.into(), 35.into()],
                ),
                blowup_log2,
            )
            .unwrap();
        let (verifier_circuit, gate) = build_test_circuit();
        let verifier_circuit = verifier_circuit.to_compressed::<H>(blowup_log2);
        let public_inputs = verifier_circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_compile_separately_blowup_2() {
        test_compile_separately::<Sha2Hash>(1);
        test_compile_separately::<Poseidon2Hash>(1);
        test_compile_separately::<Sha2Hash>(2);
        test_compile_separately::<Poseidon2Hash>(2);
        test_compile_separately::<Sha2Hash>(3);
        test_compile_separately::<Poseidon2Hash>(3);
    }

    const DEFAULT_BLOWUP_LOG2: usize = 3;

    fn test_gate(circuit: &Circuit, left: u64, right: u64, out: u64) -> Result<()> {
        let proof = circuit.prove::<Sha2Hash>(
            witness(vec![left.into()], vec![right.into()], vec![out.into()]),
            DEFAULT_BLOWUP_LOG2,
        )?;
        let compressed_circuit = circuit.compress::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        compressed_circuit.verify(&proof).unwrap();
        Ok(())
    }

    fn test_connected_unary_gate(circuit: &Circuit, input: u64, output: u64) -> Result<()> {
        let proof = circuit.prove::<Sha2Hash>(
            witness(
                vec![0.into(), input.into()],
                vec![0.into(), input.into()],
                vec![input.into(), output.into()],
            ),
            DEFAULT_BLOWUP_LOG2,
        )?;
        let compressed_circuit = circuit.compress::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        compressed_circuit.verify(&proof).unwrap();
        Ok(())
    }

    fn test_connected_binary_gate(
        circuit: &Circuit,
        left: u64,
        right: u64,
        out: u64,
    ) -> Result<()> {
        let proof = circuit.prove::<Sha2Hash>(
            witness(
                vec![0.into(), 0.into(), left.into()],
                vec![0.into(), 0.into(), right.into()],
                vec![left.into(), right.into(), out.into()],
            ),
            DEFAULT_BLOWUP_LOG2,
        )?;
        let compressed_circuit = circuit.compress::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        compressed_circuit.verify(&proof).unwrap();
        Ok(())
    }

    fn test_connected_nop_gate_impl(
        circuit: &Circuit,
        left: u64,
        right: u64,
        out: u64,
    ) -> Result<()> {
        let proof = circuit.prove::<Sha2Hash>(
            witness(
                vec![0.into(), 0.into(), 0.into(), left.into()],
                vec![0.into(), 0.into(), 0.into(), right.into()],
                vec![left.into(), right.into(), out.into(), out.into()],
            ),
            DEFAULT_BLOWUP_LOG2,
        )?;
        let compressed_circuit = circuit.compress::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        compressed_circuit.verify(&proof).unwrap();
        Ok(())
    }

    #[test]
    fn test_nop_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_nop_gate(None, None, None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 12, 34, 56).is_ok());
        assert!(test_gate(&circuit, 34, 56, 78).is_ok());
    }

    #[test]
    fn test_connected_nop_gate() {
        let mut builder = CircuitBuilder::default();
        let lhs = builder.add_const_gate(123.into());
        let rhs = builder.add_const_gate(456.into());
        let out = builder.add_const_gate(789.into());
        builder.add_nop_gate(lhs.into(), rhs.into(), out.into());
        let circuit = builder.build();
        assert!(test_connected_nop_gate_impl(&circuit, 123, 456, 789).is_ok());
        assert!(test_connected_nop_gate_impl(&circuit, 42, 456, 789).is_err());
        assert!(test_connected_nop_gate_impl(&circuit, 123, 42, 789).is_err());
        assert!(test_connected_nop_gate_impl(&circuit, 123, 456, 42).is_err());
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
    fn test_poly2_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_poly2_gate(12.into(), 34.into(), 56.into(), None);
        let circuit = builder.build();
        assert!(test_gate(&circuit, 42, 42, 22652).is_ok());
        assert!(test_gate(&circuit, 78, 42, 22652).is_err());
        assert!(test_gate(&circuit, 42, 78, 22652).is_err());
        assert!(test_gate(&circuit, 42, 42, 78).is_err());
    }

    #[test]
    fn test_connected_poly2_gate() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(43.into());
        builder.add_poly2_gate(34.into(), 56.into(), 78.into(), input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 43, 65352).is_ok());
        assert!(test_connected_unary_gate(&circuit, 43, 22652).is_err());
        assert!(test_connected_unary_gate(&circuit, 43, 23706).is_err());
    }

    #[test]
    fn test_bit_assertion_gate() {
        let mut builder = CircuitBuilder::default();
        builder.add_bit_assertion_gate(None);
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
    fn test_connected_bit_assertion_gate1() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(0.into());
        builder.add_bit_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 0, 0).is_ok());
    }

    #[test]
    fn test_connected_bit_assertion_gate2() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(1.into());
        builder.add_bit_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 1, 0).is_ok());
    }

    #[test]
    fn test_connected_bit_assertion_gate3() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(2.into());
        builder.add_bit_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 2, 0).is_err());
    }

    #[test]
    fn test_connected_bit_assertion_gate4() {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(2.into());
        builder.add_bit_assertion_gate(input.into());
        let circuit = builder.build();
        assert!(test_connected_unary_gate(&circuit, 3, 0).is_err());
    }

    fn test_trit_assertion_gate_impl(value: u64) -> Result<()> {
        let mut builder = CircuitBuilder::default();
        builder.add_trit_assertion_gate(None);
        let circuit = builder.build();
        let mut witness = Witness::new(circuit.size());
        witness.assert_trit(WireOrUnconstrained::Unconstrained(value.into()));
        let proof = circuit.prove::<Sha2Hash>(witness, DEFAULT_BLOWUP_LOG2)?;
        let compressed_circuit = circuit.to_compressed::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        compressed_circuit.verify(&proof)?;
        Ok(())
    }

    #[test]
    fn test_trit_assertion_gate() {
        assert!(test_trit_assertion_gate_impl(0).is_ok());
        assert!(test_trit_assertion_gate_impl(1).is_ok());
        assert!(test_trit_assertion_gate_impl(2).is_ok());
        assert!(test_trit_assertion_gate_impl(3).is_err());
        assert!(test_trit_assertion_gate_impl(4).is_err());
    }

    fn test_connected_trit_assertion_gate_impl(value: u64) -> Result<()> {
        let mut builder = CircuitBuilder::default();
        let input = builder.add_const_gate(value.into());
        builder.add_trit_assertion_gate(input.into());
        let circuit = builder.build();
        let mut witness = Witness::new(circuit.size());
        let input = witness.assert_constant(value.into());
        witness.assert_trit(input.into());
        let proof = circuit.prove::<Sha2Hash>(witness, DEFAULT_BLOWUP_LOG2)?;
        let compressed_circuit = circuit.to_compressed::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        compressed_circuit.verify(&proof)?;
        Ok(())
    }

    #[test]
    fn test_connected_trit_assertion_gate() {
        assert!(test_connected_trit_assertion_gate_impl(0).is_ok());
        assert!(test_connected_trit_assertion_gate_impl(1).is_ok());
        assert!(test_connected_trit_assertion_gate_impl(2).is_ok());
        assert!(test_connected_trit_assertion_gate_impl(3).is_err());
        assert!(test_connected_trit_assertion_gate_impl(4).is_err());
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
    /// test circuit is meaningful because its size is not a power of 2 (it's 6, or 9 including the
    /// blinding rows), so it tests padding.
    fn build_uneven_size_circuit() -> (Circuit, usize) {
        let mut builder = CircuitBuilder::default();
        let input = Wire::LeftIn(builder.gate_count());
        let gate1 = builder.add_square_gate(input.into());
        let gate2 = builder.add_mul_gate(gate1.into(), input.into());
        let gate3 = builder.add_mul_gate(input.into(), None);
        let gate4 = builder.add_sum_gate(gate3.into(), gate2.into());
        let gate5 = builder.add_sum_gate(None, gate4.into());
        let gate6 = builder.add_nop_gate(Wire::LeftIn(gate5.gate()).into(), None, gate5.into());
        builder.declare_public_gates([gate6]);
        (builder.build(), gate6)
    }

    fn test_uneven_size_circuit1<H: Hash>(blowup_log2: usize) {
        let (circuit, gate) = build_uneven_size_circuit();
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![3.into(), 9.into(), 3.into(), 12.into(), 5.into(), 5.into()],
                    vec![3.into(), 3.into(), 4.into(), 27.into(), 39.into(), 0.into()],
                    vec![
                        9.into(),
                        27.into(),
                        12.into(),
                        39.into(),
                        44.into(),
                        44.into(),
                    ],
                ),
                blowup_log2,
            )
            .unwrap();
        let compressed_circuit = circuit.to_compressed::<H>(blowup_log2);
        let public_inputs = compressed_circuit.verify::<H>(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 44.into());
    }

    #[test]
    fn test_uneven_size_circuit1_blowup_2() {
        test_uneven_size_circuit1::<Sha2Hash>(1);
        test_uneven_size_circuit1::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_uneven_size_circuit1_blowup_4() {
        test_uneven_size_circuit1::<Sha2Hash>(2);
        test_uneven_size_circuit1::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_uneven_size_circuit1_blowup_8() {
        test_uneven_size_circuit1::<Sha2Hash>(3);
        test_uneven_size_circuit1::<Poseidon2Hash>(3);
    }

    fn test_uneven_size_circuit2<H: Hash>(blowup_log2: usize) {
        let (circuit, gate) = build_uneven_size_circuit();
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![4.into(), 16.into(), 4.into(), 12.into(), 5.into(), 5.into()],
                    vec![4.into(), 4.into(), 3.into(), 64.into(), 76.into(), 0.into()],
                    vec![
                        16.into(),
                        64.into(),
                        12.into(),
                        76.into(),
                        81.into(),
                        81.into(),
                    ],
                ),
                blowup_log2,
            )
            .unwrap();
        let compressed_circuit = circuit.to_compressed::<H>(blowup_log2);
        let public_inputs = compressed_circuit.verify::<H>(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 81.into());
    }

    #[test]
    fn test_uneven_size_circuit2_blowup_2() {
        test_uneven_size_circuit2::<Sha2Hash>(1);
        test_uneven_size_circuit2::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_uneven_size_circuit2_blowup_4() {
        test_uneven_size_circuit2::<Sha2Hash>(2);
        test_uneven_size_circuit2::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_uneven_size_circuit2_blowup_8() {
        test_uneven_size_circuit2::<Sha2Hash>(3);
        test_uneven_size_circuit2::<Poseidon2Hash>(3);
    }

    #[test]
    fn test_compile_uneven_size_circuit_separately() {
        let (prover_circuit, _) = build_uneven_size_circuit();
        let proof = prover_circuit
            .prove::<Sha2Hash>(
                witness(
                    vec![3.into(), 9.into(), 3.into(), 12.into(), 5.into(), 5.into()],
                    vec![3.into(), 3.into(), 4.into(), 27.into(), 39.into(), 0.into()],
                    vec![
                        9.into(),
                        27.into(),
                        12.into(),
                        39.into(),
                        44.into(),
                        44.into(),
                    ],
                ),
                DEFAULT_BLOWUP_LOG2,
            )
            .unwrap();
        let (verifier_circuit, gate) = build_uneven_size_circuit();
        let verifier_circuit = verifier_circuit.to_compressed::<Sha2Hash>(DEFAULT_BLOWUP_LOG2);
        let public_inputs = verifier_circuit.verify::<Sha2Hash>(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::LeftIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 44.into());
    }
}
