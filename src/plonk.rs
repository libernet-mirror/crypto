use crate::bluesky::Scalar;
use crate::fri2;
use crate::pcs;
use crate::poly;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use ff::Field;
use std::collections::{BTreeMap, BTreeSet, btree_map};
use std::sync::LazyLock;

/// Re-export the available hash backends.
pub use pcs::{Hash, Poseidon2Hash, Sha3Hash};

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

const K1: Scalar = Scalar::from_const(71);
const K2: Scalar = Scalar::from_const(104);

fn padded_size(n: usize) -> usize {
    std::cmp::max(2, n.next_power_of_two())
}

/// Returns the challenge point of the PLONK scheme, referred to as `xi` throughout the rest of the
/// codebase.
///
/// The three arguments are the Merkle root hashes of the three witness columns, from which the
/// challenge point is derived as per Fiat-Shamir.
fn get_challenge<H: Hash>(lhs_root: Scalar, rhs_root: Scalar, out_root: Scalar) -> Scalar {
    static DST: LazyLock<Scalar> =
        LazyLock::new(|| utils::hash_to_scalar(b"libernet/plonk/challenge"));
    H::hash_many(&[*DST, lhs_root, rhs_root, out_root])
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
    public_inputs: BTreeSet<Wire>,
}

impl CircuitBuilder {
    /// Returns the size of the circuit built so far.
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    /// Returns the number of gates added so far.
    ///
    /// This is the same as casting `len()` to `u32`.
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

    pub fn add_nop_gate(&mut self) {
        self.add_raw_gate(
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
            Scalar::ZERO,
        );
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
        self.add_nop_gate();
        self.add_nop_gate();
        self.add_nop_gate();
    }

    pub fn declare_public_inputs<I: IntoIterator<Item = Wire>>(&mut self, wires: I) {
        self.public_inputs = BTreeSet::from_iter(wires);
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
            public_inputs: self.public_inputs,
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
                size
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
    public_inputs: BTreeMap<Wire, Scalar>,
    commitment: pcs::Commitment,
    inner_proof: pcs::Proof<H>,
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

    pub fn get_lhs_query_points(&self, xi: Scalar, n: usize) -> BTreeSet<Scalar> {
        BTreeSet::from_iter(
            std::iter::once(xi).chain(
                self.public_inputs
                    .iter()
                    .filter(|&wire| match wire {
                        Wire::LeftIn(_) => true,
                        _ => false,
                    })
                    .map(|&wire| {
                        Polynomial::domain_element2(
                            match wire {
                                Wire::LeftIn(index) => index,
                                _ => unreachable!(),
                            } as usize,
                            n,
                        )
                    }),
            ),
        )
    }

    pub fn get_rhs_query_points(&self, xi: Scalar, n: usize) -> BTreeSet<Scalar> {
        BTreeSet::from_iter(
            std::iter::once(xi).chain(
                self.public_inputs
                    .iter()
                    .filter(|&wire| match wire {
                        Wire::RightIn(_) => true,
                        _ => false,
                    })
                    .map(|&wire| {
                        Polynomial::domain_element2(
                            match wire {
                                Wire::RightIn(index) => index,
                                _ => unreachable!(),
                            } as usize,
                            n,
                        )
                    }),
            ),
        )
    }

    pub fn get_out_query_points(&self, xi: Scalar, n: usize) -> BTreeSet<Scalar> {
        BTreeSet::from_iter(
            std::iter::once(xi).chain(
                self.public_inputs
                    .iter()
                    .filter(|&wire| match wire {
                        Wire::Out(_) => true,
                        _ => false,
                    })
                    .map(|&wire| {
                        Polynomial::domain_element2(
                            match wire {
                                Wire::Out(index) => index,
                                _ => unreachable!(),
                            } as usize,
                            n,
                        )
                    }),
            ),
        )
    }

    pub fn prove<H: Hash>(&self, mut witness: Witness, blowup_exp: u32) -> Result<Proof<H>> {
        witness.blind();
        if witness.size() != self.size {
            return Err(anyhow!(
                "incorrect witness size (got {}, want {})",
                witness.size(),
                self.size
            ));
        }

        let n = padded_size(self.size);
        let pcs_degree_bound = (self.size * 3).next_power_of_two();

        let public_inputs = self
            .public_inputs
            .iter()
            .map(|&wire| {
                (
                    wire,
                    match wire {
                        Wire::LeftIn(gate) => witness.left[gate as usize],
                        Wire::RightIn(gate) => witness.right[gate as usize],
                        Wire::Out(gate) => witness.out[gate as usize],
                    },
                )
            })
            .collect();

        let left = Polynomial::encode2(witness.left.clone());
        let right = Polynomial::encode2(witness.right.clone());
        let out = Polynomial::encode2(witness.out.clone());

        let xi = {
            let m = pcs_degree_bound << blowup_exp;
            get_challenge::<H>(
                pcs::merkle_root::<H>(left.clone().lde2(m).as_slice()),
                pcs::merkle_root::<H>(right.clone().lde2(m).as_slice()),
                pcs::merkle_root::<H>(out.clone().lde2(m).as_slice()),
            )
        };

        let alpha = H::hash(xi, Scalar::from_const(1));
        let beta = H::hash(xi, Scalar::from_const(2));
        let gamma = H::hash(xi, Scalar::from_const(3));

        let (
            permutation_accumulator,
            permutation_fixpoint_constraint,
            permutation_recurrence_constraint,
        ) = self.build_permutation_argument(&witness, &left, &right, &out, beta, gamma)?;

        let quotient = {
            let gate_constraint = self.ql.clone() * left.clone()
                + self.qr.clone() * right.clone()
                + self.qo.clone() * out.clone()
                + Polynomial::multiply_many([self.qm.clone(), left.clone(), right.clone()])
                + self.qc.clone();
            let constraint = gate_constraint
                + permutation_fixpoint_constraint * alpha
                + permutation_recurrence_constraint * alpha.square();
            constraint.divide_by_zero(n)?
        };

        let omega = Polynomial::domain_element2(1, n);

        let prover = pcs::Prover::<H>::new(
            vec![
                left.clone(),
                right.clone(),
                out.clone(),
                permutation_accumulator,
                quotient,
            ],
            blowup_exp,
            vec![
                self.get_lhs_query_points(xi, n),
                self.get_rhs_query_points(xi, n),
                self.get_out_query_points(xi, n),
                [xi, xi * omega].into(),
                [xi].into(),
            ],
            pcs_degree_bound,
        );

        let commitment = prover.commit();
        let inner_proof = prover.prove(&commitment);

        Ok(Proof {
            public_inputs,
            commitment,
            inner_proof,
        })
    }

    fn lagrange0(x: Scalar, n: usize) -> Scalar {
        (x.pow_vartime([n as u64, 0, 0, 0]) - Scalar::ONE)
            * (Scalar::from(n as u64) * (x - Scalar::ONE))
                .invert()
                .into_option()
                .unwrap()
    }

    pub fn verify<H: Hash>(&self, proof: &Proof<H>) -> Result<BTreeMap<Wire, Scalar>> {
        let inner_proof = &proof.inner_proof;
        if inner_proof.len() != 5 {
            return Err(anyhow!("incorrect number of openings"));
        }

        let n = padded_size(self.size);

        let xi = {
            let sources = proof.commitment.sources();
            get_challenge::<H>(sources[0].root(), sources[1].root(), sources[2].root())
        };
        for i in 0..5 {
            if !inner_proof.points(i).contains_key(&xi) {
                return Err(anyhow!(
                    "invalid proof: missing required opening on Fiat-Shamir challenge point"
                ));
            }
        }

        let omega = Polynomial::domain_element2(1, n);
        if !inner_proof.points(3).contains_key(&(xi * omega)) {
            return Err(anyhow!(
                "invalid proof: missing required opening for the shifted permutation accumulator"
            ));
        }

        inner_proof.verify(&proof.commitment)?;

        let alpha = H::hash(xi, Scalar::from_const(1));
        let beta = H::hash(xi, Scalar::from_const(2));
        let gamma = H::hash(xi, Scalar::from_const(3));

        let left = inner_proof.points(0).get(&xi).cloned().unwrap();
        let right = inner_proof.points(1).get(&xi).cloned().unwrap();
        let out = inner_proof.points(2).get(&xi).cloned().unwrap();
        let (permutation_accumulator, shifted_permutation_accumulator) = {
            let points = inner_proof.points(3);
            (
                points.get(&xi).cloned().unwrap(),
                points.get(&(xi * omega)).cloned().unwrap(),
            )
        };
        let quotient = inner_proof.points(4).get(&xi).cloned().unwrap();
        let zero = xi.pow([n as u64, 0, 0, 0]) - Scalar::ONE;

        let gate_constraint = self.ql.evaluate(xi) * left
            + self.qr.evaluate(xi) * right
            + self.qo.evaluate(xi) * out
            + self.qm.evaluate(xi) * left * right
            + self.qc.evaluate(xi);

        let permutation_numerator = (left + beta * xi + gamma)
            * (right + beta * K1 * xi + gamma)
            * (out + beta * K2 * xi + gamma);
        let permutation_denominator = {
            (left + beta * self.sl.evaluate(xi) + gamma)
                * (right + beta * self.sr.evaluate(xi) + gamma)
                * (out + beta * self.so.evaluate(xi) + gamma)
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

        Ok(BTreeMap::from_iter(self.public_inputs.iter().map(
            |&wire| {
                (
                    wire,
                    *match wire {
                        Wire::LeftIn(index) => inner_proof
                            .points(0)
                            .get(&Polynomial::domain_element2(index as usize, n)),
                        Wire::RightIn(index) => inner_proof
                            .points(1)
                            .get(&Polynomial::domain_element2(index as usize, n)),
                        Wire::Out(index) => inner_proof
                            .points(2)
                            .get(&Polynomial::domain_element2(index as usize, n)),
                    }
                    .unwrap(),
                )
            },
        )))
    }
}

#[derive(Debug, Clone)]
pub struct CompressedCircuit {
    original_size: usize,
    ql: fri2::Commitment,
    qr: fri2::Commitment,
    qo: fri2::Commitment,
    qm: fri2::Commitment,
    qc: fri2::Commitment,
    sl: fri2::Commitment,
    sr: fri2::Commitment,
    so: fri2::Commitment,
}

impl CompressedCircuit {
    pub fn original_size(&self) -> usize {
        self.original_size
    }

    pub fn verify<H: Hash>(&self, proof: &Proof<H>) -> Result<BTreeMap<Wire, Scalar>> {
        // TODO
        todo!()
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
        let blinded_size = original_size + NUM_BLINDING_ROWS;
        let padded_size = padded_size(blinded_size);
        left.resize(padded_size, Scalar::ZERO);
        right.resize(padded_size, Scalar::ZERO);
        out.resize(padded_size, Scalar::ZERO);
        Witness {
            size: blinded_size,
            gate_counter: original_size as u32,
            left,
            right,
            out,
        }
    }

    fn test_circuit1<H: Hash>(blowup_exp: u32) {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![3.into(), 9.into(), 3.into(), 30.into()],
                    vec![3.into(), 3.into(), 27.into(), 5.into()],
                    vec![9.into(), 27.into(), 30.into(), 35.into()],
                ),
                blowup_exp,
            )
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 35.into());
    }

    #[test]
    fn test_circuit1_blowup_2() {
        test_circuit1::<Sha3Hash>(1);
        test_circuit1::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_circuit1_blowup_4() {
        test_circuit1::<Sha3Hash>(2);
        test_circuit1::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_circuit1_blowup_8() {
        test_circuit1::<Sha3Hash>(3);
        test_circuit1::<Poseidon2Hash>(3);
    }

    #[test]
    fn test_circuit1_blowup_16() {
        test_circuit1::<Sha3Hash>(4);
        test_circuit1::<Poseidon2Hash>(4);
    }

    #[test]
    fn test_circuit1_blowup_32() {
        test_circuit1::<Sha3Hash>(5);
        test_circuit1::<Poseidon2Hash>(5);
    }

    #[test]
    fn test_circuit1_blowup_64() {
        test_circuit1::<Sha3Hash>(6);
        test_circuit1::<Poseidon2Hash>(6);
    }

    #[test]
    fn test_circuit1_blowup_128() {
        test_circuit1::<Sha3Hash>(7);
        test_circuit1::<Poseidon2Hash>(7);
    }

    #[test]
    fn test_circuit1_blowup_256() {
        test_circuit1::<Sha3Hash>(8);
        test_circuit1::<Poseidon2Hash>(8);
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
        let proof = circuit.prove::<Sha3Hash>(witness, 3).unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&gate4).unwrap(), 35.into());
    }

    fn test_circuit2<H: Hash>(blowup_exp: u32) {
        let (circuit, gate) = build_test_circuit();
        let proof = circuit
            .prove::<H>(
                witness(
                    vec![4.into(), 16.into(), 4.into(), 68.into()],
                    vec![4.into(), 4.into(), 64.into(), 5.into()],
                    vec![16.into(), 64.into(), 68.into(), 73.into()],
                ),
                blowup_exp,
            )
            .unwrap();
        let public_inputs = circuit.verify(&proof).unwrap();
        assert_eq!(*public_inputs.get(&Wire::RightIn(gate)).unwrap(), 5.into());
        assert_eq!(*public_inputs.get(&Wire::Out(gate)).unwrap(), 73.into());
    }

    #[test]
    fn test_circuit2_blowup_2() {
        test_circuit2::<Sha3Hash>(1);
        test_circuit2::<Poseidon2Hash>(1);
    }

    #[test]
    fn test_circuit2_blowup_4() {
        test_circuit2::<Sha3Hash>(2);
        test_circuit2::<Poseidon2Hash>(2);
    }

    #[test]
    fn test_circuit2_blowup_8() {
        test_circuit2::<Sha3Hash>(3);
        test_circuit2::<Poseidon2Hash>(3);
    }

    #[test]
    fn test_circuit2_blowup_16() {
        test_circuit2::<Sha3Hash>(4);
        test_circuit2::<Poseidon2Hash>(4);
    }

    #[test]
    fn test_circuit2_blowup_32() {
        test_circuit2::<Sha3Hash>(5);
        test_circuit2::<Poseidon2Hash>(5);
    }

    #[test]
    fn test_circuit2_blowup_64() {
        test_circuit2::<Sha3Hash>(6);
        test_circuit2::<Poseidon2Hash>(6);
    }

    #[test]
    fn test_circuit2_blowup_128() {
        test_circuit2::<Sha3Hash>(7);
        test_circuit2::<Poseidon2Hash>(7);
    }

    #[test]
    fn test_circuit2_blowup_256() {
        test_circuit2::<Sha3Hash>(8);
        test_circuit2::<Poseidon2Hash>(8);
    }

    #[test]
    fn test_gate_constraint_violation() {
        let (circuit, _) = build_test_circuit();
        assert!(
            circuit
                .prove::<Sha3Hash>(
                    witness(
                        vec![4.into(), 16.into(), 4.into(), 68.into()],
                        vec![4.into(), 4.into(), 64.into(), 5.into()],
                        vec![16.into(), 64.into(), 68.into(), 35.into()],
                    ),
                    2
                )
                .is_err()
        );
    }

    // TODO
}
