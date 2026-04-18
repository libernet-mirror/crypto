use crate::bluesky::Scalar;
use std::collections::{BTreeMap, BTreeSet, btree_map};

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
    // TODO
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

    // TODO
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
