use crate::bluesky::Scalar;
use crate::poly;
use crate::turbo::expr::Expression;
use std::collections::{BTreeMap, BTreeSet};

type Polynomial = poly::Polynomial<Scalar>;

#[derive(Debug, Default, Clone)]
pub struct CircuitBuilder {
    num_columns: usize,
    gates: Vec<Expression>,
    gates_by_repr: BTreeMap<String, Vec<usize>>,
    public_gates: BTreeSet<usize>,
}

impl CircuitBuilder {
    pub fn len(&self) -> usize {
        self.gates.len()
    }

    pub fn var(&self, column_index: usize) -> Expression {
        Expression::var(column_index)
    }

    pub fn add_gate(&mut self, gate: Expression) {
        self.num_columns = std::cmp::max(self.num_columns, gate.get_max_columns());
        let repr = gate.to_repr();
        let index = self.gates.len();
        self.gates.push(gate);
        match self.gates_by_repr.get_mut(&repr) {
            Some(gates) => {
                gates.push(index);
            }
            None => {
                self.gates_by_repr.insert(repr, vec![index]);
            }
        };
    }

    pub fn declare_public_gate(&mut self, gate: usize) {
        self.public_gates.insert(gate);
    }

    pub fn declare_public_gates(&mut self, mut gates: BTreeSet<usize>) {
        self.public_gates.append(&mut gates);
    }

    // TODO
}

#[derive(Debug, Clone)]
pub struct Circuit {
    num_columns: usize,
    gates: Vec<Expression>,
    public_gates: BTreeSet<usize>,
    sigma: Vec<Polynomial>,
}

impl Circuit {
    pub fn num_columns(&self) -> usize {
        self.num_columns
    }

    pub fn len(&self) -> usize {
        self.gates.len()
    }

    pub fn public_gates(&self) -> &BTreeSet<usize> {
        &self.public_gates
    }

    // TODO
}

// TODO

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vitalik_circuit() {
        let mut builder = CircuitBuilder::default();
        let x = builder.var(0);
        let y = builder.var(1);
        builder.add_gate(x.square() - y);
        // TODO
    }

    // TODO
}
