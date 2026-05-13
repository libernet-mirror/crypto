use crate::bluesky::Scalar;
use crate::poly;
use crate::turbo::expr::Expression;
use std::collections::BTreeSet;

type Polynomial = poly::Polynomial<Scalar>;

#[derive(Debug, Default, Clone)]
pub struct CircuitBuilder {
    num_columns: usize,
    gates: Vec<Expression>,
    public_gates: BTreeSet<usize>,
}

impl CircuitBuilder {
    fn var(&self, column_index: usize) -> Expression {
        Expression::var(column_index)
    }

    fn add_gate(&mut self, gate: Expression) {
        self.num_columns = std::cmp::max(self.num_columns, gate.get_max_columns());
        self.gates.push(gate);
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
