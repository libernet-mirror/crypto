use crate::bluesky::Scalar;
use crate::poly;
use std::fmt::Debug;
use std::ops::{Add, Mul, Neg, Sub};
use std::sync::Arc;

type Polynomial = poly::Polynomial<Scalar>;

trait Node: Debug {
    fn to_repr(&self) -> String;

    fn get_max_columns(&self) -> usize;

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial;
}

#[derive(Debug, Copy, Clone)]
struct ConstantNode(Scalar);

impl Node for ConstantNode {
    fn to_repr(&self) -> String {
        format!("{}", self.0.to_u256())
    }

    fn get_max_columns(&self) -> usize {
        0
    }

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        Polynomial::with_coefficients(vec![self.0])
    }
}

#[derive(Debug, Copy, Clone)]
struct VariableNode(usize);

impl Node for VariableNode {
    fn to_repr(&self) -> String {
        format!("x{}", self.0)
    }

    fn get_max_columns(&self) -> usize {
        self.0 + 1
    }

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        witness[self.0].clone()
    }
}

#[derive(Debug, Clone)]
struct AddNode(Arc<dyn Node>, Arc<dyn Node>);

impl Node for AddNode {
    fn to_repr(&self) -> String {
        format!("+ {} {}", self.0.to_repr(), self.1.to_repr())
    }

    fn get_max_columns(&self) -> usize {
        std::cmp::max(self.0.get_max_columns(), self.1.get_max_columns())
    }

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        let lhs = self.0.get_constraint(witness);
        let rhs = self.1.get_constraint(witness);
        lhs + rhs
    }
}

#[derive(Debug, Clone)]
struct SubNode(Arc<dyn Node>, Arc<dyn Node>);

impl Node for SubNode {
    fn to_repr(&self) -> String {
        format!("- {} {}", self.0.to_repr(), self.1.to_repr())
    }

    fn get_max_columns(&self) -> usize {
        std::cmp::max(self.0.get_max_columns(), self.1.get_max_columns())
    }

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        let lhs = self.0.get_constraint(witness);
        let rhs = self.1.get_constraint(witness);
        lhs - rhs
    }
}

#[derive(Debug, Clone)]
struct NegNode(Arc<dyn Node>);

impl Node for NegNode {
    fn to_repr(&self) -> String {
        format!("- {}", self.0.to_repr())
    }

    fn get_max_columns(&self) -> usize {
        self.0.get_max_columns()
    }

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        -self.0.get_constraint(witness)
    }
}

#[derive(Debug, Clone)]
struct MulNode(Arc<dyn Node>, Arc<dyn Node>);

impl Node for MulNode {
    fn to_repr(&self) -> String {
        format!("* {} {}", self.0.to_repr(), self.1.to_repr())
    }

    fn get_max_columns(&self) -> usize {
        std::cmp::max(self.0.get_max_columns(), self.1.get_max_columns())
    }

    fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        let lhs = self.0.get_constraint(witness);
        let rhs = self.1.get_constraint(witness);
        lhs * rhs
    }
}

#[derive(Debug, Clone)]
pub struct Expression(Arc<dyn Node>);

impl Expression {
    pub(super) fn var(column_index: usize) -> Self {
        Self(Arc::new(VariableNode(column_index)))
    }

    pub fn to_repr(&self) -> String {
        self.0.to_repr()
    }

    pub(super) fn get_max_columns(&self) -> usize {
        self.0.get_max_columns()
    }

    pub(super) fn get_constraint(&self, witness: &[Polynomial]) -> Polynomial {
        self.0.get_constraint(witness).trim()
    }

    pub fn square(self) -> Expression {
        self.clone() * self
    }
}

impl From<Scalar> for Expression {
    fn from(value: Scalar) -> Self {
        Self(Arc::new(ConstantNode(value)))
    }
}

impl From<u64> for Expression {
    fn from(value: u64) -> Self {
        Self(Arc::new(ConstantNode(value.into())))
    }
}

impl Add<Expression> for Expression {
    type Output = Expression;

    fn add(self, rhs: Self) -> Self::Output {
        Expression(Arc::new(AddNode(self.0, rhs.0)))
    }
}

impl Add<Scalar> for Expression {
    type Output = Expression;

    fn add(self, rhs: Scalar) -> Self::Output {
        Expression(Arc::new(AddNode(self.0, Arc::new(ConstantNode(rhs)))))
    }
}

impl Add<Expression> for Scalar {
    type Output = Expression;

    fn add(self, rhs: Expression) -> Self::Output {
        Expression(Arc::new(AddNode(Arc::new(ConstantNode(self)), rhs.0)))
    }
}

impl Sub<Expression> for Expression {
    type Output = Expression;

    fn sub(self, rhs: Self) -> Self::Output {
        Expression(Arc::new(SubNode(self.0, rhs.0)))
    }
}

impl Sub<Scalar> for Expression {
    type Output = Expression;

    fn sub(self, rhs: Scalar) -> Self::Output {
        Expression(Arc::new(SubNode(self.0, Arc::new(ConstantNode(rhs)))))
    }
}

impl Sub<Expression> for Scalar {
    type Output = Expression;

    fn sub(self, rhs: Expression) -> Self::Output {
        Expression(Arc::new(SubNode(Arc::new(ConstantNode(self)), rhs.0)))
    }
}

impl Neg for Expression {
    type Output = Expression;

    fn neg(self) -> Self::Output {
        Expression(Arc::new(NegNode(self.0)))
    }
}

impl Mul<Expression> for Expression {
    type Output = Expression;

    fn mul(self, rhs: Self) -> Self::Output {
        Expression(Arc::new(MulNode(self.0, rhs.0)))
    }
}

impl Mul<Scalar> for Expression {
    type Output = Expression;

    fn mul(self, rhs: Scalar) -> Self::Output {
        Expression(Arc::new(MulNode(self.0, Arc::new(ConstantNode(rhs)))))
    }
}

impl Mul<Expression> for Scalar {
    type Output = Expression;

    fn mul(self, rhs: Expression) -> Self::Output {
        Expression(Arc::new(MulNode(Arc::new(ConstantNode(self)), rhs.0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
