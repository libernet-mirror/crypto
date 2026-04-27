// Copyright 2025 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

use crate::bluesky::Scalar;
use wasm_bindgen::prelude::*;

pub mod bluesky;
pub mod fri;
pub mod fri2;
pub mod fri3;
pub mod merkle;
pub mod pcs;
pub mod plonk;
pub mod poly;
pub mod poseidon;
pub mod utils;
pub mod xits;

fn map_err<E: Into<anyhow::Error>>(error: E) -> JsValue {
    JsValue::from_str(error.into().to_string().as_str())
}

#[wasm_bindgen]
pub fn hash_to_scalar(message: &str) -> String {
    utils::format_scalar(utils::hash_to_scalar(message.as_bytes()))
}

#[wasm_bindgen]
pub fn poseidon_hash_t3(inputs: Vec<String>) -> Result<String, JsValue> {
    Ok(utils::format_scalar(poseidon::hash_t3(
        inputs
            .iter()
            .map(|input| input.parse())
            .collect::<anyhow::Result<Vec<Scalar>>>()
            .map_err(map_err)?
            .as_slice(),
    )))
}

#[wasm_bindgen]
pub fn poseidon_hash_t4(inputs: Vec<String>) -> Result<String, JsValue> {
    Ok(utils::format_scalar(poseidon::hash_t4(
        inputs
            .iter()
            .map(|input| input.parse())
            .collect::<anyhow::Result<Vec<Scalar>>>()
            .map_err(map_err)?
            .as_slice(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_scalar() {
        assert_eq!(
            hash_to_scalar("lorem ipsum dolor sit amet"),
            "0x69c562c4b39c86fc322322c86cfe5be83fbd472c6a38862bdd2f362bfa442ad6"
        );
        assert_eq!(
            hash_to_scalar("sator arepo tenet opera rotas"),
            "0x027880d47636bf77d55804a6cf2d5ec8f09427cdf678e2ed3d74c432cc2efa7a"
        );
    }

    #[test]
    fn test_poseidon_hash_t3() {
        assert_eq!(
            poseidon_hash_t3(vec![
                "0x255144e621ed2a6e5717c3164e8cf146b4a757369db8ea63c739843ef1c16364".to_string(),
                "0x638a49ba49c18944c21827cbab35b970ef3763a4639ec2d30eaf1fc8ee6da2ec".to_string()
            ])
            .unwrap(),
            "0x33f0535dce3a9f54529b9d2acf505701a4ca77245bc03aa0c42a5d34e1a3a42c"
        );
    }

    #[test]
    fn test_poseidon_hash_t4() {
        assert_eq!(
            poseidon_hash_t4(vec![
                "0x255144e621ed2a6e5717c3164e8cf146b4a757369db8ea63c739843ef1c16364".to_string(),
                "0x638a49ba49c18944c21827cbab35b970ef3763a4639ec2d30eaf1fc8ee6da2ec".to_string()
            ])
            .unwrap(),
            "0x23b2a74798a47ebbdb9348d81e4f082f3f076d97fff5933a798f22d4799dde79"
        );
    }
}
