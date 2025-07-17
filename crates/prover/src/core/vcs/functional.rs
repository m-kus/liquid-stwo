//! Mixed degree merkle tree, non-batched inclusion proof.

use std::cmp::Reverse;
use std::collections::BTreeMap;

use itertools::Itertools;

use super::ops::{MerkleHasher, MerkleOps};
use super::prover::{MerkleDecommitment, MerkleProver};
use super::verifier::{MerkleVerificationError};
use crate::core::backend::{Col, Column};
use crate::core::fields::m31::BaseField;

pub trait FunctionalMerkleProver<B: MerkleOps<H>, H: MerkleHasher> {
    /// Decommit the merkle tree on the given query positions.
    ///
    /// Returns the values at the queried positions and the decommitment.
    /// The queries are given as a mapping from the log size of the layer size to the queried
    /// positions on each column of that size (must contain the log size of the columns).
    ///
    /// The decommitment is a concatenation of authentication paths for each queried value.
    /// This is a non-batched inclusion proof.
    fn fp_decommit(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        columns: Vec<&Col<B, BaseField>>,
    ) -> (Vec<BaseField>, MerkleDecommitment<H>);
}

pub trait FunctionalMerkleVerifier<H: MerkleHasher> {
    /// Verify the decommitment of the merkle tree on the given query positions.
    fn fp_verify(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        queried_values: Vec<BaseField>,
        decommitment: MerkleDecommitment<H>,
    ) -> Result<(), MerkleVerificationError>;
}

impl<B: MerkleOps<H>, H: MerkleHasher> FunctionalMerkleProver<B, H> for MerkleProver<B, H> {
   fn fp_decommit(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        columns: Vec<&Col<B, BaseField>>,
    ) -> (Vec<BaseField>, MerkleDecommitment<H>) {
        let mut queried_values = vec![];
        let mut decommitment = MerkleDecommitment::empty();

        if !columns.is_empty() {
            // Sort columns by layer.
            let mut columns_by_layer = columns
                .iter()
                .sorted_by_key(|c| Reverse(c.len()))
                .peekable();

            let log_size = columns.first().expect("No columns").len().ilog2();
            let queries = queries_per_log_size
                .get(&log_size)
                .expect("No queries for log size");

            for query in queries {
                let node_values = columns.iter().map(|c| c.at(*query));
                queried_values.extend(node_values);

                let mut prev_node_index = *query;
                let mut node_index = *query / 2;

                for layer_log_size in (0..self.layers.len() as u32).rev() {
                    let previous_layer_hashes = self.layers.get(layer_log_size as usize + 1);

                    if let Some(previous_layer_hashes) = previous_layer_hashes {
                        if prev_node_index % 2 == 0 {
                            decommitment
                                .hash_witness
                                .push(previous_layer_hashes.at(2 * node_index + 1));
                        } else {
                            decommitment
                                .hash_witness
                                .push(previous_layer_hashes.at(2 * node_index));
                        }

                        prev_node_index = node_index;
                        node_index /= 2;
                    }
                }
            }
        }

        (queried_values, decommitment)
    }
}
