//! Simple Merkle commitment scheme.

use std::collections::BTreeMap;

use itertools::any;

use super::ops::{MerkleHasher, MerkleOps};
use super::prover::{MerkleDecommitment, MerkleProver};
use super::verifier::{MerkleVerificationError, MerkleVerifier};
use crate::core::backend::{Col, Column};
use crate::core::fields::m31::BaseField;

pub trait SimpleMerkleProver<B: MerkleOps<H>, H: MerkleHasher> {
    /// Commit to a set of columns of the same length.
    fn simple_commit(columns: Vec<&Col<B, BaseField>>) -> Self;

    /// Decommit the merkle tree on the given query positions.
    /// All columns must be of the same length.
    ///
    /// Returns the values at the queried positions and the decommitment.
    /// The queries are given as a mapping from the log size of the layer size to the queried
    /// positions on each column of that size (must contain the log size of the columns).
    ///
    /// The decommitment is a concatenation of authentication paths for each queried value.
    /// This is a non-batched inclusion proof.
    fn simple_decommit(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        columns: Vec<&Col<B, BaseField>>,
        adjacent_leaves: bool,
    ) -> (Vec<BaseField>, MerkleDecommitment<H>);
}

pub trait SimpleMerkleVerifier<H: MerkleHasher> {
    /// Verify the decommitment of the merkle tree on the given query positions.
    fn simple_verify(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        queried_values: Vec<BaseField>,
        decommitment: MerkleDecommitment<H>,
        adjacent_leaves: bool,
    ) -> Result<(), MerkleVerificationError>;
}

impl<B: MerkleOps<H>, H: MerkleHasher> SimpleMerkleProver<B, H> for MerkleProver<B, H> {
    fn simple_commit(columns: Vec<&Col<B, BaseField>>) -> Self {
        if columns.is_empty() {
            return Self {
                layers: vec![B::commit_on_layer(0, None, &[])],
            };
        }

        assert!(
            columns.iter().all(|c| c.len() == columns[0].len()),
            "All columns must be of the same length"
        );

        let mut layers: Vec<Col<B, H::Hash>> = Vec::new();
        let max_log_size = columns[0].len().ilog2();

        layers.push(B::commit_on_layer(max_log_size, None, &columns));

        for log_size in (0..max_log_size).rev() {
            layers.push(B::commit_on_layer(log_size, layers.last(), &vec![]));
        }

        layers.reverse();
        Self { layers }
    }

    fn simple_decommit(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        columns: Vec<&Col<B, BaseField>>,
        adjacent_leaves: bool,
    ) -> (Vec<BaseField>, MerkleDecommitment<H>) {
        let mut queried_values = vec![];
        let mut decommitment = MerkleDecommitment::empty();

        if !columns.is_empty() {
            assert!(
                columns.iter().all(|c| c.len() == columns[0].len()),
                "All columns must be of the same length"
            );

            let log_size = columns.first().expect("No columns").len().ilog2();
            let queries = queries_per_log_size
                .get(&log_size)
                .expect("No queries for log size");

            let queries = if adjacent_leaves {
                queries
                    .chunks_exact(2)
                    .map(|chunk| {
                        assert!(chunk[0] + 1 == chunk[1]);
                        chunk[0]
                    })
                    .collect()
            } else {
                queries.clone()
            };

            for query in queries {
                if !adjacent_leaves {
                    let node_values = columns.iter().map(|c| c.at(query));
                    queried_values.extend(node_values);
                }

                let mut node_index = query / 2;
                let mut auth_path = query + (1 << log_size);
                let mut next_log_size = log_size;

                if adjacent_leaves {
                    node_index /= 2;
                    auth_path /= 2;
                    next_log_size -= 1;
                }

                for layer_log_size in (0..next_log_size).rev() {
                    let previous_layer_hashes = self
                        .layers
                        .get(layer_log_size as usize + 1)
                        .expect("No previous layer hashes");

                    if auth_path % 2 == 0 {
                        decommitment
                            .hash_witness
                            .push(previous_layer_hashes.at(2 * node_index + 1));
                    } else {
                        decommitment
                            .hash_witness
                            .push(previous_layer_hashes.at(2 * node_index));
                    }

                    node_index /= 2;
                    auth_path /= 2;
                }
            }
        }

        (queried_values, decommitment)
    }
}

impl<H: MerkleHasher> SimpleMerkleVerifier<H> for MerkleVerifier<H> {
    fn simple_verify(
        &self,
        queries_per_log_size: &BTreeMap<u32, Vec<usize>>,
        queried_values: Vec<BaseField>,
        decommitment: MerkleDecommitment<H>,
        adjacent_leaves: bool,
    ) -> Result<(), MerkleVerificationError> {
        if self.column_log_sizes.is_empty() {
            return Ok(());
        }

        let log_size = *self.column_log_sizes.iter().next().unwrap();
        if any(self.column_log_sizes.iter(), |log_size| {
            log_size != log_size
        }) {
            return Err(MerkleVerificationError::MixedDegreeUnsupported);
        }

        let queries = queries_per_log_size
            .get(&log_size)
            .expect("No queries for log size");
        let n_columns = self
            .n_columns_per_log_size
            .get(&log_size)
            .expect("No columns for log size");

        let mut sibling_hashes = decommitment.hash_witness.iter();
        if !decommitment.column_witness.is_empty() {
            return Err(MerkleVerificationError::WitnessTooLong);
        }

        let mut queried_values_iter = queried_values.chunks(*n_columns);

        let queries = if adjacent_leaves {
            queries.chunks_exact(2).map(|chunk| chunk[0]).collect()
        } else {
            queries.clone()
        };

        for query in queries {
            let node_values = queried_values_iter
                .next()
                .ok_or(MerkleVerificationError::TooFewQueriedValues)?;
            let mut node = H::hash_node(None, &node_values);
            let mut auth_path = query + (1 << log_size);
            let mut next_log_size = log_size;

            if adjacent_leaves {
                assert!(auth_path % 2 == 0);
                let column_witness = queried_values_iter
                    .next()
                    .ok_or(MerkleVerificationError::WitnessTooShort)?;
                let sibling_node = H::hash_node(None, &column_witness);
                node = H::hash_node(Some((node, sibling_node)), &[]);
                auth_path /= 2;
                next_log_size -= 1;
            }

            for _ in 0..next_log_size {
                let sibling_node = *sibling_hashes
                    .next()
                    .ok_or(MerkleVerificationError::WitnessTooShort)?;
                if auth_path % 2 == 0 {
                    node = H::hash_node(Some((node, sibling_node)), &[]);
                } else {
                    node = H::hash_node(Some((sibling_node, node)), &[]);
                }
                auth_path /= 2;
            }

            if auth_path != 1 {
                return Err(MerkleVerificationError::WitnessTooLong);
            }

            if node != self.root {
                return Err(MerkleVerificationError::RootMismatch);
            }
        }

        if sibling_hashes.next().is_some() {
            return Err(MerkleVerificationError::WitnessTooLong);
        }

        if queried_values_iter.next().is_some() {
            return Err(MerkleVerificationError::TooManyQueriedValues);
        }

        Ok(())
    }
}
