//! Mixed degree merkle tree, non-batched inclusion proof.

use std::collections::BTreeMap;

use super::ops::{MerkleHasher, MerkleOps};
use super::prover::{MerkleDecommitment};
use super::verifier::{MerkleVerificationError};
use crate::core::backend::Col;
use crate::core::fields::m31::BaseField;

pub trait FunctionalMerkleProver<B: MerkleOps<H>, H: MerkleHasher> {
    /// Commit to a set of columns of variable length.
    fn fp_commit(columns: Vec<&Col<B, BaseField>>) -> Self;

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
