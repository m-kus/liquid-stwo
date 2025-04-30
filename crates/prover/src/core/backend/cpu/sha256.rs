use itertools::Itertools;

use crate::core::backend::CpuBackend;
use crate::core::fields::m31::BaseField;
use crate::core::vcs::ops::{MerkleHasher, MerkleOps};
use crate::core::vcs::sha256_hash::Sha256Hash;
use crate::core::vcs::sha256_merkle::Sha256MerkleHasher;

impl MerkleOps<Sha256MerkleHasher> for CpuBackend {
    fn commit_on_layer(
        log_size: u32,
        prev_layer: Option<&Vec<Sha256Hash>>,
        columns: &[&Vec<BaseField>],
    ) -> Vec<Sha256Hash> {
        (0..(1 << log_size))
            .map(|i| {
                Sha256MerkleHasher::hash_node(
                    prev_layer.map(|prev_layer| (prev_layer[2 * i], prev_layer[2 * i + 1])),
                    &columns.iter().map(|column| column[i]).collect_vec(),
                )
            })
            .collect()
    }
}
