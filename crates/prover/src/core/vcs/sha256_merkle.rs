use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ops::MerkleHasher;
use super::sha256_hash::Sha256Hash;
use crate::core::channel::{MerkleChannel, Sha256Channel};
use crate::core::fields::m31::BaseField;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct Sha256MerkleHasher;
impl MerkleHasher for Sha256MerkleHasher {
    type Hash = Sha256Hash;

    fn hash_node(
        children_hashes: Option<(Self::Hash, Self::Hash)>,
        column_values: &[BaseField],
    ) -> Self::Hash {
        let mut hasher = Sha256::new();

        if let Some((left_child, right_child)) = children_hashes {
            hasher.update(left_child);
            hasher.update(right_child);
        }

        for value in column_values {
            hasher.update(value.0.to_le_bytes());
        }

        Sha256Hash(hasher.finalize().into())
    }
}

#[derive(Default)]
pub struct Sha256MerkleChannel;

impl MerkleChannel for Sha256MerkleChannel {
    type C = Sha256Channel;
    type H = Sha256MerkleHasher;

    fn mix_root(channel: &mut Self::C, root: <Self::H as MerkleHasher>::Hash) {
        let mut hasher = Sha256::new();
        hasher.update(&channel.digest());
        hasher.update(&root.0);
        channel.update_digest(hasher.finalize().as_slice().into());
    }
}

#[cfg(test)]
mod tests {
    use num_traits::Zero;

    use super::Sha256MerkleChannel;
    use crate::core::channel::{MerkleChannel, Sha256Channel};
    use crate::core::fields::m31::BaseField;
    use crate::core::vcs::sha256_merkle::{Sha256Hash, Sha256MerkleHasher};
    use crate::core::vcs::test_utils::prepare_merkle;
    use crate::core::vcs::verifier::MerkleVerificationError;

    #[test]
    fn test_merkle_success() {
        let (queries, decommitment, values, verifier) = prepare_merkle::<Sha256MerkleHasher>();

        verifier.verify(&queries, values, decommitment).unwrap();
    }

    #[test]
    fn test_merkle_invalid_witness() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        decommitment.hash_witness[4] = Sha256Hash::default();

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_invalid_value() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        values[6] = BaseField::zero();

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::RootMismatch
        );
    }

    #[test]
    fn test_merkle_witness_too_short() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        decommitment.hash_witness.pop();

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooShort
        );
    }

    #[test]
    fn test_merkle_witness_too_long() {
        let (queries, mut decommitment, values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        decommitment.hash_witness.push(Sha256Hash::default());

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::WitnessTooLong
        );
    }

    #[test]
    fn test_merkle_column_values_too_long() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        values.insert(3, BaseField::zero());

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::TooManyQueriedValues
        );
    }

    #[test]
    fn test_merkle_column_values_too_short() {
        let (queries, decommitment, mut values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        values.remove(3);

        assert_eq!(
            verifier.verify(&queries, values, decommitment).unwrap_err(),
            MerkleVerificationError::TooFewQueriedValues
        );
    }

    #[test]
    fn test_merkle_channel() {
        let mut channel = Sha256Channel::default();
        let (_queries, _decommitment, _values, verifier) = prepare_merkle::<Sha256MerkleHasher>();
        Sha256MerkleChannel::mix_root(&mut channel, verifier.root);
        assert_eq!(channel.channel_time.n_challenges, 1);
    }
}
