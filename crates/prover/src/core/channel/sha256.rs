use std::iter;

use sha2::{Digest, Sha256};

use super::ChannelTime;
use crate::core::channel::Channel;
use crate::core::fields::cm31::CM31;
use crate::core::fields::m31::{BaseField, N_BYTES_FELT, P};
use crate::core::fields::qm31::{SecureField, QM31};
use crate::core::vcs::sha256_hash::Sha256Hash;

#[derive(Default, Debug, Clone)]
/// A channel.
pub struct Sha256Channel {
    digest: Sha256Hash,
    pub channel_time: ChannelTime,
}

impl Sha256Channel {
    pub fn digest(&self) -> Sha256Hash {
        self.digest
    }

    pub fn update_digest(&mut self, new_digest: Sha256Hash) {
        self.digest = new_digest;
        self.channel_time.inc_challenges();
    }

    /// Generates a uniform random vector of BaseField elements.
    fn draw_base_felts<const N: usize>(&mut self) -> [BaseField; N] {
        assert!(N <= Self::BYTES_PER_HASH);
        // Repeats hashing with an increasing counter until getting a good result.
        // Retry probability for each round is ~ 2^(-28).
        loop {
            let words: [u32; N] = self
                .draw_random_bytes()
                .chunks_exact(N_BYTES_FELT) // 4 bytes per u32.
                .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
                .take(N)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            // Retry if not all the words are in the range [0, 2P).
            if words.iter().all(|x| *x < 2 * P) {
                return words
                    .into_iter()
                    .map(|x| BaseField::reduce(x as u64))
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
            }
        }
    }
}

impl Channel for Sha256Channel {
    const BYTES_PER_HASH: usize = 32;

    fn mix_felts(&mut self, felts: &[SecureField]) {
        let mut hasher = Sha256::new();
        hasher.update(self.digest);

        for felt in felts {
            hasher.update(felt.0 .0 .0.to_be_bytes());
            hasher.update(felt.0 .1 .0.to_be_bytes());
            hasher.update(felt.1 .0 .0.to_be_bytes());
            hasher.update(felt.1 .1 .0.to_be_bytes());
        }

        self.update_digest(hasher.finalize().as_slice().into());
    }

    fn mix_u64(&mut self, nonce: u64) {
        // mix_u64 is called during PoW. However, later we plan to replace it by a Bitcoin block
        // inclusion proof, then this function would never be called.
        let mut hasher = Sha256::new();
        hasher.update(self.digest);
        hasher.update(nonce.to_be_bytes());
        self.update_digest(hasher.finalize().as_slice().into());
    }

    fn draw_felt(&mut self) -> SecureField {
        let coords = self.draw_base_felts::<4>();
        QM31(CM31(coords[0], coords[1]), CM31(coords[2], coords[3]))
    }

    fn draw_felts(&mut self, n_felts: usize) -> Vec<SecureField> {
        let mut felts = iter::from_fn(|| Some(self.draw_base_felts::<8>())).flatten();
        let secure_felts = iter::from_fn(|| {
            Some(SecureField::from_m31_array([
                felts.next()?,
                felts.next()?,
                felts.next()?,
                felts.next()?,
            ]))
        });
        secure_felts.take(n_felts).collect()
    }

    fn draw_random_bytes(&mut self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, self.digest);
        // Downcast to u32 to match the Simplicity code and avoid cross-platform issues.
        let n_sent: u32 = self.channel_time.n_sent.try_into().unwrap();
        Digest::update(&mut hasher, n_sent.to_be_bytes());
        let res = hasher.finalize().to_vec();
        self.channel_time.inc_sent();
        res
    }

    fn trailing_zeros(&self) -> u32 {
        let mut n_bits = 0;
        for byte in self.digest.0.iter().rev() {
            if *byte == 0 {
                n_bits += 8;
            } else {
                n_bits += byte.leading_zeros();
                break;
            }
        }
        n_bits
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::core::channel::{Channel, Sha256Channel};
    use crate::core::fields::qm31::SecureField;
    use crate::{m31, qm31};

    #[test]
    fn test_draw_random_bytes() {
        let mut channel = Sha256Channel::default();

        let first_random_bytes = channel.draw_random_bytes();

        // Assert that next random bytes are different.
        assert_ne!(first_random_bytes, channel.draw_random_bytes());

        // Test vector for validating the Simfony code.
        assert_eq!(
            first_random_bytes,
            hex::decode("2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb")
                .unwrap()
        );
    }

    #[test]
    pub fn test_draw_felt() {
        let mut channel = Sha256Channel::default();

        let first_random_felt = channel.draw_felt();
        assert_eq!(
            first_random_felt,
            qm31!(1840668629, 533944055, 1922121815, 459001195)
        );

        // Assert that next random felt is different.
        let second_random_felt = channel.draw_felt();
        assert_eq!(
            second_random_felt,
            qm31!(559458448, 1834888235, 1610726090, 1135320235)
        );
    }

    #[test]
    pub fn test_draw_felts() {
        let mut channel = Sha256Channel::default();

        let mut random_felts = channel.draw_felts(5);
        random_felts.extend(channel.draw_felts(4));

        // Assert that all the random felts are unique.
        assert_eq!(
            random_felts.len(),
            random_felts.iter().collect::<BTreeSet<_>>().len()
        );
    }

    #[test]
    pub fn test_mix_felts() {
        let mut channel = Sha256Channel::default();
        let initial_digest = channel.digest;
        let felts: Vec<SecureField> = (0..2)
            .map(|i| SecureField::from(m31!(i + 1923782)))
            .collect();

        channel.mix_felts(felts.as_slice());

        assert_ne!(initial_digest, channel.digest);
    }
}
