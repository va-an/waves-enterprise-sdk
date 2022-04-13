use crate::public_key::{generate_seed, secure_hash, PublicKey};
use base58::ToBase58;
use curve25519_dalek::{constants, scalar::Scalar};
use ed25519_dalek::*;
use sha2::{Digest, Sha256};

// TODO: need to store `chain id`?
#[derive(Debug)]
pub struct Account {
    pub seed: String,
    pub address: String,
    pub public_key: String,
    pub private_key: String,
}

impl Account {
    pub fn generate(chain_id: u8) -> Account {
        let seed = generate_seed();
        Account::from_seed(&seed, chain_id)
    }

    pub fn from_seed(seed: &str, chain_id: u8) -> Account {
        let seed_bytes = seed.as_bytes().to_vec();
        let nonce = [0, 0, 0, 0].to_vec();

        let mut sk = [0u8; SECRET_KEY_LENGTH];

        let acc_seed = secure_hash([nonce, seed_bytes].concat().as_slice());
        let hash_seed = &Sha256::digest(acc_seed.as_slice());

        sk.copy_from_slice(hash_seed);
        sk[0] &= 248;
        sk[31] &= 127;
        sk[31] |= 64;

        let ed_pk = &Scalar::from_bits(sk) * &constants::ED25519_BASEPOINT_TABLE;
        let pk = ed_pk.to_montgomery().to_bytes();

        Account {
            seed: seed.to_string(),
            address: PublicKey(pk).to_address(chain_id),
            public_key: pk.to_base58(),
            private_key: sk.to_base58(),
        }
    }
}
