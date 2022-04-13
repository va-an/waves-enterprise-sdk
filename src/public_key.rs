use base58::ToBase58;
use bip39::{Language, Mnemonic, MnemonicType};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use ed25519_dalek::*;
use sha2::Digest;
use sha3::Keccak256;

const ADDRESS_VERSION: u8 = 1;
const ADDRESS_LENGTH: usize = 26;

pub struct PublicKey(pub [u8; PUBLIC_KEY_LENGTH]);

impl PublicKey {
    pub fn to_address(&self, chain_id: u8) -> String {
        let mut buf = [0u8; ADDRESS_LENGTH];

        buf[0] = ADDRESS_VERSION;
        buf[1] = chain_id;
        buf[2..22].copy_from_slice(&secure_hash(&self.0)[..20]);

        let checksum = &secure_hash(&buf[..22])[..4];
        buf[22..].copy_from_slice(checksum);

        buf.to_base58()
    }
}

pub fn secure_hash(message: &[u8]) -> Vec<u8> {
    Keccak256::digest(&blake_hash(message)).to_vec()
}

fn blake_hash(message: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2bVar::new(32).unwrap();
    hasher.update(message);
    let mut buf = [0u8; 32];
    hasher.finalize_variable(&mut buf).unwrap();

    buf.to_vec()
}

pub fn generate_seed() -> String {
    let mnemonic = Mnemonic::new(MnemonicType::Words18, Language::English);
    let phrase: &str = mnemonic.phrase();
    format!("{}", phrase)
}
