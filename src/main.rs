pub mod account;
pub mod public_key;

use crate::account::Account;

/// MAINNET chainID
pub const MAINNET: u8 = 'V' as u8;

// TODO: move code to lib.rs
fn main() {
    let account = Account::generate(MAINNET);
    println!("{:#?}", account);
}
