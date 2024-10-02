#![no_main]

use cfdkim::{verify_email_with_public_key, DkimPublicKey};
use mailparse::parse_mail;
use sp1_zkvm::io::{commit, read, read_vec};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let from_domain = read::<String>();
    let raw_email = read_vec();
    let public_key_type = read::<String>();
    let public_key_vec = read_vec();

    let email = parse_mail(&raw_email).unwrap();
    let public_key = DkimPublicKey::from_vec_with_type(&public_key_vec, &public_key_type);

    let result = verify_email_with_public_key(&from_domain, &email, &public_key).unwrap();
    if let Some(_) = &result.error() {
        commit(&false);
    } else {
        commit(&true);
    }
}
