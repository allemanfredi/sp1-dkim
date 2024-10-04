use cfdkim::{dns, header::HEADER, public_key::retrieve_public_key, validate_header};
use mailparse::MailHeaderMap;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::env;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio;
use trust_dns_resolver::TokioAsyncResolver;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let from_domain = &args[2];
    let email_path = &args[3];

    let mut file = File::open(email_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let raw_email = contents.replace('\n', "\r\n");

    let email = mailparse::parse_mail(raw_email.as_bytes())?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let resolver = dns::from_tokio_resolver(resolver);

    for h in email.headers.get_all_headers(HEADER) {
        let value = String::from_utf8_lossy(h.get_value_raw());
        let dkim_header = validate_header(&value).unwrap();

        let signing_domain = dkim_header.get_required_tag("d");
        if signing_domain.to_lowercase() != from_domain.to_lowercase() {
            continue;
        }

        let public_key = retrieve_public_key(
            Arc::clone(&resolver),
            dkim_header.get_required_tag("d"),
            dkim_header.get_required_tag("s"),
        )
        .await
        .unwrap();

        let mut stdin = SP1Stdin::new();
        stdin.write::<String>(&from_domain.to_string());
        stdin.write_vec(raw_email.as_bytes().to_vec());
        stdin.write::<String>(&public_key.get_type());
        stdin.write_vec(public_key.to_vec());

        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);
        let mut proof = client.prove(&pk, stdin).run()?;

        // println!("result: {:?}", proof.public_values.read_slice());
        // println!("result: {:?}", proof.public_values.read_slice());
        // println!("result: {:?}", proof.public_values.read::<bool>());

        client.verify(&proof, &vk).expect("verification failed");

        proof.save("proof.json").expect("saving proof failed");
        return Ok(());
    }

    println!("Invalid from_domain.");
    Ok(())
}
