//! Differential-testing oracle backed by trailofbits/sequencehash-rs.
//!
//! Speaks the line protocol described in `../oracle.py`. A rejected request
//! (the reference panics on a SequenceMAC key shorter than 32 bytes) is
//! answered with "error".

use std::io::{self, BufRead, Write};
use std::panic;

use crypto_common::BlockSizeUser;
use digest::Digest;
use sequencehash::{SequenceHash, SequenceMAC};

fn run<T: BlockSizeUser + Clone + Digest>(key: &[u8], customizer: &[u8], inputs: &[Vec<u8>]) -> Vec<u8> {
    if key.is_empty() {
        let mut function = SequenceHash::<T>::new();
        inputs.iter().for_each(|item| function.add(item));
        function.result_with_customizer(&customizer)
    } else {
        let mut function = SequenceMAC::<T>::new(&key);
        inputs.iter().for_each(|item| function.add(item));
        function.result_with_customizer(&customizer)
    }
}

fn respond(line: &str) -> String {
    let mut fields = line.split('\t');
    let algorithm = fields.next().expect("missing algorithm");
    let decode = |field: &str| hex::decode(field).expect("invalid hex");
    let key = decode(fields.next().expect("missing key"));
    let customizer = decode(fields.next().expect("missing customizer"));
    let inputs: Vec<Vec<u8>> = fields.map(decode).collect();

    let compute = match algorithm {
        "sha256" => run::<sha2::Sha256>,
        "sha512" => run::<sha2::Sha512>,
        "sha3_256" => run::<sha3::Sha3_256>,
        "sha3_512" => run::<sha3::Sha3_512>,
        "blake2b" => run::<blake2::Blake2b512>,
        "blake2s" => run::<blake2::Blake2s256>,
        other => panic!("unsupported algorithm {other}"),
    };

    match panic::catch_unwind(|| compute(&key, &customizer, &inputs)) {
        Ok(output) => hex::encode(output),
        Err(_) => "error".to_string(),
    }
}

fn main() {
    // Rejections are expected answers, so keep their panic messages quiet.
    panic::set_hook(Box::new(|_| {}));
    let mut stdout = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        writeln!(stdout, "{}", respond(&line.expect("stdin"))).expect("stdout");
        stdout.flush().expect("stdout");
    }
}
