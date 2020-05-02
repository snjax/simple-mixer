#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

extern crate clap;

pub mod circuit;
pub mod native;
pub mod constants;

use clap::Clap;

use crate::circuit::{CWithdrawPub, CWithdrawSec, c_withdraw};
use crate::native::{Note, WithdrawPub, WithdrawSec, MixerParams};

use std::fs::File;
use std::io::{Write};



use typenum::{Unsigned, U16};
use pairing::bn256::{Fr, Bn256, Fq};
use fawkes_crypto::native::num::{Num};
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::core::cs::{Circuit, TestCS};
use fawkes_crypto::helpers::groth16::prover::{generate_keys, prove, Proof, Parameters};
use fawkes_crypto::helpers::groth16::verifier::{truncate_verifying_key, verify, TruncatedVerifyingKeyData, TruncatedVerifyingKey};

use fawkes_crypto::native::poseidon::{PoseidonParams, MerkleProof, poseidon_merkle_proof_root};
use fawkes_crypto::helpers::groth16::ethereum::generate_sol_data;
use rand::{Rng, thread_rng};



#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    command: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Generate a SNARK proof
    Prove(ProveOpts),
    /// Verify a SNARK proof
    Verify(VerifyOpts),
    /// Generate trusted setup parameters
    Setup(SetupOpts),
    /// Generate verifier smart contract
    GenerateVerifier(GenerateVerifierOpts),
    /// Generate test object
    GenerateTestData(GenerateTestDataOpts)
}

/// A subcommand for generating a SNARK proof
#[derive(Clap)]
struct ProveOpts {
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params", default_value = "params.bin")]
    params: String,
    /// Input object JSON file
    #[clap(short = "o", long = "object", default_value = "object.json")]
    object: String,
    /// Output file for proof JSON
    #[clap(short = "r", long = "proof", default_value = "proof.json")]
    proof: String,
    /// Output file for public inputs JSON
    #[clap(short = "i", long = "inputs", default_value = "inputs.json")]
    inputs: String,
}

/// A subcommand for verifying a SNARK proof
#[derive(Clap)]
struct VerifyOpts {
    /// Snark verification key
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
    /// Proof JSON file
    #[clap(short = "r", long = "proof", default_value = "proof.json")]
    proof: String,
    /// Public inputs JSON file
    #[clap(short = "i", long = "inputs", default_value = "inputs.json")]
    inputs: String,
}

/// A subcommand for generating a trusted setup parameters
#[derive(Clap)]
struct SetupOpts {
    /// Snark trusted setup parameters file
    #[clap(short = "p", long = "params", default_value = "params.bin")]
    params: String,
    /// Snark verifying key file
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
}

/// A subcommand for generating a Solidity verifier smart contract
#[derive(Clap)]
struct GenerateVerifierOpts {
    /// Snark verification key
    #[clap(short = "v", long = "vk", default_value = "verification_key.json")]
    vk: String,
    /// Output smart contract name
    #[clap(short = "s", long = "solidity", default_value = "verifier.sol")]
    solidity: String,
}

#[derive(Clap)]
struct GenerateTestDataOpts {
    /// Input object JSON file
    #[clap(short = "o", long = "object", default_value = "object.json")]
    object: String
}




struct Withdraw<H:Unsigned> {
    p:Option<WithdrawPub<Fr>>,
    s:Option<WithdrawSec<Fr, H>>,
    params:MixerParams<Fr>
}

circuit!(impl <H:Unsigned> Withdraw<H>, CWithdrawPub, CWithdrawSec, MixerParams, c_withdraw); 

impl Default for MixerParams<Fr> {
    fn default() -> Self {
        Self {
            hash: PoseidonParams::<Fr>::new(2, 8, 53),
            compress: PoseidonParams::<Fr>::new(3, 8, 53),
            eddsa: PoseidonParams::<Fr>::new(4, 8, 54)
        }
    }
}




fn gen_test_data<R:Rng, H:Unsigned>(rng: &mut R) -> (WithdrawPub<Fr>, WithdrawSec<Fr, H>){
    let ref params = MixerParams::default();

    let proof = MerkleProof::<Fr,H> {
        sibling: (0..H::USIZE).map(|_| rng.gen()).collect(),
        path: (0..H::USIZE).map(|_| rng.gen()).collect()
    };

    let note = Note::<Fr> {
        secret: rng.gen()
    };

    let hash = note.hash(params);
    let nullifier = note.nullifier(params);
    let root = poseidon_merkle_proof_root(hash, &proof, &params.compress);
    let memo: Num<Fr> = rng.gen();

    
    (WithdrawPub {root, nullifier, memo}, WithdrawSec {proof, note})
}



fn cli_setup(o:SetupOpts) {
    let params = generate_keys::<Bn256, Withdraw<U16>>();
    let vk_data_str = serde_json::to_string_pretty(&truncate_verifying_key(&params.vk).into_data()).unwrap();
    params.write(File::create(o.params).unwrap()).unwrap();
    std::fs::write(o.vk, &vk_data_str.into_bytes()).unwrap();
    println!("setup OK");
}

fn cli_generate_verifier(o: GenerateVerifierOpts) {
    let vk_str = std::fs::read_to_string(o.vk).unwrap();
    let vk :TruncatedVerifyingKeyData<Fq> = serde_json::from_str(&vk_str).unwrap();
    let sol_str = generate_sol_data(&vk);
    File::create(o.solidity).unwrap().write(&sol_str.into_bytes()).unwrap();
    println!("solidity verifier generated")
}

fn cli_verify(o:VerifyOpts) {
    let vk_str = std::fs::read_to_string(o.vk).unwrap();
    let proof_str = std::fs::read_to_string(o.proof).unwrap();
    let public_inputs_str = std::fs::read_to_string(o.inputs).unwrap();

    let vk = TruncatedVerifyingKey::<Bn256>::from_data(&serde_json::from_str(&vk_str).unwrap());
    let proof = Proof::<Bn256>::from_data(&serde_json::from_str(&proof_str).unwrap());
    let public_inputs = serde_json::from_str::<Vec<Num<Fr>>>(&public_inputs_str).unwrap().into_iter().map(|e| e.into_inner()).collect::<Vec<_>>();

    println!("Verify result is {}.", verify(&vk, &proof, &public_inputs).unwrap_or(false))
}

fn cli_generate_test_data(o:GenerateTestDataOpts) {
    let mut rng = thread_rng();
    let data = gen_test_data::<_, U16>(&mut rng);
    let data_str = serde_json::to_string_pretty(&data).unwrap();
    std::fs::write(o.object, &data_str.into_bytes()).unwrap();
    println!("test data generated")

}

fn cli_prove(o:ProveOpts) {
    let params = Parameters::<Bn256>::read(File::open(o.params).unwrap(), false).unwrap();
    let object_str = std::fs::read_to_string(o.object).unwrap();

    let (p, s) = serde_json::from_str::<(WithdrawPub<Fr>, WithdrawSec<Fr, U16>)>(&object_str).unwrap();
    let c = Withdraw {p:Some(p), s:Some(s), params:MixerParams::default()};
    let proof = prove(&c, &params);
    let inputs = c.get_inputs().unwrap();

    let proof_str = serde_json::to_string_pretty(&proof.into_data()).unwrap();
    let inputs_str = serde_json::to_string_pretty(&inputs).unwrap();

    std::fs::write(o.proof, &proof_str.into_bytes()).unwrap();
    std::fs::write(o.inputs, &inputs_str.into_bytes()).unwrap();
    
    println!("Proved")
}


fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        SubCommand::Prove(o) => cli_prove(o),
        SubCommand::Verify(o) => cli_verify(o),
        SubCommand::Setup(o) => cli_setup(o),
        SubCommand::GenerateVerifier(o) => cli_generate_verifier(o),
        SubCommand::GenerateTestData(o) => cli_generate_test_data(o)
    }    
}
