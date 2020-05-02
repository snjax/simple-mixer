#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

pub mod circuit;
pub mod native;
pub mod constants;

use crate::{
    circuit::{CWithdrawPub, CWithdrawSec, c_withdraw},
    native::{Note, WithdrawPub, WithdrawSec, MixerParams}
};

use rand::{Rng, thread_rng};
use typenum::{U16};
use pairing::bn256::{Fr};

use fawkes_crypto::{
    native::{num::Num, poseidon::{MerkleProof, poseidon_merkle_proof_root, PoseidonParams}}
};

use lazy_static::lazy_static;

lazy_static! {
    static ref MIXER_PARAMS: MixerParams<Fr> = MixerParams::<Fr> {
        hash: PoseidonParams::<Fr>::new(2, 8, 53),
        compress: PoseidonParams::<Fr>::new(3, 8, 53)
    };
}


fn gen_test_data() -> (WithdrawPub<Fr>, WithdrawSec<Fr, U16>){
    let mut rng = thread_rng();
    let ref params = MIXER_PARAMS;

    let proof = MerkleProof::<Fr,U16> {
        sibling: (0..16).map(|_| rng.gen()).collect(),
        path: (0..16).map(|_| rng.gen()).collect()
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

groth16_circuit_bindings!(cli, WithdrawPub<Fr>, CWithdrawPub, WithdrawSec<Fr, U16>, CWithdrawSec, MIXER_PARAMS, c_withdraw, gen_test_data);

fn main() {
    cli::cli_main()
}