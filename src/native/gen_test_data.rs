use crate::MIXER_PARAMS;

use rand::{Rng, thread_rng};
use typenum::{U16};
use pairing::bn256::{Fr};

use crate::native::{Note, WithdrawPub, WithdrawSec};



use fawkes_crypto::native::{
    num::Num, 
    poseidon::{MerkleProof, poseidon_merkle_proof_root}
};



pub fn gen_test_data() -> (WithdrawPub<Fr>, WithdrawSec<Fr, U16>){
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