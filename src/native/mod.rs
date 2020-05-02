use fawkes_crypto::native::num::Num;
use fawkes_crypto::native::poseidon::{poseidon_with_salt, PoseidonParams, MerkleProof};
use ff::{PrimeField};

use typenum::Unsigned;
use std::fmt::Debug;

use crate::constants::{SEED_NOTE_HASH, SEED_NULLIFIER};

#[derive(Debug, Clone)]
pub struct MixerParams<F:PrimeField> {
    pub hash: PoseidonParams<F>,
    pub compress: PoseidonParams<F>,
    pub eddsa: PoseidonParams<F>
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct Note<F:PrimeField> {
    pub secret: Num<F>
}

#[derive(Debug, Clone)]
pub struct Withdraw<F:PrimeField,H:Unsigned>(WithdrawPub<F>, WithdrawSec<F,H>,MixerParams<F>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct WithdrawPub<F:PrimeField> {
    pub root: Num<F>,
    pub nullifier: Num<F>,
    pub memo: Num<F>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize="", deserialize=""))]
pub struct WithdrawSec<F:PrimeField, H:Unsigned> {
    pub proof: MerkleProof<F, H>,
    pub note: Note<F>
}


impl<F:PrimeField> Note<F> {
    pub fn hash(&self, params:&MixerParams<F>) -> Num<F> {
        poseidon_with_salt(&[self.secret], SEED_NOTE_HASH, &params.hash)
    }

    pub fn nullifier(&self, params:&MixerParams<F>) -> Num<F> {
        poseidon_with_salt(&[self.secret], SEED_NULLIFIER, &params.hash)
    }
}