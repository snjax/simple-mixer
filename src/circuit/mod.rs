use typenum::Unsigned;

use fawkes_crypto::native::num::Num;
use fawkes_crypto::circuit::num::CNum;
use fawkes_crypto::circuit::bool::CBool;
use fawkes_crypto::core::signal::Signal;
use fawkes_crypto::core::cs::ConstraintSystem;
use fawkes_crypto::circuit::poseidon::{CMerkleProof, c_poseidon_with_salt, c_poseidon_merkle_proof_root};


use crate::native::{MixerParams, Note, WithdrawPub, WithdrawSec};
use crate::constants::{SEED_NOTE_HASH, SEED_NULLIFIER};

#[derive(Clone, Signal)]
#[Value="Note<CS::F>"]
pub struct CNote<'a, CS:ConstraintSystem> {
    pub secret: CNum<'a, CS>
}

impl<'a,CS:ConstraintSystem> CNote<'a,CS> {
    pub fn hash(&self, params:&MixerParams<CS::F>) -> CNum<'a, CS> {
        c_poseidon_with_salt(&[self.secret.clone()], SEED_NOTE_HASH, &params.hash)
    }

    pub fn nullifier(&self, params:&MixerParams<CS::F>) -> CNum<'a, CS> {
        c_poseidon_with_salt(&[self.secret.clone()], SEED_NULLIFIER, &params.hash)
    }
}

#[derive(Clone, Signal)]
#[Value="WithdrawPub<CS::F>"]
pub struct CWithdrawPub<'a, CS:ConstraintSystem> {
    pub root: CNum<'a, CS>,
    pub nullifier: CNum<'a, CS>,
    pub memo: CNum<'a, CS>
}

#[derive(Clone, Signal)]
#[Value="WithdrawSec<CS::F,H>"]
pub struct CWithdrawSec<'a, CS:ConstraintSystem, H:Unsigned> {
    pub proof: CMerkleProof<'a, CS, H>,
    pub note: CNote<'a, CS>
}

pub fn c_withdraw<'a,CS:ConstraintSystem, H:Unsigned>(p:&CWithdrawPub<'a, CS>, s:&CWithdrawSec<'a, CS,H>, params:&MixerParams<CS::F>){
    //check nullifier
    (&p.nullifier - s.note.nullifier(params)).assert_zero();

    //check merkle proof
    let note_hash = s.note.hash(params);
    (&p.root - c_poseidon_merkle_proof_root(&note_hash, &s.proof, &params.compress)).assert_zero();

    //bind memo
    (&p.memo + Num::one()).assert_nonzero();
}

