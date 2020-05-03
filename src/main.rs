#[macro_use]
extern crate fawkes_crypto;

#[macro_use]
extern crate fawkes_crypto_derive;

#[macro_use]
extern crate serde;

pub mod circuit;
pub mod native;
pub mod constants;

use crate::native::gen_test_data::gen_test_data;

use crate::{
    circuit::{CWithdrawPub, CWithdrawSec, c_withdraw},
    native::{WithdrawPub, WithdrawSec, MixerParams}
};

use typenum::{U16};
use pairing::bn256::{Fr};

use fawkes_crypto::native::poseidon::PoseidonParams;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref MIXER_PARAMS: MixerParams<Fr> = MixerParams::<Fr> {
        hash: PoseidonParams::<Fr>::new(2, 8, 53),
        compress: PoseidonParams::<Fr>::new(3, 8, 53)
    };
}

groth16_circuit_bindings!(cli, WithdrawPub<Fr>, CWithdrawPub, WithdrawSec<Fr, U16>, CWithdrawSec, MIXER_PARAMS, c_withdraw, gen_test_data);

fn main() {
    cli::cli_main()
}