// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_plonk::prelude::*;
use rand_core::OsRng;
use std::fs;
use dusk_jubjub::Scalar;
use dusk_poseidon::sponge;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// Implements a circuit that checks:
// 1) PoseidonHash(r||s) = h_rs
// where "||"is the concatenation operator and "h" is a PI
// 2) JubJub::GENERATOR * e(JubJubScalar) = f where F is a PI
#[derive(Debug, Default)]
pub struct PreImageCircuit {
    r: BlsScalar,
    s: BlsScalar,
    h_rs: BlsScalar,
    e: JubJubScalar,
    f: JubJubAffine,
}

impl Circuit for PreImageCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];
    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> std::result::Result<(), Error> {
        let r = composer.append_witness(self.r);
        let s = composer.append_witness(self.s);

        let hash_rs = composer.append_public_witness(self.h_rs);


        //This return a witness of PoseidonHash(r||s)
        let hash_witness_rs = sponge::gadget(composer, &[r,s]);


        composer.assert_equal(hash_witness_rs, hash_rs);


        let e = composer.append_witness(self.e);
        let scalar_mul_result = composer
            .component_mul_generator(e, dusk_jubjub::GENERATOR_EXTENDED);

        // Apply the constraint
        composer.assert_equal_public_point(scalar_mul_result, self.f);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![self.h_rs.into(), self.f.into()]
    }

    fn padded_gates(&self) -> usize {
        1 << 11
    }
}

#[test]
fn test_pre_image() -> Result<()> {

    // Generate CRS
    let pp = PublicParameters::setup(1 << 15, &mut OsRng)
        .expect("Failed generating the public parameters.");


    // Initialize the circuit
    let mut circuit = PreImageCircuit::default();

    // Compile/preprocess the circuit
    let (pk_p, vd_p) = circuit.compile(&pp).expect("Failed to compile circuit");;


    let a = BlsScalar::from(77u64);
    let b = BlsScalar::from(10);
    let hash_rs = sponge::hash(&[a,b]);
    // Prover POV
    let proof = {
        let mut circuit = PreImageCircuit {
            r: a,
            s: b,
            h_rs: hash_rs,//25
            e: JubJubScalar::from(7u64),
            f: JubJubAffine::from(
                dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(7u64),
            ),
        };

        circuit.prove(&pp, &pk_p, b"Test")//, &mut OsRng)
    }.expect("Failed to generate proof");

    let hash_rs_2 = sponge::hash(&[a,b]);

    // Verifier POV
    let public_inputs: Vec<PublicInputValue> = vec![
        hash_rs_2.into(),
        JubJubAffine::from(
            dusk_jubjub::GENERATOR_EXTENDED * JubJubScalar::from(7u64),
        )
            .into(),
    ];

    Ok(PreImageCircuit::verify(
        &pp,
        &vd_p,
        &proof,
        &public_inputs,
        b"Test",
    ).expect("Fail to verify"))
}
