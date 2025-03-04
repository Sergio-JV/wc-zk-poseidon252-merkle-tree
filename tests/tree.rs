// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "canon")]

mod max_annotation;

use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::tree::{
    self, PoseidonAnnotation, PoseidonBranch, PoseidonTree,
};
use max_annotation::MockLeaf;
use rand_core::{CryptoRng, OsRng, RngCore};

use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use crate::max_annotation::TornadoLeaf;


const DEPTH: usize = 17;
const CAPACITY: usize = 15;
type Tree = PoseidonTree<MockLeaf, PoseidonAnnotation, DEPTH>;

//This was added by me
type Tree2 = PoseidonTree<TornadoLeaf, PoseidonAnnotation, DEPTH>;

struct MerkleOpeningCircuit {
    branch: PoseidonBranch<DEPTH>,
}

impl MerkleOpeningCircuit {
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        tree: &mut Tree,
    ) -> Self {
        let leaf = MockLeaf::random(rng);
        let pos = tree.push(leaf).expect("Failed to append to the tree");

        let branch = tree
            .branch(pos)
            .expect("Failed to read the tree for the branch")
            .expect(
                "Failed to fetch the branch of the created leaf from the tree",
            );

        Self { branch }
    }
}

impl Circuit for MerkleOpeningCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        use std::ops::Deref;

        let leaf: BlsScalar = *self.branch.deref();
        let leaf = composer.append_witness(leaf);

        let root = self.branch.root();
        let root = composer.append_witness(*root);

        let root_p =
            tree::merkle_opening::<DEPTH>(composer, &self.branch, leaf);

        composer.assert_equal(root_p, root);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY
    }
}


    #[test]
    fn tree_merkle_opening() {
        let label = b"dusk-network";
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let mut tree = Tree::default();

        let mut circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);
        let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

        //I do not know why this lines are repeated, so I have decided to comment those lines and the test
        //still works, until now I id not see any reason why those line should be included

        let mut tree = Tree::default();
        let mut circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);

        let proof = circuit
            .prove(&pp, &pk, label)
            .expect("Failed to generate proof");

        MerkleOpeningCircuit::verify(&pp, &vd, &proof, &[], label)
            .expect("Proof verification failed");
    }



    #[test]
    fn tree_merkle_opening_r_s() {


     let label = b"Test";
     let public_params = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let number_of_leaf = 1 << DEPTH;
        // Create the ZK keys
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng)
            .expect("Failed generating the public parameters.");

        let mut tree = Tree::default();
        let mut circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);
        let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

        // Instantiate a new tree
        let mut tree: PoseidonTree<MockLeaf, PoseidonAnnotation, DEPTH> =
            PoseidonTree::new();


        let mut rng = OsRng;

        // Append elements to the tree
        for i in 0..number_of_leaf {
            let r = BlsScalar::random(&mut rng);
            let s = BlsScalar::random(&mut rng);

            let r_s = sponge::hash(&[r, s]);

            let s_r = sponge::hash(&[s,r]);

            assert_ne!(r_s,s_r);

            let l = MockLeaf::f_bls(r_s);

            tree.push(l).expect("Failed appending to the tree");
        }

// Generate a ZK opening proof
        let proof = circuit
            .prove(&pp, &pk, label)
            .expect("Failed to generate proof");

// Verify the proof
        MerkleOpeningCircuit::verify(&pp, &vd, &proof, &[], label)
            .expect("Proof verification failed");
    }

