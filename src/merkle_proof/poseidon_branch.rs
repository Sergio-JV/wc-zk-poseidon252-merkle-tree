// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Definitions of the merkle tree structure seen in Poseidon.
use crate::hashing_utils::scalar_storage::StorageScalar;
use crate::ARITY;
use canonical::Store;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use hades252::WIDTH;
use kelvin::{Branch, Compound};
use std::borrow::Borrow;

/// The `Poseidon` structure will accept a number of inputs equal to the arity.
///
/// The levels are ordered so the first element of `levels` is actually the bottom
/// level of the Kelvin tree.
#[derive(Debug, Clone, PartialEq)]
pub struct PoseidonBranch {
    /// Root of the Merkle Tree
    pub(crate) root: BlsScalar,
    /// Levels of the MerkleTree with it's corresponding leaves and offset.
    pub(crate) levels: Vec<PoseidonLevel>,
    /// Padding levels used to avoid variadic proofs in ZK circuits.
    /// This field is only relevant when we use `merkle_opening_gadget` fn
    /// otherways, it's simply ignored to check the `Scalar` usage of openings.
    pub(crate) padding_levels: Vec<PoseidonLevel>,
}

/// Provides a conversion between Branch and PoseidonBranch.
///
/// We extract the data from the `Branch` and store it appropiately
/// inside of the `PoseidonBranch` structure with the bitflags already
/// computed and the offsets pointing to the next levels pointing also to
/// the correct places.
impl<C, S> From<&Branch<'_, C, S>> for PoseidonBranch
where
    C: Compound<S>,
    C::Annotation: Borrow<StorageScalar>,
    S: Store,
{
    fn from(branch: &Branch<C, S>) -> PoseidonBranch {
        let mut poseidon_branch = PoseidonBranch::new();

        // Skip root and store it directly.
        poseidon_branch.root = branch
            .levels()
            .first()
            .expect("Unexpected Error: Kelvin Branch always has a root")
            .annotation()
            .expect("Unexpected Error: Kelvin Branch should always suceed applying annotations")
            .borrow()
            .to_owned()
            .into();
        // Store the levels with the bitflags already computed inside
        // of our PoseidonBranch structure.
        branch.levels().iter().rev().for_each(|level| {
            // Generate a default mutable `PoseidonLevel`, add the corresponding data
            // extracted from the `Branch` and push it to our poseidon branch previously
            // generated.
            poseidon_branch.levels.push({
                let mut pos_level = PoseidonLevel::default();
                let mut level_bitflags = 0u64;
                level
                    .children()
                    .iter()
                    // Copy in poseidon_branch the leave values of the actual level with an
                    // offset of one. So then we can add the bitflags at the beggining as the
                    // first item of the `WIDTH` ones.
                    .zip(pos_level.leaves.iter_mut().skip(1))
                    // If they're null, place a Scalar::zero() inside of them as stated on the
                    // Poseidon Hash paper.
                    .enumerate()
                    .for_each(|(idx, (src, dest))| {
                        *dest = match src.annotation() {
                            Some(annotation) => {
                                let stor_scalar: &StorageScalar =
                                    &(*annotation).borrow();
                                let scalar: &BlsScalar = stor_scalar.borrow();
                                // If the Annotation contains a value, we set the bitflag to 1.
                                // Since the first element will be the most significant bit of the
                                // bitflags, we need to shift it according to the `ARITY`.
                                //
                                // So for example:
                                // A level with: [Some(val), None, None, None] should correspond to
                                // Bitflags(1000). This means that we need to shift the first element
                                // by `ARITY - 1` to select the correct position of the bit
                                // and then decrease the shift order by `idx`.
                                level_bitflags |= 1u64 << ((ARITY - 1) - idx);
                                *scalar
                            }
                            None => BlsScalar::zero(),
                        };
                    });
                // Now we should have our bitflags value computed as well as the
                // `WIDTH` leaves set on the [1..4] positions of our poseidon_level.
                //
                // We need now to add the bitflags element in pos_level.leaves[0]
                pos_level.leaves[0] = BlsScalar::from(level_bitflags);
                // Once we have the level, we get the position where the hash of the previous level is
                // stored on the this level.
                // NOTE that this position is in respect of a WIDTH = `ARITY` so we need to
                // keep in mind that we've added an extra term (bitflags) and so, the index that
                // the branch is returning is indeed pointing one position before on the next level
                // that we will compute later. We just add 1 to it to inline the value with the
                // new `WIDTH`
                pos_level.offset = level.offset() + 1;
                pos_level
            })
        });
        poseidon_branch
    }
}

impl PoseidonBranch {
    /// Generates a default PoseidonBranch with the specified capacity for storing
    /// `n` levels inside.
    pub fn new() -> Self {
        PoseidonBranch {
            root: BlsScalar::zero(),
            levels: vec![],
            padding_levels: vec![],
        }
    }

    /// Generates a default PoseidonBranch with the specified capacity for storing
    /// `n` levels inside.
    pub fn with_capacity(n: usize) -> Self {
        PoseidonBranch {
            root: BlsScalar::zero(),
            levels: Vec::with_capacity(n),
            padding_levels: vec![],
        }
    }

    /// Get the root of the tree where the branch has been taken from.
    pub fn root(&self) -> BlsScalar {
        self.root
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Represents a Merkle-Tree Level inside of a `PoseidonBranch`.
/// It stores the leaves as `BlsScalar` and the offset which represents
/// the position on the level where the hash of the previous `PoseidonLevel`
/// is stored in.
pub struct PoseidonLevel {
    /// Position on the level where the hash of the previous `PoseidonLevel`
    /// is stored in.
    pub offset: usize,
    /// Leaves of the Level.
    pub leaves: [BlsScalar; WIDTH],
}

impl Default for PoseidonLevel {
    fn default() -> Self {
        PoseidonLevel {
            offset: 0usize,
            leaves: [BlsScalar::zero(); WIDTH],
        }
    }
}
