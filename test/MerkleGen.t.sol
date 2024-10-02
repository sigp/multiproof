// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console} from "forge-std/Test.sol";
import {MerkleGen} from "../src/MerkleGen.sol";
import {Prover} from "../src/Prover.sol";

/**
 * @dev Tests for MerkleGen.sol.
 * @author sonicskye.
 */
contract MerkleGenTest is Test {
    /// @dev A test for standard 4-leaf Merkle tree with all known values.
    function test_prove_multi_proof_for_standard_4_leaf_merkle_tree() public {
        // Generate an array of bytes32 leaves
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = keccak256(abi.encodePacked(uint256(0)));
        leaves[1] = keccak256(abi.encodePacked(uint256(1)));
        leaves[2] = keccak256(abi.encodePacked(uint256(2)));
        leaves[3] = keccak256(abi.encodePacked(uint256(3)));

        // Generate selected indexes
        uint256[] memory indices = new uint256[](4);
        indices[0] = 0;
        indices[1] = 1;
        indices[2] = 2;
        indices[3] = 3;

        bytes32[] memory leaf_indexes = new bytes32[](indices.length);
        for (uint256 i = 0; i < indices.length; i++) {
            leaf_indexes[i] = leaves[indices[i]];
        }

        // Generate the proof
        (bytes32[] memory proof, bool[] memory proofFlagBits, bytes32 root) =
            MerkleGen.generateMultiproof(leaves, indices);

        emit log_named_bytes32("root", root);

        // Verify the proof
        assertTrue(Prover.proveMultiProof(proof, proofFlagBits, root, leaf_indexes));
    }

    /// @dev A fuzz test for proving MultiProofs for the Merkle tree.
    function testFuzz_prove_multi_proof(uint256 seed, bool[] memory select_leaves_, uint256 numLeaves) public pure {
        //uint256 numLeaves = 5;
        // Assume
        numLeaves = bound(numLeaves, 1, 10000);
        vm.assume(select_leaves_.length >= numLeaves);
        // Seed for generating leaves
        seed = bound(seed, 1 ether, 1000 ether);

        // Count the number of selected leaves
        uint256 numIndexes = 0;
        for (uint256 i = 0; i < numLeaves; i++) {
            if (select_leaves_[i]) {
                numIndexes += 1;
            }
        }

        vm.assume(numIndexes > 0 && numIndexes <= numLeaves);

        // Generate an array of bytes32 leaves
        bytes32[] memory leaves = new bytes32[](numLeaves);
        for (uint256 i = 0; i < numLeaves; i++) {
            leaves[i] = keccak256(abi.encodePacked(seed + i));
        }

        // Generate selected indexes
        uint256[] memory indices = new uint256[](numIndexes);
        bytes32[] memory leaf_indexes = new bytes32[](numIndexes);
        uint256 j = 0;
        for (uint256 i = 0; i < numLeaves; i++) {
            if (select_leaves_[i]) {
                indices[j] = i;
                leaf_indexes[j] = leaves[i];
                j += 1;
            }
        }

        // Generate the proof
        (bytes32[] memory proof, bool[] memory proofFlagBits, bytes32 root) =
            MerkleGen.generateMultiproof(leaves, indices);

        // Verify the proof
        assertTrue(Prover.proveMultiProof(proof, proofFlagBits, root, leaf_indexes));
    }

    /// @dev A test for standard 4-leaf Merkle tree with all known values.
    function test_prove_single_proof_for_standard_4_leaf_merkle_tree() public {
        // Generate an array of bytes32 leaves
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = keccak256(abi.encodePacked(uint256(0)));
        leaves[1] = keccak256(abi.encodePacked(uint256(1)));
        leaves[2] = keccak256(abi.encodePacked(uint256(2)));
        leaves[3] = keccak256(abi.encodePacked(uint256(3)));

        // Generate the proof and root
        (bytes32[] memory proof, bytes32 root) = MerkleGen.generateSingleProof(leaves, 1);

        emit log_named_bytes32("root", root);

        // Verify the proof
        assertTrue(Prover.proveSingleProof(proof, root, leaves[1]));
    }

    /// @dev A fuzz test for proving SingleProofs for the Merkle tree.
    function testFuzz_prove_single_proof(uint256 seed, uint256 numLeaves, uint256 randomLeafIndex) public {
        // Assume total number of leaves
        numLeaves = bound(numLeaves, 2, 10000);

        // Seed for generating leaves
        seed = bound(seed, 1 ether, 1000 ether);

        randomLeafIndex = bound(randomLeafIndex, 0, numLeaves - 1);

        // Generate an array of bytes32 leaves
        bytes32[] memory leaves = new bytes32[](numLeaves);
        for (uint256 i = 0; i < numLeaves; i++) {
            leaves[i] = keccak256(abi.encodePacked(seed + i));
        }

        // Generate the proof
        (bytes32[] memory proof, bytes32 root) = MerkleGen.generateSingleProof(leaves, randomLeafIndex);

        emit log_named_bytes32("root", root);

        // Verify the proof
        assertTrue(Prover.proveSingleProof(proof, root, leaves[randomLeafIndex]));
    }
}
