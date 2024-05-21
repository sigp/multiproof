/*
Testing for MerkleGen.sol.

Contributors:
- sonicskye

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {MerkleGen} from "../src/MerkleGen.sol";
import {Prover} from "../src/Prover.sol";

contract MerkleGenTest is Test {

    MerkleGen public merkleGen;
    Prover public prover;

    function setUp() public {
        merkleGen = new MerkleGen();
        prover = new Prover();
    }

    /// @notice A standard 4-leaf Merkle tree with all known values
    function test_prove() public {
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
        (bytes32[] memory proof, bool[] memory proofFlagBits, bytes32 root) = merkleGen.gen(leaves, indices);

        emit log_named_bytes32("root", root);

        // Verify the proof
        assertTrue(prover.prove(proof, proofFlagBits, root, leaf_indexes));
        
    }

    /// @notice A fuzz test for the Merkle tree
    function testFuzz_prove(uint256 seed, bool[] memory select_leaves_, uint256 numLeaves) public view {
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
        (bytes32[] memory proof, bool[] memory proofFlagBits, bytes32 root) = merkleGen.gen(leaves, indices);

        // Verify the proof
        assertTrue(prover.prove(proof, proofFlagBits, root, leaf_indexes));
    }



}