// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {Counter} from "../src/Counter.sol";
import {MerkleGen} from "../src/MerkleGen.sol";
import {Prover} from "../src/Prover.sol";

contract MerkleGenTest is Test {

    MerkleGen public merkleGen;
    Prover public prover;

    function setUp() public {
        merkleGen = new MerkleGen();
        prover = new Prover();
    }

    function test_prove() public {
        // Generate an array of bytes32 leaves
        bytes32[] memory leaves = new bytes32[](4);
        leaves[0] = keccak256(abi.encodePacked(uint256(0)));
        leaves[1] = keccak256(abi.encodePacked(uint256(1)));
        leaves[2] = keccak256(abi.encodePacked(uint256(2)));
        leaves[3] = keccak256(abi.encodePacked(uint256(3)));

        // compute H01
        bytes32 h01;
        if (leaves[0] < leaves[1]) {
            h01 = keccak256(abi.encodePacked(leaves[0], leaves[1]));
        }
        else {
            h01 = keccak256(abi.encodePacked(leaves[1], leaves[0]));
        }
        emit log_named_bytes32("h01", h01);
        // compute H23
        bytes32 h23;
        if (leaves[2] < leaves[3]) {
            h23 = keccak256(abi.encodePacked(leaves[2], leaves[3]));
        }
        else {
            h23 = keccak256(abi.encodePacked(leaves[3], leaves[2]));
        }
        emit log_named_bytes32("h23", h23);
        // compute H0123
        bytes32 h0123;
        if (h01 < h23) {
            h0123 = keccak256(abi.encodePacked(h01, h23));
        }
        else {
            h0123 = keccak256(abi.encodePacked(h23, h01));
        }

        emit log_named_bytes32("h0123", h0123);

        // Generate selected indexes
        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;

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



}