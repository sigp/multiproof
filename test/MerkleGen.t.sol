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

        // Generate selected indexes
        uint256[] memory indices = new uint256[](2);
        indices[0] = 0;
        indices[1] = 1;

        // Generate the proof
        (bytes32[] memory proof, bool[] memory proofFlagBits, bytes32 root) = merkleGen.gen(leaves, indices);

        // Verify the proof
        assertTrue(prover.prove(proof, proofFlagBits, root, leaves));
        
    }



}