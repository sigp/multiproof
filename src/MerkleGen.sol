/*
A contract for Generating Merkle MultiProof.

Contributors:
- sonicskye

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ArrayLib} from './libraries/ArrayLib.sol';

contract MerkleGen {

    using ArrayLib for *;

    bool SOURCE_FROM_HASHES = true;
    bool SOURCE_FROM_PROOF = false;

    function hash_internal_node(bytes32 a, bytes32 b) internal pure returns (bytes32 h) {
        if (a < b) {
            h = keccak256(abi.encodePacked(a, b));
        }
        else {
            h = keccak256(abi.encodePacked(b, a));
        }
    }

    function compute_next_layer(bytes32[] memory layer) internal pure returns (bytes32[] memory) {
        if (layer.length == 1) {
            return layer;
        } 

        if (layer.length % 2 == 1) {
            // Append with the same leaf if odd number of leaves
            layer = layer.append(layer[layer.length - 1]);
        }

        bytes32[] memory next_layer;
        for (uint256 i = 0; i < layer.length; i += 2) {
            next_layer = next_layer.append(hash_internal_node(layer[i], layer[i + 1]));
        }
        return next_layer;
    }

    function parent_index(uint256 index) internal pure returns (uint256) {
        return index / 2;
    }

    function sibling_index(uint256 index) internal pure returns (uint256) {
        return index ^ 1;
    }

    function prove_single_layer(bytes32[] memory layer, uint256[] memory indices) internal view returns (uint256[] memory, bytes32[] memory, bool[] memory) {
        uint256[] memory auth_indices;
        uint256[] memory next_indices;
        bool[] memory source_flags;
        uint256 j = 0;

        while (j < indices.length) {
            uint256 x = indices[j];
            next_indices = next_indices.append(parent_index(x));

            if ( ((j + 1) < indices.length) && (indices[j + 1] == sibling_index(x)) ) {
                j += 1;
                source_flags = source_flags.append(SOURCE_FROM_HASHES);
            }
            else {
                auth_indices = auth_indices.append(sibling_index(x));
                source_flags = source_flags.append(SOURCE_FROM_PROOF);
            }
            j += 1;
        }

        bytes32[] memory subProof = new bytes32[](auth_indices.length);
        for (uint256 i = 0; i < auth_indices.length; i++) {
            // Here, if the index is out of bounds, we use the last element of the layer
            if (layer.length - 1 < auth_indices[i]) {
                subProof[i] = layer[auth_indices[i]-1];
            } else {
                subProof[i] = layer[auth_indices[i]];
            }
        }

        return (next_indices, subProof, source_flags);
    }

    function helper_count(bool[] memory flags, bool flag) internal pure returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < flags.length; i++) {
            if (flags[i] == flag) {
                count += 1;
            }
        }
        return count;
    }

    function verify_compute_root(bytes32[] memory leaves, bytes32[] memory proof_hashes, bool[] memory proof_source_flags) internal view returns (bytes32) {
        uint256 total_hashes = leaves.length + proof_hashes.length - 1;
        require(total_hashes == proof_source_flags.length, "Invalid total hashes");
        require(helper_count(proof_source_flags, SOURCE_FROM_PROOF) == proof_hashes.length, "Invalid number of proof hashes");

        bytes32[] memory hashes = new bytes32[](total_hashes);
        // Fill hashes with leaves[0]
        for (uint256 i = 0; i < total_hashes; i++) {
            hashes[i] = leaves[0];
        }
        // Variables
        uint256 leaf_pos = 0;
        uint256 hash_pos = 0;
        uint256 proof_pos = 0;

        for (uint256 i = 0; i < total_hashes; i++) {
            bytes32 a;
            bytes32 b;

            // Select a
            if (proof_source_flags[i] == SOURCE_FROM_HASHES) {
                if (leaf_pos < leaves.length) {
                    a = leaves[leaf_pos];
                    leaf_pos += 1;
                }
                else {
                    a = hashes[hash_pos];
                    hash_pos += 1;
                }
            }
            else if (proof_source_flags[i] == SOURCE_FROM_PROOF) {
                a = proof_hashes[proof_pos];
                proof_pos += 1;
            }

            // Select b
            if (leaf_pos < leaves.length) {
                b = leaves[leaf_pos];
                leaf_pos += 1;
            }
            else {
                b = hashes[hash_pos];
                hash_pos += 1;
            }

            // Compute hash
            hashes[i] = hash_internal_node(a, b);
        }

        if (total_hashes > 0) {
            return hashes[total_hashes - 1];
        }
        else {
            return leaves[0];
        }

    }

    function gen(bytes32[] memory hashed_leaves, uint256[] memory selected_indexes) public view returns (bytes32[] memory, bool[] memory, bytes32){
        bytes32[] memory layer = hashed_leaves.copy();
        // If odd number of leaves, append with the same leaf
        if (layer.length % 2 == 1) {
            layer = layer.append(layer[layer.length - 1]);
        }
        // Create two dimensional array
        bytes32[][] memory layers = new bytes32[][](1);
        layers[0] = layer;
        bytes32[] memory next_layer;
        while (layer.length > 1) {
            next_layer = compute_next_layer(layer);
            layers = layers.append(next_layer);
            layer = next_layer;
        }

        bytes32[] memory proof_hashes;
        bool[] memory proof_source_flags;
        uint256[] memory indices = selected_indexes.copy();

        bytes32[] memory subproof;
        bool[] memory source_flags;
        for (uint256 i = 0; i < layers.length - 1; i++) { // Exclude the last layer because it is the root
            layer = layers[i];
            (indices, subproof, source_flags) = prove_single_layer(layer, indices);
            proof_hashes = proof_hashes.extend(subproof);
            proof_source_flags = proof_source_flags.extend(source_flags);
        }

        // Get leaves in hashed_leaves that are in selected_indexes
        bytes32[] memory indexed_leaves = new bytes32[](selected_indexes.length);
        for (uint256 i = 0; i < selected_indexes.length; i++) {
            indexed_leaves[i] = hashed_leaves[selected_indexes[i]];
        }

        bytes32 root = verify_compute_root(indexed_leaves, proof_hashes, proof_source_flags);

        // Check if computed root is the same as the root of the tree
        require(root == layers[layers.length-1][0], "Invalid root");

        // Convert proof_source_flags to bits and uint256
        uint256 proof_flag_bits = 0;
        bool[] memory proof_flag_bits_bool = new bool[](proof_source_flags.length);
        for (uint256 i = 0; i < proof_source_flags.length; i++) {
            if (proof_source_flags[i] == SOURCE_FROM_HASHES) {
                proof_flag_bits_bool[i] = true;
                proof_flag_bits = proof_flag_bits | (1 << i);
                
            }
            else {
                proof_flag_bits_bool[i] = false;
                proof_flag_bits = proof_flag_bits | (0 << i);
            }
        }

        return (proof_hashes, proof_flag_bits_bool, root);

    }

}