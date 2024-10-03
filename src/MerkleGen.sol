// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {ArrayLib} from "./libraries/ArrayLib.sol";

/**
 * @notice Library for generating Merkle MultiProofs.
 * @author sonicskye.
 * @author kamuikatsurgi.
 */
library MerkleGen {
    using ArrayLib for *;

    bool private constant SOURCE_FROM_HASHES = true;
    bool private constant SOURCE_FROM_PROOF = false;

    /**
     * @notice Generates a Merkle MultiProof for the selected leaves.
     * @dev Constructs the necessary proof components and verifies the Merkle root.
     * @dev The computed root must match the actual root of the Merkle tree.
     * @param hashed_leaves The array of hashed leaves in the Merkle tree.
     * @param selected_indexes The indices of the leaves to include in the proof.
     * @return Sibling hashes required for the proof.
     * @return Flags indicating the source of each proof hash.
     * @return Merkle root of the tree.
     */
    function generateMultiproof(bytes32[] memory hashed_leaves, uint256[] memory selected_indexes)
        public
        pure
        returns (bytes32[] memory, bool[] memory, bytes32)
    {
        bytes32[] memory layer = hashed_leaves.copy();
        // Append with the same leaf if odd number of leaves
        if (layer.length % 2 == 1) {
            layer = layer.append(layer[layer.length - 1]);
        }
        // Create a two dimensional array
        bytes32[][] memory layers = new bytes32[][](1);
        layers[0] = layer;
        bytes32[] memory parent_layer;
        while (layer.length > 1) {
            parent_layer = _computeParentLayer(layer);
            layers = layers.append(parent_layer);
            layer = parent_layer;
        }

        bytes32[] memory proof_hashes;
        bool[] memory proof_source_flags;
        uint256[] memory indices = selected_indexes.copy();

        bytes32[] memory subproof;
        bool[] memory source_flags;
        for (uint256 i = 0; i < layers.length - 1; i++) {
            // Exclude the last layer because it's the root
            layer = layers[i];
            (indices, subproof, source_flags) = _proveSingleLayer(layer, indices);
            proof_hashes = proof_hashes.extend(subproof);
            proof_source_flags = proof_source_flags.extend(source_flags);
        }

        // Get leaves in hashed_leaves that are in selected_indexes
        bytes32[] memory indexed_leaves = new bytes32[](selected_indexes.length);
        for (uint256 i = 0; i < selected_indexes.length; i++) {
            indexed_leaves[i] = hashed_leaves[selected_indexes[i]];
        }

        bytes32 root = _verifyComputeRoot(indexed_leaves, proof_hashes, proof_source_flags);

        // Check if computed root is the same as the root of the tree
        require(root == layers[layers.length - 1][0], "Invalid root");

        // Convert proof_source_flags to bits and uint256
        uint256 proof_flag_bits = 0;
        bool[] memory proof_flag_bits_bool = new bool[](proof_source_flags.length);
        for (uint256 i = 0; i < proof_source_flags.length; i++) {
            if (proof_source_flags[i] == SOURCE_FROM_HASHES) {
                proof_flag_bits_bool[i] = true;
                proof_flag_bits = proof_flag_bits | (1 << i);
            } else {
                proof_flag_bits_bool[i] = false;
                proof_flag_bits = proof_flag_bits | (0 << i);
            }
        }

        return (proof_hashes, proof_flag_bits_bool, root);
    }

    /**
     * @notice Generates a Merkle proof for a single leaf in the Merkle tree.
     * @dev The function computes the proof and the root of the Merkle tree.
     * @param leaves The array of leaves used to build the Merkle tree.
     * @param leafIndex The index of the leaf for which the proof is generated.
     * @return proof An array of sibling hashes forming the Merkle proof for the leaf.
     * @return root The root hash of the Merkle tree.
     */
    function generateSingleProof(bytes32[] memory leaves, uint256 leafIndex)
        public
        pure
        returns (bytes32[] memory, bytes32)
    {
        require(leaves.length > 1, "MerkleGen: Leaves should be greater than 1.");

        // Append with the same leaf if odd number of leaves
        if (leaves.length % 2 == 1) {
            leaves = leaves.append(leaves[leaves.length - 1]);
        }

        bytes32[] memory proof = _getProof(leaves, leafIndex);
        bytes32 root = _getRoot(leaves);

        return (proof, root);
    }

    /**
     * @notice Hashes two leaf nodes to generate their parent node.
     * @param a First child node.
     * @param b Second child node.
     * @return h Hashed parent node.
     */
    function _hashLeafPairs(bytes32 a, bytes32 b) internal pure returns (bytes32 h) {
        if (a < b) {
            h = keccak256(abi.encodePacked(a, b));
        } else {
            h = keccak256(abi.encodePacked(b, a));
        }
    }

    /**
     * @notice Computes the parent layer in the Merkle tree from the current layer.
     * @dev If the current layer has an odd number of nodes, the last node is duplicated.
     * @param layer Current layer of the Merkle tree.
     * @return Computed parent layer.
     */
    function _computeParentLayer(bytes32[] memory layer) internal pure returns (bytes32[] memory) {
        if (layer.length == 1) {
            return layer;
        }

        if (layer.length % 2 == 1) {
            // Append with the same leaf if odd number of leaves
            layer = layer.append(layer[layer.length - 1]);
        }

        bytes32[] memory parent_layer;

        for (uint256 i = 0; i < layer.length; i += 2) {
            parent_layer = parent_layer.append(_hashLeafPairs(layer[i], layer[i + 1]));
        }

        return parent_layer;
    }

    /**
     * @notice Calculates the parent index for a given node index.
     * @param index Current node index.
     * @return Parent node index.
     */
    function _getParentIndex(uint256 index) internal pure returns (uint256) {
        return index / 2;
    }

    /**
     * @notice Calculates the sibling index of a given node index.
     * @param index Current node index.
     * @return Sibling node index.
     */
    function _getSiblingIndex(uint256 index) internal pure returns (uint256) {
        return index ^ 1;
    }

    /**
     * @notice Generates the proof components for a single layer in the Merkle tree.
     * @dev Processes selected indices to extract the necessary sibling hashes and flags.
     * @param layer Current layer of the Merkle tree.
     * @param indices Indices of the selected nodes in the current layer.
     * @return Indices for the next layer.
     * @return Sibling hashes required for the proof.
     * @return Flags indicating the source of each proof hash.
     */
    function _proveSingleLayer(bytes32[] memory layer, uint256[] memory indices)
        internal
        pure
        returns (uint256[] memory, bytes32[] memory, bool[] memory)
    {
        uint256[] memory auth_indices;
        uint256[] memory next_indices;
        bool[] memory source_flags;
        uint256 j = 0;

        while (j < indices.length) {
            uint256 x = indices[j];
            next_indices = next_indices.append(_getParentIndex(x));

            if (((j + 1) < indices.length) && (indices[j + 1] == _getSiblingIndex(x))) {
                j += 1;
                source_flags = source_flags.append(SOURCE_FROM_HASHES);
            } else {
                auth_indices = auth_indices.append(_getSiblingIndex(x));
                source_flags = source_flags.append(SOURCE_FROM_PROOF);
            }
            j += 1;
        }

        bytes32[] memory subProof = new bytes32[](auth_indices.length);
        for (uint256 i = 0; i < auth_indices.length; i++) {
            // Here, if the index is out of bounds, we use the last element of the layer
            if (layer.length - 1 < auth_indices[i]) {
                subProof[i] = layer[auth_indices[i] - 1];
            } else {
                subProof[i] = layer[auth_indices[i]];
            }
        }

        return (next_indices, subProof, source_flags);
    }

    /**
     * @notice Counts the number of occurrences of a specific flag in an array.
     * @param flags Array of boolean flags.
     * @param flag Flag to count.
     * @return Number of times the flag appears in the array.
     */
    function _helperCount(bool[] memory flags, bool flag) internal pure returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 0; i < flags.length; i++) {
            if (flags[i] == flag) {
                count += 1;
            }
        }
        return count;
    }

    /**
     * @notice Verifies and computes the Merkle root from the provided leaves and proof components.
     * @dev Reconstructs the Merkle root by iteratively hashing pairs based on the source flags.
     * @dev The total number of hashes must equal the number of source flags plus one.
     * @dev The number of proof hashes must match the number of `SOURCE_FROM_PROOF` flags.
     * @param leaves Selected leaves to be included in the proof.
     * @param proof_hashes Sibling hashes extracted from the proof.
     * @param proof_source_flags Flags indicating the source of each proof hash.
     * @return Computed Merkle root.
     */
    function _verifyComputeRoot(
        bytes32[] memory leaves,
        bytes32[] memory proof_hashes,
        bool[] memory proof_source_flags
    ) internal pure returns (bytes32) {
        uint256 total_hashes = leaves.length + proof_hashes.length - 1;
        require(total_hashes == proof_source_flags.length, "MerkleGen: Invalid total hashes.");
        require(
            _helperCount(proof_source_flags, SOURCE_FROM_PROOF) == proof_hashes.length,
            "MerkleGen: Invalid number of proof hashes."
        );

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
                } else {
                    a = hashes[hash_pos];
                    hash_pos += 1;
                }
            } else if (proof_source_flags[i] == SOURCE_FROM_PROOF) {
                a = proof_hashes[proof_pos];
                proof_pos += 1;
            }

            // Select b
            if (leaf_pos < leaves.length) {
                b = leaves[leaf_pos];
                leaf_pos += 1;
            } else {
                b = hashes[hash_pos];
                hash_pos += 1;
            }

            // Compute hash
            hashes[i] = _hashLeafPairs(a, b);
        }

        if (total_hashes > 0) {
            return hashes[total_hashes - 1];
        } else {
            return leaves[0];
        }
    }

    /**
     * @notice Initializes the Merkle tree by placing leaves in the correct positions.
     * @dev The tree is represented as a flat array, where the leaves occupy the last `leaves.length` positions.
     * @param leaves The array of leaves to be used for the Merkle tree.
     * @return A flat array representing the initialized tree, with leaves placed in the correct positions.
     */
    function _initTree(bytes32[] memory leaves) internal pure returns (bytes32[] memory) {
        require(leaves.length > 1, "MerkleGen: Leaves should be greater than 1.");

        bytes32[] memory tree = new bytes32[](2 * leaves.length - 1);

        uint256 index = tree.length - leaves.length;

        for (uint256 i = 0; i < leaves.length; i++) {
            tree[index + i] = leaves[i];
        }

        return tree;
    }

    /**
     * @notice Builds the complete Merkle tree from the given leaves.
     * @dev The function computes the parent nodes from the leaves up to the root of the tree.
     * @param leaves The array of leaves to build the Merkle tree.
     * @return A flat array representing the complete Merkle tree.
     */
    function _buildTree(bytes32[] memory leaves) internal pure returns (bytes32[] memory) {
        bytes32[] memory tree = _initTree(leaves);

        for (uint256 i = tree.length - 1; i > 1; i -= 2) {
            bytes32 left = tree[i - 1];
            bytes32 right = tree[i];
            bytes32 parent = _hashLeafPairs(left, right);
            uint256 parentIndex = (i - 1) / 2;
            tree[parentIndex] = parent;
        }

        return tree;
    }

    /**
     * @notice Returns the root hash of the Merkle tree constructed from the given leaves.
     * @dev The tree is built and the root (the first element of the tree) is returned.
     * @param leaves The array of leaves to build the Merkle tree.
     * @return The root hash of the Merkle tree.
     */
    function _getRoot(bytes32[] memory leaves) internal pure returns (bytes32) {
        require(leaves.length > 1, "MerkleGen: Data should be greater than 1.");

        bytes32[] memory tree = _buildTree(leaves);

        return tree[0];
    }

    /**
     * @notice Generates the Merkle proof for a specific leaf index.
     * @dev Traverses the tree from the leaf at the specified index to the root, collecting the sibling hashes required for proof.
     * @param leaves The array of leaves for the Merkle tree.
     * @param index The index of the leaf for which the proof is generated.
     * @return An array of sibling hashes forming the Merkle proof for the leaf at the specified index.
     */
    function _getProof(bytes32[] memory leaves, uint256 index) internal pure returns (bytes32[] memory) {
        require(leaves.length > 1, "MerkleGen: Leaves should be greater than 1.");

        bytes32[] memory tree = _buildTree(leaves);

        uint256 proofLength = _log2CeilBitMagic(leaves.length);
        bytes32[] memory proof = new bytes32[](proofLength);

        uint256 proofIndex = 0;

        uint256 currentIndex = leaves.length - 1 + index;

        while (currentIndex > 0) {
            uint256 siblingIndex = (currentIndex % 2 == 0) ? currentIndex - 1 : currentIndex + 1;

            if (siblingIndex < tree.length) {
                proof[proofIndex] = tree[siblingIndex];
                proofIndex++;
            }

            currentIndex = (currentIndex - 1) / 2;
        }

        bytes32[] memory finalProof = new bytes32[](proofIndex);
        for (uint256 i = 0; i < proofIndex; i++) {
            finalProof[i] = proof[i];
        }

        return finalProof;
    }

    /**
     * @notice Computes the ceiling of the base-2 logarithm of a number using bitwise operations.
     * @dev This is an optimized method to compute the log2 value, rounded up to the nearest integer.
     * @param x The number for which the log2 ceiling is computed.
     * @return The smallest integer greater than or equal to log2(x).
     */
    function _log2CeilBitMagic(uint256 x) internal pure returns (uint256) {
        if (x <= 1) {
            return 0;
        }

        uint256 msb = 0;
        uint256 _x = x;

        if (x >= 2 ** 128) {
            x >>= 128;
            msb += 128;
        }
        if (x >= 2 ** 64) {
            x >>= 64;
            msb += 64;
        }
        if (x >= 2 ** 32) {
            x >>= 32;
            msb += 32;
        }
        if (x >= 2 ** 16) {
            x >>= 16;
            msb += 16;
        }
        if (x >= 2 ** 8) {
            x >>= 8;
            msb += 8;
        }
        if (x >= 2 ** 4) {
            x >>= 4;
            msb += 4;
        }
        if (x >= 2 ** 2) {
            x >>= 2;
            msb += 2;
        }
        if (x >= 2 ** 1) {
            msb += 1;
        }

        uint256 lsb = (~_x + 1) & _x;

        if ((lsb == _x) && (msb > 0)) {
            return msb;
        } else {
            return msb + 1;
        }
    }
}
