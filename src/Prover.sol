// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @notice Wrapper library for proving Merkle MultiProofs.
 * @author sonicskye.
 * @author kamuikatsurgi.
 */
library Prover {
    /**
     * @notice Verifies the validity of a Merkle MultiProof.
     * @dev Uses OpenZeppelin's `multiProofVerifyCalldata` to validate a multiproof.
     * @param proof The array of sibling hashes that help prove the inclusion of the leaves.
     * @param flag A boolean array that indicates whether each node is from the proof or hashes.
     * @param root Root hash of the Merkle tree.
     * @param leaves Leaf nodes that are being proved to be part of the Merkle tree.
     * @return A boolean value indicating whether the proof is valid or not.
     */
    function proveMultiProof(bytes32[] calldata proof, bool[] calldata flag, bytes32 root, bytes32[] calldata leaves)
        public
        pure
        returns (bool)
    {
        return MerkleProof.multiProofVerifyCalldata(proof, flag, root, leaves);
    }

    /**
     * @notice Verifies the validity of a Merkle SingleProof.
     * @dev Uses OpenZeppelin's `verifyCalldata` to validate the proof.
     * @param proof The array of sibling hashes that help prove the inclusion of the leaf.
     * @param root Root hash of the Merkle tree.
     * @param leaf Leaf node that is being proved to be a part of the Merkle tree.
     * @return A boolean value indicating whether the proof is valid or not.
     */
    function proveSingleProof(bytes32[] calldata proof, bytes32 root, bytes32 leaf) public pure returns (bool) {
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }
}
