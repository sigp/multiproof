// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {MerkleProof} from '@openzeppelin/contracts/utils/cryptography/MerkleProof.sol';

contract Prover {

    function prove(bytes32[] calldata proof, bool[] calldata proofFlags, bytes32 root, bytes32[] calldata leaves) public pure returns(bool) {

        return MerkleProof.multiProofVerifyCalldata(proof, proofFlags, root, leaves);
    }
}