/*
A library for handling array operations needed by MerkleGen contract.

Contributors:
- sonicskye

*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library ArrayLib {

    // Bytes32 array operations

    function append(bytes32[] memory arr, bytes32 val) public pure returns (bytes32[] memory) {
        bytes32[] memory newArr = new bytes32[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    function extend(bytes32[] memory arr, bytes32[] memory vals) public pure returns (bytes32[] memory) {
        bytes32[] memory newArr = new bytes32[](arr.length + vals.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        for (uint256 i = 0; i < vals.length; i++) {
            newArr[arr.length + i] = vals[i];
        }
        return newArr;
    }

    // Bytes32 two dimensional array operations

    function append(bytes32[][] memory arr, bytes32[] memory val) public pure returns (bytes32[][] memory) {
        bytes32[][] memory newArr = new bytes32[][](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    // Copy bytes32 array
    function copy(bytes32[] memory arr) public pure returns (bytes32[] memory) {
        bytes32[] memory newArr = new bytes32[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        return newArr;
    }

    // Uint256 array operations

    function append(uint256[] memory arr, uint256 val) public pure returns (uint256[] memory) {
        uint256[] memory newArr = new uint256[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    function extend(uint256[] memory arr, uint256[] memory vals) public pure returns (uint256[] memory) {
        uint256[] memory newArr = new uint256[](arr.length + vals.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        for (uint256 i = 0; i < vals.length; i++) {
            newArr[arr.length + i] = vals[i];
        }
        return newArr;
    }

    function copy(uint256[] memory arr) public pure returns (uint256[] memory) {
        uint256[] memory newArr = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        return newArr;
    }

    // Bool array operations

    function append(bool[] memory arr, bool val) public pure returns (bool[] memory) {
        bool[] memory newArr = new bool[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    function extend(bool[] memory arr, bool[] memory vals) public pure returns (bool[] memory) {
        bool[] memory newArr = new bool[](arr.length + vals.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        for (uint256 i = 0; i < vals.length; i++) {
            newArr[arr.length + i] = vals[i];
        }
        return newArr;
    }
}