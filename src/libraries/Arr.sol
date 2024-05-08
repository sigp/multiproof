// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

library Arr {

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
}