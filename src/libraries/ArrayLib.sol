// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @dev Library for array operations.
 * @author sonicskye.
 */
library ArrayLib {
    /**
     * @notice Appends a `bytes32` value to an existing `bytes32[]` array.
     * @param arr The array to which the value will be appended.
     * @param val The value to append to the array.
     * @return A new array containing all elements of `arr` with `val` appended.
     */
    function append(bytes32[] memory arr, bytes32 val) public pure returns (bytes32[] memory) {
        bytes32[] memory newArr = new bytes32[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    /**
     * @notice Combines two arrays by concatenating them.
     * @param arr The array to extend.
     * @param vals The array of values to append to `arr`.
     * @return A new array containing all elements of `arr` followed by all elements of `vals`.
     */
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

    /**
     * @notice Appends a `bytes32[]` array to a two-dimensional `bytes32[][]` array.
     * @param arr The 2D array to which the value will be appended.
     * @param val The array to append to the 2D array.
     * @return A new 2D array containing all elements of `arr` with `val` appended.
     */
    function append(bytes32[][] memory arr, bytes32[] memory val) public pure returns (bytes32[][] memory) {
        bytes32[][] memory newArr = new bytes32[][](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    /**
     * @notice Copies a `bytes32[]` array into a new array.
     * @param arr The array to copy.
     * @return A new array containing the same elements as `arr`.
     */
    function copy(bytes32[] memory arr) public pure returns (bytes32[] memory) {
        bytes32[] memory newArr = new bytes32[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        return newArr;
    }

    /**
     * @notice Appends a `uint256` value to an existing `uint256[]` array.
     * @param arr The array to which the value will be appended.
     * @param val The value to append to the array.
     * @return A new array containing all elements of `arr` with `val` appended.
     */
    function append(uint256[] memory arr, uint256 val) public pure returns (uint256[] memory) {
        uint256[] memory newArr = new uint256[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    /**
     * @notice Extends a `uint256[]` array with another `uint256[]` array.
     * @param arr The array to extend.
     * @param vals The array of values to append to `arr`.
     * @return A new array containing all elements of `arr` followed by all elements of `vals`.
     */
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

    /**
     * @notice Copies a `uint256[]` array into a new array.
     * @param arr The array to copy.
     * @return A new array containing the same elements as `arr`.
     */
    function copy(uint256[] memory arr) public pure returns (uint256[] memory) {
        uint256[] memory newArr = new uint256[](arr.length);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        return newArr;
    }

    /**
     * @notice Appends a `bool` value to an existing `bool[]` array.
     * @param arr The array to which the value will be appended.
     * @param val The value to append to the array.
     * @return A new array containing all elements of `arr` with `val` appended.
     */
    function append(bool[] memory arr, bool val) public pure returns (bool[] memory) {
        bool[] memory newArr = new bool[](arr.length + 1);
        for (uint256 i = 0; i < arr.length; i++) {
            newArr[i] = arr[i];
        }
        newArr[arr.length] = val;
        return newArr;
    }

    /**
     * @notice Extends a `bool[]` array with another `bool[]` array.
     * @param arr The array to extend.
     * @param vals The array of values to append to `arr`.
     * @return A new array containing all elements of `arr` followed by all elements of `vals`.
     */
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
