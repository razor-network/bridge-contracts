// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

contract MockSource {
    struct Value {
        int8 power;
        uint16 collectionId;
        bytes32 name;
        uint256 value;
    }

    Value public value;

    function setResult() external {
        value = Value(-2, 1, keccak256("collectionName"), 12000);
    }

    function getResult() external view returns (Value memory) {
        return value;
    }
}
