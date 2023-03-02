// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./../library/Structs.sol";

contract StakeStorage {
    /// @notice mapping of validator address => validator id
    mapping(address => uint32) public validatorIds;
    /// @notice mapping of validator id => validator struct
    mapping(uint32 => Structs.Validator) public validators;
    /// @notice mapping of validator address => unstake lock epoch
    mapping(address => uint256) public withdrawAfterPerValidator;

    /// @notice total number of validators
    uint32 public numValidators;
}
