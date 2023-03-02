// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

interface IBlameManager {
    function setBlamePointsToZero(uint32[] memory validatorIds) external;

    function getBlamePointsPerValidator(uint32 validatorId) external view returns (uint16);
}
