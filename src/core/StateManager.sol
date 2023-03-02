// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../Storage/Parameters.sol";

contract StateManager is Parameters {
    //slither-disable-next-line immutable-states
    uint256 public firstDynastyCreation;
    //slither-disable-next-line constable-states
    uint256 public baseEpochIncrement = 0;
    //slither-disable-next-line constable-states
    uint256 public baseTimeIncrement = 0;

    /**
     * @return the value of current dynasty
     */
    function getDynasty() public view returns (uint256) {
        return ((getEpoch() - 1) / dynastyLength) + 1;
    }

    /**
     * @return the value of current epoch in the dynasty
     */
    function getEpoch() public view returns (uint256) {
        return (((block.timestamp - firstDynastyCreation) + baseTimeIncrement) / epochLength) + baseEpochIncrement + 1;
    }
}
