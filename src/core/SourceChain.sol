// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "@openzeppelin/contracts/utils/Address.sol";

contract SourceChain {
    using Address for address;

    function getData(address target, bytes memory payload) external view returns (bytes memory) {
        return target.functionStaticCall(payload);
    }
}
