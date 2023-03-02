// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "forge-std/Test.sol";

import {SourceChain} from "src/core/SourceChain.sol";
import {MockSource} from "src/mocks/MockSource.sol";

contract SourceChainTest is Test {
    SourceChain public sourceChain;
    MockSource public mockSource;

    function setUp() external {
        sourceChain = new SourceChain();
        mockSource = new MockSource();
        mockSource.setResult();

        vm.label(address(sourceChain), "Source Chain");
        vm.label(address(mockSource), "Mock Source");
    }

    function testSourceChain() external {
        bytes memory payload = abi.encodeWithSignature("getResult()");
        bytes memory returnData = sourceChain.getData(address(mockSource), payload);
        bytes memory mockData = abi.encode(mockSource.getResult());
        assertEq(mockData, returnData);
    }
}
