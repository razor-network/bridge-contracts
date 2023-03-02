// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./../library/Structs.sol";

contract BlameStorage {
    /// @notice mapping of dynasty => epoch => blame => validatorIds
    mapping(uint256 => mapping(uint256 => mapping(uint8 => uint32[]))) public blamesPerEpoch;
    /// @notice mapping of validatorId => dynasty => epoch => blame attestations
    mapping(uint32 => mapping(uint256 => mapping(uint256 => mapping(uint8 => bytes32)))) public blameAttestations;
    /// @notice mapping of dynasty => epoch => blames attested in dynasty
    mapping(uint256 => mapping(uint256 => bytes32)) public attestedBlames;
    /// @notice mapping of dynasty => epoch => blame => numVotes
    mapping(uint256 => mapping(uint256 => mapping(bytes32 => uint256))) public blameVotesPerAttestation;
    /// @notice mapping of dynasty => did we jump dynasty here due to blame?
    mapping(uint256 => bool) public hasJumpedDynasty;
    /// @notice mapping of validatorId => blame points
    mapping(uint32 => uint16) public blamePointsPerValidator;
    // Penalty points for each blame in order
    // 5: UnresponsiveSigner, 3: UnresponsiveSigning, 2: UnresponsiveNode, 5: InvalidSigning
    uint16[4] public penaltyPoints = [5, 3, 2, 5];
    /// @notice blameThreshold T required by the network to reach consensus on a blame (~66%)
    uint32 public blameThreshold = 7;
}
