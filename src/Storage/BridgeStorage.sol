// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./../library/Structs.sol";

contract BridgeStorage {
    // SIGNER ADDRESS
    /// @notice mapping dynasty => epoch
    mapping(uint256 => uint256) public modeChange;
    /// @notice mapping dynasty => epoch => signerAddress
    mapping(uint256 => mapping(uint256 => address)) public signerAddressPerDynasty;
    /// @notice mapping validatorId => dynasty => epoch => signerAttestation
    mapping(uint32 => mapping(uint256 => mapping(uint256 => Structs.SignerAttestation))) public signerAttestations;
    /// @notice mapping dynasty => epoch => signerAddresses attested this dynasty
    mapping(uint256 => mapping(uint256 => address)) public attestedSignerAddress;
    /// @notice mapping dynasty => epoch => signerAddress => numVotes
    mapping(uint256 => mapping(uint256 => mapping(address => uint256))) public signerVotesPerAttestation;
    /// @notice mapping signer address => bool
    mapping(address => bool) public isSignerDisputed;

    // REQUEST

    /// @notice mapping requestId => request
    mapping(uint32 => Structs.Request) public requests;
    /// @notice mapping of chainID => bool
    mapping(uint256 => bool) public isChainSupported;
    /// @notice mapping dynasty => epoch => message => numVotes
    mapping(uint256 => mapping(uint256 => mapping(bytes32 => uint256))) public numMessageVotesPerEpoch;
    /// @notice mapping dynasty => epoch => message
    mapping(uint256 => mapping(uint256 => bytes32)) public messagePerEpoch;
    /// @notice mapping validatorId => dynasty => epoch => bool
    mapping(uint32 => mapping(uint256 => mapping(uint256 => bool))) public hasValidatorCommitMessage;

    // SIGNING
    /// @notice mapping epoch => Block Struct
    mapping(uint256 => Structs.Block) public blocks;

    // TRANSFER PROOF

    /// @notice mapping dynasty => Signer Transfer
    mapping(uint256 => Structs.SignerTransfer) public signerTransferProofs;

    //VALIDATOR SELECTION
    /// @notice mapping dynasty => activeSet
    mapping(uint256 => uint32[]) public activeSetPerDynasty;
    /// @notice mapping validatorId => dynasty => iteration
    mapping(uint32 => mapping(uint256 => uint256)) public validatorIterationPerDynasty;
    /// @notice mapping validatorId => dynasty => isSelected
    mapping(uint32 => mapping(uint256 => bool)) public isValidatorSelectedPerDynasty;
    /// @notice mapping dynasty => biggestStake
    mapping(uint256 => uint256) public biggestStakePerDynasty;
    /// @notice mapping dynasty => numParticipants
    mapping(uint256 => uint32) public numParticipantsPerDynasty;
    /// @notice mapping dynasty => churned Out validators
    mapping(uint256 => uint32[]) public churnedOutValidators;
    /// @notice mapping dynasty => validator id => numParticipants
    mapping(uint256 => mapping(uint32 => bool)) public isChurnedOut;

    /// @notice number of requests created, refer to createRequest()
    uint32 public numRequests;
    /// @notice number of requests fulfilled, refer to finalizeBlock()
    uint32 public numRequestsFulfilled;
    /// @notice current dynasty and previous dynasties active set encoded(keccak256)
    /// @dev this salt is used to select validators in _isElectedProposer() using a bias implementation
    bytes32 public salt;
    /// @notice number of participants N required by the network
    uint32 public numParticipants = 10;
    /// @notice threshold T required by the network to reach consensus (T + 1)
    uint32 public threshold = 8;
}
