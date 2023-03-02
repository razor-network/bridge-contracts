// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./../library/Structs.sol";

contract ResultStorage {
    /// @notice mapping of epoch => Block
    mapping(uint256 => Structs.Block) public blocks;
    /// @notice mapping of requestId => collectionId
    mapping(uint32 => uint16) public requestToCollection;
    /// @notice mapping for latest result of collectionId => Value
    mapping(uint16 => Structs.Value) public collectionResults;
    /// @notice mapping of dynasty => signer address details
    mapping(uint256 => Structs.SignerAddressDetails) public signerAddressPerDynasty;
    /// @notice mapping of collection name => collection id
    mapping(bytes32 => uint16) public collectionIds;
    // signer address => time expiry
    mapping(address => uint256) public disputeExpiryPerSigner;
    // signer address => disputed bool
    mapping(address => bool) public isSignerDisputed;

    /// @notice active collections ids
    uint16[] public activeCollectionIds;
    /// @notice timestamp when result was last updated
    uint256 public lastUpdatedTimestamp;
    /// @notice dispute time period for fraud proofs
    uint256 public constant DISPUTE_TIME_PERIOD = 1200;
    /// @notice current dynasty
    uint256 public currentDynasty;
    /// @notice when the current dynasty would end in epochs
    uint256 public expectedDynastyEnd;
    /// @notice length of a dynasty in epochs
    uint256 public dynastyLength = 100;
}
