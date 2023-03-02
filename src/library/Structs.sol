// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

library Structs {
    struct Validator {
        uint32 id;
        address _validatorAddress;
        uint256 stake;
        uint256 jailEndDynasty;
    }

    struct SignerAttestation {
        uint32 validatorId;
        address signerAddress;
    }

    struct Request {
        bool fulfilled;
        uint32 requestId;
        uint256 epoch;
        bytes requestData;
    }

    struct Block {
        uint256 timestamp;
        bytes message;
        bytes signature;
    }

    struct SignerTransfer {
        address newSignerAddress;
        uint256 epoch;
        bytes signature;
    }

    struct Value {
        int8 power;
        uint16 collectionId;
        bytes32 name;
        uint256 value;
    }

    struct SignerAddressDetails {
        bool isDisputed;
        bool signerTransferCompleted;
        uint32 numBlocksLimit;
        address signerAddress;
        uint256 epochAssigned;
        uint256 disputeExpiry;
        uint256[] blocksConfirmedDuringDisputePeriod;
    }
}
