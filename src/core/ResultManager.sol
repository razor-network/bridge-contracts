// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "../Storage/ResultStorage.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @notice this contract is part of the bridge ecosystem and has to be deployed on the destination chains
 */
contract ResultManager is ResultStorage, AccessControl, Initializable {
    /**
     * @dev Emitted when proof of old signer transfering ownership to the new signer address is sent to Result Manager.
     * @param signerDetails details of the signer in a struct
     */
    event SignerSet(Structs.SignerAddressDetails signerDetails);

    // Dispute errors
    /// @notice reverts when signer addresses are different in the dispute
    error InvalidSignatureDispute();
    /// @notice reverts when the details of the signer proofs are not different ie, same
    error InvalidDetailsDispute();
    /// @notice reverts when the signer address does not exist
    error InvalidDynasty();
    /// @notice reverts when the dispute time period has expired
    error DisputeExpired();
    /// @notice reverts when trying to dispute signer proof done by admin
    error AdminSignerTransfer();

    // Set Block errors
    /// @notice reverts with error signer address has not yet been confirmed
    error SignerAddressNotConfirmed();
    /// @notice reverts with error signer address has been disputed
    error SignerAddressDisputed();
    /// @notice reverts with the error if the signature is not signed by required signer
    error InvalidSignature();
    /// @notice reverts with error if the epoch in which signer address was assigned is greater than or equal to epoch in the block message
    error IncorrectBlockSent();
    /// @notice reverts with error if the block is already set for the epoch
    error BlockAlreadySet();
    /// @notice reverts with error when a signer address has exhausted the number of blocks it can set
    error BlockLimitReached();

    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @notice sets the new signer address by providing signer transfer proof
     * @dev the signer address can be updated only when the dynasty changes as the nodes
     *  that created the previous signer address must transfer ownership to the newly created signer address
     * @param signerTransferProof a struct containing epoch, new signer address and a signature signed by the previous signer address
     */
    function setSigner(Structs.SignerTransfer memory signerTransferProof) external {
        // if network has stalled for one or more dynasties then increase current dynasty accordingly
        if (signerTransferProof.epoch > (expectedDynastyEnd + dynastyLength)) {
            uint256 epochDiff = signerTransferProof.epoch - (expectedDynastyEnd + dynastyLength);
            uint256 dynastyJumped = (epochDiff / dynastyLength) + 1;
            currentDynasty += dynastyJumped + 1;
            expectedDynastyEnd += ((dynastyJumped + 1) * dynastyLength);
        } else {
            currentDynasty += 1;
            expectedDynastyEnd += dynastyLength;
        }

        bytes32 messageHash = keccak256(abi.encodePacked(signerTransferProof.epoch, signerTransferProof.newSignerAddress));
        // incase of admin intervention is required for signer transfer if previous signer address doesnt transfer power or
        // the network has stalled for one dynasty or more such that no signer address is present in the previous dynasty.
        if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            if (ECDSA.recover(messageHash, signerTransferProof.signature) != msg.sender) revert InvalidSignature();
        } else {
            if (ECDSA.recover(messageHash, signerTransferProof.signature) != signerAddressPerDynasty[currentDynasty - 1].signerAddress) {
                revert InvalidSignature();
            }
        }

        signerAddressPerDynasty[currentDynasty] = Structs.SignerAddressDetails(
            false,
            false,
            uint32(expectedDynastyEnd - signerTransferProof.epoch),
            signerTransferProof.newSignerAddress,
            signerTransferProof.epoch,
            block.timestamp + DISPUTE_TIME_PERIOD,
            new uint256[](0)
        );

        emit SignerSet(signerAddressPerDynasty[currentDynasty]);
    }

    /**
     * @notice Incase of double signing/incorrect handover where the details on the native chain is different to
     * what it is set on the destination chain is different, a dispute can be generated on destination chain where
     * native chain details are sent here. If the dispute goes through, the new signer address is invalidated and any blocks
     * merged during the dispute period will be removed
     * @param dynasty the dynasty for which the dispute is being generated
     * @param signerTransferProof struct of transfer proof present on native chain
     */
    function disputeSigner(uint256 dynasty, Structs.SignerTransfer memory signerTransferProof) external {
        address signerAddress = signerAddressPerDynasty[dynasty].signerAddress;
        //slither-disable-next-line incorrect-equality
        if (signerAddress == address(0)) revert InvalidDynasty();
        //slither-disable-next-line timestamp
        if (signerAddressPerDynasty[dynasty].disputeExpiry <= block.timestamp) revert DisputeExpired();

        bytes32 messageHash = keccak256(abi.encodePacked(signerTransferProof.epoch, signerTransferProof.newSignerAddress));
        address recoveredSignerAddress = ECDSA.recover(messageHash, signerTransferProof.signature);

        if (
            recoveredSignerAddress != signerAddressPerDynasty[dynasty - 1].signerAddress
                && !hasRole(DEFAULT_ADMIN_ROLE, recoveredSignerAddress)
        ) revert InvalidSignatureDispute();

        if (
            signerTransferProof.epoch == signerAddressPerDynasty[dynasty].epochAssigned
                && signerTransferProof.newSignerAddress == signerAddressPerDynasty[dynasty].signerAddress
        ) revert InvalidDetailsDispute();

        signerAddressPerDynasty[dynasty].isDisputed = true;
        signerAddressPerDynasty[dynasty].numBlocksLimit = 0;

        for (uint256 i = 0; i < signerAddressPerDynasty[dynasty].blocksConfirmedDuringDisputePeriod.length; i++) {
            blocks[signerAddressPerDynasty[dynasty].blocksConfirmedDuringDisputePeriod[i]] = Structs.Block(0, bytes(""), bytes(""));
        }
    }

    /**
     * @notice sets the block by providing message data and signature of the current dynasty signer address
     * @dev Once the block is confirmed on the source chain, anyone can set the block by calling this function to the destination
     * chain. Signature verification are being done here as well to ensure a valid block is being set to the contract. After verification,
     * we decode the message and assign results to their corresponding collectionIds
     * @param confirmedBlock block confirmed on the native chain
     */
    function setBlock(Structs.Block memory confirmedBlock) external {
        bytes32 messageHash = keccak256(confirmedBlock.message);

        (uint256 dynasty, uint256 epoch, uint32[] memory requestIds, bytes[] memory values) =
            abi.decode(confirmedBlock.message, (uint256, uint256, uint32[], bytes[])); // solhint-disable-line

        address signerAddress = signerAddressPerDynasty[dynasty].signerAddress;

        if (signerAddressPerDynasty[dynasty].isDisputed) revert SignerAddressDisputed();
        if (signerAddressPerDynasty[dynasty].epochAssigned >= epoch) revert IncorrectBlockSent();
        if (ECDSA.recover(messageHash, confirmedBlock.signature) != signerAddress) revert InvalidSignature();
        if (bytes32(blocks[epoch].signature) != bytes32(0)) revert BlockAlreadySet();
        //slither-disable-next-line incorrect-equality
        if (signerAddressPerDynasty[dynasty].numBlocksLimit == 0) revert BlockLimitReached();

        //slither-disable-next-line timestamp
        if (signerAddressPerDynasty[dynasty].disputeExpiry > block.timestamp) {
            signerAddressPerDynasty[dynasty].blocksConfirmedDuringDisputePeriod.push(epoch);
        }

        signerAddressPerDynasty[dynasty].numBlocksLimit -= 1;
        blocks[epoch] = confirmedBlock;

        uint16[] memory ids = new uint16[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            Structs.Value memory collectionValue = abi.decode(values[i], (Structs.Value));
            requestToCollection[requestIds[i]] = collectionValue.collectionId;
            collectionResults[collectionValue.collectionId] = collectionValue;
            collectionIds[collectionValue.name] = collectionValue.collectionId;
            ids[i] = collectionValue.collectionId;
        }

        activeCollectionIds = ids;
        lastUpdatedTimestamp = confirmedBlock.timestamp;
    }

    /**
     * @notice sets dynasty length in epochs
     */
    function setDynastyLength(uint256 _dynastyLength) external onlyRole(DEFAULT_ADMIN_ROLE) {
        dynastyLength = _dynastyLength;
    }

    /**
     * @notice return the struct of signer details based on the dynasty provided
     * @param dynasty dynasty for which signer details is to be fetched
     * @return _signerDetails : struct of the signer details
     */
    function getSignerAddressDetails(uint256 dynasty) external view returns (Structs.SignerAddressDetails memory) {
        return signerAddressPerDynasty[dynasty];
    }

    /**
     * @notice return the struct of the block based on the epoch provided
     * @param epoch epoch for which the block is to be fetched
     * @return _block : struct of the confirmed block
     */
    function getBlock(uint256 epoch) external view returns (Structs.Block memory) {
        return blocks[epoch];
    }

    /**
     * @notice using the hash of collection name, clients can query the result of that collection
     * @param _name bytes32 hash of the collection name
     * @return result of the collection and its power
     */
    function getResult(bytes32 _name) external view returns (uint256, int8) {
        uint16 id = collectionIds[_name];
        return getResultFromID(id);
    }

    /**
     * @notice return the collectionId based on the requestId provided
     * @param requestId request ID
     * @return collectionId : collectionId fulfilled in the request
     */
    function getRequestToCollection(uint32 requestId) external view returns (uint16) {
        return requestToCollection[requestId];
    }

    /**
     * @notice using the hash of collection name, clients can query collection id with respect to its hash
     * @param _name bytes32 hash of the collection name
     * @return collection ID
     */
    function getCollectionID(bytes32 _name) external view returns (uint16) {
        return collectionIds[_name];
    }

    /**
     * @return ids of active collections in the oracle
     */
    function getActiveCollections() external view returns (uint16[] memory) {
        return activeCollectionIds;
    }

    /**
     * @notice using the collection id, clients can query the status of collection
     * @param _id collection ID
     * @return status of the collection
     */
    function getCollectionStatus(uint16 _id) external view returns (bool) {
        bool isActive = false;
        for (uint256 i = 0; i < activeCollectionIds.length; i++) {
            if (activeCollectionIds[i] == _id) {
                isActive = true;
                break;
            }
        }
        return isActive;
    }

    /**
     * @notice using the collection id, clients can query the result of the collection
     * @param collectionId collection ID
     * @return result of the collection and its power
     */
    function getResultFromID(uint16 collectionId) public view returns (uint256, int8) {
        return (collectionResults[collectionId].value, collectionResults[collectionId].power);
    }
}
