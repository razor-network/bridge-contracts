// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./StateManager.sol";
import "../interface/IBridge.sol";
import "../interface/IStakeManager.sol";
import "../interface/IBlameManager.sol";
import "../Storage/BlameStorage.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @notice this contract is part of the bridge ecosystem and has to be deployed on the native chain
 */
contract BlameManager is BlameStorage, StateManager, Initializable, IBlameManager {
    IBridge public bridge;
    IStakeManager public stakeManager;

    /// @notice reverts with the error if validatorId is incorrect
    error InvalidValidator();
    ///@notice reverts with the error if non selected validator is tying to attest blame
    error ValidatorNotSelected(uint32 validatorId, uint256 dynasty);
    ///@notice reverts with the error if type of blame attested is incorrect
    error InvalidBlameType();
    ///@notice reverts with the error if no culprits are atteseted in blame
    error NoCulprits();
    ///@notice reverts with the error if non selected validators are attested in blame
    error InvalidCulprits();
    ///@notice reverts with the error if culprits are not in ascending order
    error CulpritsOrder();
    ///@notice reverts with the error if the validator has already attested particular blame in an epoch, dynasty
    error AlreadyAttested();
    // @notice reverts with the error if incorrect mode is detected, depends on current state of the network
    error IncorrectMode();
    // @notice reverts with the error if incorrect mode is detected for a particular blametype
    error IncorrectBlameTypeMode(uint8 mode);
    /// @notice reverts with the error if blame threshold is set greater than or equal to the number of participants in the network
    error InvalidUpdation();

    //Dispute errors
    /// @notice reverts with the error if validator tries to attest a zero address or confirmSigner when attestedSignerAddress is empty
    error ZeroSignerAddress();
    /// @notice reverts when signer addresses are different in the dispute
    error InvalidSignatureDispute();
    /// @notice reverts when the details of the signer proofs are not different ie, same
    error InvalidDetailsDispute();
    /// @notice reverts when the signer address does not exist
    error InvalidDispute();

    constructor(uint256 _firstDynastyCreation) {
        firstDynastyCreation = _firstDynastyCreation;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @param bridgeAddress The address of the bridge contract
     * @param stakeManagerAddress The address of the stake manager contract
     */
    function initialize(address bridgeAddress, address stakeManagerAddress) external initializer onlyRole(DEFAULT_ADMIN_ROLE) {
        bridge = IBridge(bridgeAddress);
        stakeManager = IStakeManager(stakeManagerAddress);
    }

    /**
     * @notice validators that are part of the active set in the current dynasty can attest blames,
     * all culprits should also be part of the same active set. Validators can attest one blameType per epoch
     * but can attest multiple blames (with a different blameType)
     * @param blameType type of blame
     * @param culprits validator IDs in ascending order
     */
    function attestBlame(uint8 blameType, uint32[] memory culprits) external {
        // validator checks
        uint8 mode = bridge.getMode();
        uint256 dynasty = getDynasty();
        if (mode == uint8(EpochMode.ValidatorSelection)) {
            if (hasJumpedDynasty[dynasty - 1]) return;
            revert IncorrectMode();
        }

        uint32 validatorId = stakeManager.getValidatorId(msg.sender);
        if (validatorId == 0) revert InvalidValidator();

        uint256 epoch = getEpoch();

        if (blameType > uint8(type(BlameType).max)) revert InvalidBlameType();

        if (blameType == uint8(BlameType.UnresponsiveSigner)) {
            if (mode != uint8(EpochMode.SignerCreation)) revert IncorrectBlameTypeMode(mode);
        } else {
            if (mode != uint8(EpochMode.Signing)) revert IncorrectBlameTypeMode(mode);
        }

        if (!bridge.getIsValidatorSelectedPerDynasty(validatorId, dynasty)) revert ValidatorNotSelected(validatorId, dynasty);
        if (culprits.length == 0) revert NoCulprits();

        //slither-disable-next-line timestamp
        if (blameAttestations[validatorId][dynasty][epoch][blameType] != bytes32(0)) revert AlreadyAttested();

        for (uint8 i = 0; i < culprits.length; i++) {
            if (i != 0) {
                if (culprits[i] <= culprits[i - 1]) revert CulpritsOrder();
            }
            //slither-disable-next-line calls-loop
            if (!bridge.getIsValidatorSelectedPerDynasty(culprits[i], dynasty)) revert InvalidCulprits();
        }

        // culprits should be in ascending order
        bytes32 blameHash = keccak256(abi.encode(blameType, culprits));

        blameVotesPerAttestation[dynasty][epoch][blameHash] = blameVotesPerAttestation[dynasty][epoch][blameHash] + 1;
        blameAttestations[validatorId][dynasty][epoch][blameType] = blameHash;

        // registering vote on public key if passed threshold
        if (blameVotesPerAttestation[dynasty][epoch][blameHash] > blameThreshold && blamesPerEpoch[dynasty][epoch][blameType].length == 0) {
            blamesPerEpoch[dynasty][epoch][blameType] = culprits;
            _givePenaltyPoints(blameType, culprits);
            if (blameType == uint8(BlameType.UnresponsiveSigner) || blameType == uint8(BlameType.InvalidSigning)) {
                _slashAndJumpDynasty(blameType, culprits, epoch, dynasty);
            }
        }
    }

    function setBlamePointsToZero(uint32[] memory validatorIds) external onlyRole(PENALTY_RESETTER_ROLE) {
        for (uint256 i = 0; i < validatorIds.length; ++i) {
            blamePointsPerValidator[validatorIds[i]] = 0;
        }
    }

    /**
     * @notice Incase of double signing/incorrect handover where the details on the native chain is different to
     * what it is set on the destination chain is different, a dispute can be generated on the native chain where you send
     * the native chain as well as the destination chain details here. If dispute goes through, the entire active set is slashed
     * and jailed.
     * @param signerTransferDisputeB struct of transfer proof present on native/destination chain
     */
    function resultManagerProofDispute(Structs.SignerTransfer memory signerTransferDisputeB) external {
        uint256 dynasty = getDynasty();

        address signerAddress = bridge.getSignerAddress(dynasty - 1);
        //slither-disable-next-line incorrect-equality
        if (signerAddress == address(0)) revert ZeroSignerAddress();

        Structs.SignerTransfer memory signerTransferProof = bridge.getSignerTransferProof(dynasty);
        bytes32 messageHashB = keccak256(abi.encodePacked(signerTransferDisputeB.epoch, signerTransferDisputeB.newSignerAddress));

        address signerAddressB = ECDSA.recover(messageHashB, signerTransferDisputeB.signature);
        if (signerAddress != signerAddressB) revert InvalidSignatureDispute();
        if (
            //slither-disable-next-line incorrect-equality,timestamp
            signerTransferProof.epoch == signerTransferDisputeB.epoch
                && signerTransferProof.newSignerAddress == signerTransferDisputeB.newSignerAddress
        ) revert InvalidDetailsDispute();

        uint256 currentEpoch = getEpoch();

        //slither-disable-next-line weak-prng
        baseEpochIncrement += dynastyLength - (currentEpoch % dynastyLength);
        //slither-disable-next-line weak-prng
        baseTimeIncrement += epochLength - ((block.timestamp - firstDynastyCreation) % epochLength);

        uint32[] memory activeSet = bridge.getActiveSetPerDynasty(dynasty - 1);

        bridge.setIsSignerDisputed(dynasty);
        stakeManager.slashValidators(activeSet, slashPercentage);
        stakeManager.jailValidators(activeSet);
        stakeManager.updateBaseParameters(baseEpochIncrement, baseTimeIncrement);
        bridge.updateBaseParameters(baseEpochIncrement, baseTimeIncrement);
    }

    /**
     * @notice this blame threshold(BT) value is used by the network to reach consensus (BT + 1) on the blame. BT needs to be
     * less than or equal to the bridge threshold(T) (BT <= T)
     * @param _blameThreshold threshold value to be set for the network specific to blames
     */
    function setThreshold(uint32 _blameThreshold) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (bridge.getMode() != uint8(EpochMode.ValidatorSelection)) revert IncorrectMode();
        if (_blameThreshold > bridge.getThreshold()) revert InvalidUpdation();
        blameThreshold = _blameThreshold;
    }

    /**
     * @notice get culprits of particular blame type in an epoch, dynasty
     * @param dynasty dynasty
     * @param epoch epoch
     * @param blameType type of blame
     * @return validatorsIds of culprits
     */
    function getBlamesPerEpoch(uint256 dynasty, uint256 epoch, uint8 blameType) external view returns (uint32[] memory) {
        return blamesPerEpoch[dynasty][epoch][blameType];
    }

    function getBlamePointsPerValidator(uint32 validatorId) external view returns (uint16) {
        return blamePointsPerValidator[validatorId];
    }

    /**
     * @notice get penalty points for each blame type (index is based on enum order of blame type)
     * @return penalty points
     */
    function getPenaltyPoints() external view returns (uint16[4] memory) {
        return penaltyPoints;
    }

    /**
     * @notice give penalty points to culprits after consensus has been reached on a blame
     * @param blameType type of blame
     * @param culprits validatorsIds of culprits
     */
    function _givePenaltyPoints(uint8 blameType, uint32[] memory culprits) internal {
        for (uint8 i = 0; i < culprits.length; i++) {
            // add penalty points
            blamePointsPerValidator[culprits[i]] += penaltyPoints[blameType];
            // set to MAX_POINTS if blame points cross the MAX_POINTS value
            blamePointsPerValidator[culprits[i]] =
                blamePointsPerValidator[culprits[i]] > MAX_POINTS ? MAX_POINTS : blamePointsPerValidator[culprits[i]];
        }
    }

    function _slashAndJumpDynasty(uint8 _blameType, uint32[] memory _culprits, uint256 epoch, uint256 dynasty) internal {
        hasJumpedDynasty[dynasty] = true;

        //slither-disable-next-line weak-prng
        baseEpochIncrement += dynastyLength - (epoch % dynastyLength);
        //slither-disable-next-line weak-prng
        baseTimeIncrement += epochLength - ((block.timestamp - firstDynastyCreation) % epochLength);

        // slash validators only if they are blamed for UnresponsiveSigner or InvalidSigning BlameTypes
        if (_blameType == uint8(BlameType.UnresponsiveSigner)) {
            stakeManager.slashValidators(_culprits, unresponsiveSignerSlashPercentage);
        } else if (_blameType == uint8(BlameType.InvalidSigning)) {
            stakeManager.slashValidators(_culprits, invalidSigningSlashPercentage);
        }

        stakeManager.updateBaseParameters(baseEpochIncrement, baseTimeIncrement);
        bridge.updateBaseParameters(baseEpochIncrement, baseTimeIncrement);
    }
}
