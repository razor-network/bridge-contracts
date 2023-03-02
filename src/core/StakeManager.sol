// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./StateManager.sol";
import "../interface/IBridge.sol";
import "../interface/IStakeManager.sol";
import "../Storage/StakeStorage.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";

/**
 * @notice this contract is part of the bridge ecosystem and has to be deployed on the native chain
 */
contract StakeManager is StakeStorage, StateManager, Initializable, IStakeManager {
    IERC20 public bridgeToken;
    IBridge public bridge;

    /**
     * @dev Emitted when a address has staked tokens.
     * @param amount staked by validator
     * @param validator address
     * @param validatorId ID of given validator address
     * @param epoch current epoch validator has staked in
     * @param dynasty current dynasty validator has staked in
     */
    event Staked(uint256 amount, address validator, uint32 indexed validatorId, uint256 indexed epoch, uint256 indexed dynasty);

    /**
     * @dev Emitted when a address has unstaked  tokens.
     * @param validator address
     * @param validatorId ID of given validator address
     * @param epoch current epoch validator has unstaked in
     * @param dynasty current dynasty validator has unstaked in
     */
    event Unstaked(address validator, uint32 indexed validatorId, uint256 indexed epoch, uint256 indexed dynasty);

    /**
     * @dev Emitted when a address has withdrawn tokens.
     * @param validator address
     * @param validatorId ID of given validator address
     * @param mode current mode
     * @param epoch current epoch validator has unstaked in
     * @param dynasty current dynasty validator has unstaked in
     */
    event Withdraw(address validator, uint32 indexed validatorId, uint8 mode, uint256 indexed epoch, uint256 indexed dynasty);

    /**
     * @dev Emitted when a validator has been slashed.
     * @param validator address of the validator
     * @param validatorId ID of given validator address
     * @param epoch current epoch validator has unstaked in
     * @param dynasty current dynasty validator has unstaked in
     * @param prevStake previous stake before slashing
     * @param newStake new stake after slashing
     * @param sender caller of slash()
     */
    event Slashed(
        address validator,
        uint32 indexed validatorId,
        uint256 indexed epoch,
        uint256 indexed dynasty,
        uint256 prevStake,
        uint256 newStake,
        address sender
    );

    /**
     * @dev Emitted when a validator is jailed
     * @param validatorId ID of validator that is jailed
     * @param jailStart dynasty at which jail starts
     * @param jailEndDynasty dynasty at which jail ends
     * @param epoch epoch in which validator is jailed
     * @param sender caller of jailValidator()
     */
    event ValidatorJailed(
        uint32 indexed validatorId, uint256 indexed jailStart, uint256 jailEndDynasty, uint256 indexed epoch, address sender
    );

    // Common errors
    /// @notice reverts with the error if validator does not exist
    error ValidatorDoesNotExist();
    /// @notice reverts with the error if validatorId is incorrect
    error InvalidValidator();
    /// @notice reverts with the error if an operation was not performed in required mode
    error IncorrectMode();
    /// @notice reverts with the error if erc20 token transfer fails
    error TokenTransferFailed(address from, address to, uint256 amount);

    // stake() errors
    /// @notice reverts with the error if the stake amount is less than minStake
    error LessThanMinStake();
    /// @notice reverts with the error if the existing validator is trying to stake
    error AlreadyValidator(uint32 validatorId);

    // unstake() errors
    /// @notice reverts with the error during unstake if withdraw lock already exist for validator
    error ExistingWithdrawLock(uint256 unlockAfter);

    // withdraw() errors
    /// @notice reverts with the error during withdraw if validator has already participated in selection
    error AlreadyParticipated();
    /// @notice reverts with the error if the withdraw lock doesn't exist during withdraw
    error NoWithdrawLock();
    /// @notice reverts with the error if withdraw lock period has not passed
    error InvalidWithdrawRequest();
    /// @notice reverts with the error if validator in the activeSet
    error StillInActiveSet();

    // jailValidator() errors
    /// @notice reverts with the error if validator is being jailed in jail period
    error ValidatorAlreadyInJail();

    constructor(uint256 _firstDynastyCreation) {
        firstDynastyCreation = _firstDynastyCreation;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @param bridgeTokenAddress The address of the bridge token ERC20 contract
     * @param bridgeAddress The address of the bridge contract
     */
    function initialize(address bridgeTokenAddress, address bridgeAddress) external initializer onlyRole(DEFAULT_ADMIN_ROLE) {
        bridgeToken = IERC20(bridgeTokenAddress);
        bridge = IBridge(bridgeAddress);
    }

    /**
     * @notice Validator to stake
     * @param amount The amount to be staked
     */
    function stake(uint256 amount) external {
        if (amount < minStake) revert LessThanMinStake();
        if (validatorIds[msg.sender] != 0) revert AlreadyValidator(validatorIds[msg.sender]);

        numValidators = numValidators + 1;
        validatorIds[msg.sender] = numValidators;
        validators[numValidators] = Structs.Validator(numValidators, msg.sender, amount, 0);

        emit Staked(amount, msg.sender, validatorIds[msg.sender], getEpoch(), getDynasty());
        if (!bridgeToken.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed(msg.sender, address(this), amount);
    }

    /**
     * @notice a signal to the network that the validator is planning to withdraw their funds from the network.
     * validator would still continue to participate till the validator withdraws
     */
    function unstake() external {
        uint32 validatorId = validatorIds[msg.sender];
        if (validatorId == 0) revert InvalidValidator();
        //slither-disable-next-line incorrect-equality,timestamp
        if (withdrawAfterPerValidator[msg.sender] != 0) revert ExistingWithdrawLock(withdrawAfterPerValidator[msg.sender]);

        uint256 dynasty = getDynasty();
        withdrawAfterPerValidator[msg.sender] = dynasty + withdrawLockPeriod;
        emit Unstaked(msg.sender, validatorId, getEpoch(), dynasty);
    }

    /**
     * @notice allows validator to withdraw their funds once withdrawLockPeriod has passed
     */
    function withdraw() external {
        uint32 validatorId = validatorIds[msg.sender];
        if (validatorId == 0) revert InvalidValidator();

        uint8 mode = bridge.getMode();
        //slither-disable-next-line timestamp,incorrect-equality
        if (withdrawAfterPerValidator[msg.sender] == 0) revert NoWithdrawLock();
        if (mode != uint8(EpochMode.ValidatorSelection)) revert IncorrectMode();

        uint256 dynasty = getDynasty();
        //slither-disable-next-line incorrect-equality
        if (bridge.getValidatorIteration(validatorId, dynasty) != 0) revert AlreadyParticipated();

        //slither-disable-next-line incorrect-equality
        bool prevDynastyAndChurnCheck = (
            bridge.getChurnedOutValidatorsPerDynasty(dynasty).length == 0
                && bridge.getIsValidatorSelectedPerDynasty(validatorId, dynasty - 1)
                && bridge.getActiveSetPerDynasty(dynasty - 1).length == bridge.getNumParticipantsPerDynasty(dynasty - 1)
        );

        if (bridge.getIsValidatorSelectedPerDynasty(validatorId, dynasty) || prevDynastyAndChurnCheck) revert StillInActiveSet();

        uint256 epoch = getEpoch();
        if (dynasty < withdrawAfterPerValidator[msg.sender]) revert InvalidWithdrawRequest();

        uint256 withdrawAmount = validators[validatorId].stake;
        validators[validatorId].stake = 0;
        withdrawAfterPerValidator[msg.sender] = 0;

        emit Withdraw(msg.sender, validatorId, mode, epoch, dynasty);
        if (!bridgeToken.transfer(msg.sender, withdrawAmount)) revert TokenTransferFailed(address(this), msg.sender, withdrawAmount);
    }

    /**
     * @notice sets the base epoch and time increment when skipping a dynasty
     * @param _baseEpochIncrement base epochs to be incremented
     * @param _baseTimeIncrement base time to be incrememented
     */
    function updateBaseParameters(uint256 _baseEpochIncrement, uint256 _baseTimeIncrement) external override onlyRole(BASE_MODIFIER_ROLE) {
        baseTimeIncrement = _baseTimeIncrement;
        baseEpochIncrement = _baseEpochIncrement;
    }

    /**
     * @notice slashing multiple validators at once so that only one external call is required
     * @param _ids validator ids array that are to be slashed
     */
    function slashValidators(uint32[] memory _ids, uint32 _slashPercentage) external override onlyRole(STAKE_MODIFIER_ROLE) {
        for (uint32 i = 0; i < _ids.length; i++) {
            _slash(_ids[i], _slashPercentage);
        }
    }

    /**
     * @notice jailing multiple validators at once so that only one external call is required
     * @param _ids validator ids array that are to be jailed
     */
    function jailValidators(uint32[] memory _ids) external override onlyRole(JAILER_ROLE) {
        for (uint32 i = 0; i < _ids.length; i++) {
            _jailValidator(_ids[i]);
        }
    }

    function jailValidator(uint32 id) external override onlyRole(JAILER_ROLE) {
        _jailValidator(id);
    }

    /**
     * @notice give block reward to selected validator
     * @param selectedValidator ID of the validator
     */
    function giveBlockReward(uint32 selectedValidator) external override onlyRole(STAKE_MODIFIER_ROLE) {
        _setValidatorStake(selectedValidator, validators[selectedValidator].stake + blockReward);
    }

    /**
     * @param validatorId ID of the validator
     * @return withdraw after for the validator Id
     */
    function getWithdrawAfterPerValidator(uint32 validatorId) external view override returns (uint256) {
        return withdrawAfterPerValidator[validators[validatorId]._validatorAddress];
    }

    /**
     * @param validatorAddress validator address
     * @return ID of the validator
     */
    function getValidatorId(address validatorAddress) external view override returns (uint32) {
        return validatorIds[validatorAddress];
    }

    /**
     * @param validatorId ID of the validator
     * @return validator jail end dynasty
     */
    function getValidatorJailEndDynasty(uint32 validatorId) external view override returns (uint256) {
        return validators[validatorId].jailEndDynasty;
    }

    /**
     * @param validatorId ID of the validator
     * @return stake of validator
     */
    function getStake(uint32 validatorId) external view override returns (uint256) {
        return validators[validatorId].stake;
    }

    /**
     * @param validatorId ID of the validator
     * @return validator The Struct of validator information
     */
    function getValidator(uint32 validatorId) external view returns (Structs.Validator memory validator) {
        return validators[validatorId];
    }

    /**
     * @return total number of validators
     */
    function getNumValidators() external view override returns (uint32) {
        return numValidators;
    }

    /**
     * @notice Internal function for setting stake of a validator
     * @param _id Id of the validator
     * @param _stake the amount of Razor bridge tokens staked
     */
    function _setValidatorStake(uint32 _id, uint256 _stake) internal {
        validators[_id].stake = _stake;
    }

    /**
     * @notice internal function where validators are slashed
     * @param _id Id of the validator
     */
    function _slash(uint32 _id, uint32 _slashPercentage) internal {
        if (_id == 0) revert InvalidValidator();
        Structs.Validator memory validator = validators[_id];
        if (validator._validatorAddress == address(0)) revert ValidatorDoesNotExist();
        uint256 dynasty = getDynasty();
        uint256 epoch = getEpoch();
        uint256 _stake = validator.stake;
        uint256 amountToBeBurned = (_stake * _slashPercentage) / BASE_DENOMINATOR;
        _stake = _stake - amountToBeBurned;
        _setValidatorStake(_id, _stake);
        emit Slashed(validator._validatorAddress, _id, epoch, dynasty, _stake + amountToBeBurned, _stake, msg.sender);
        //slither-disable-next-line calls-loop
        if (!bridgeToken.transfer(BURN_ADDRESS, amountToBeBurned)) {
            revert TokenTransferFailed(address(this), BURN_ADDRESS, amountToBeBurned);
        }
    }

    /**
     * @notice allow addresses with JAILER_ROLE to jail validator
     * @param validatorId id of validator to be jailed
     */
    function _jailValidator(uint32 validatorId) internal {
        if (validatorId == 0) revert InvalidValidator();
        if (validators[validatorId]._validatorAddress == address(0)) revert ValidatorDoesNotExist();
        uint256 dynasty = getDynasty();
        //slither-disable-next-line incorrect-equality,timestamp
        if (validators[validatorId].jailEndDynasty >= dynasty) revert ValidatorAlreadyInJail();

        validators[validatorId].jailEndDynasty = dynasty + numJailDynasty;
        uint256 epoch = getEpoch();
        emit ValidatorJailed(validatorId, dynasty, dynasty + numJailDynasty, epoch, msg.sender);
    }
}
