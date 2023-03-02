// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

interface IStakeManager {
    function giveBlockReward(uint32 selectedValidator) external;

    function slashValidators(uint32[] memory _ids, uint32 _slashPercentage) external;

    function jailValidators(uint32[] memory _ids) external;

    function jailValidator(uint32 id) external;

    function updateBaseParameters(uint256 _baseEpochIncrement, uint256 _baseTimeIncrement) external;

    function getWithdrawAfterPerValidator(uint32 validatorId) external view returns (uint256);

    function getValidatorId(address validatorAddress) external view returns (uint32);

    function getStake(uint32 validatorId) external view returns (uint256);

    function getNumValidators() external view returns (uint32);

    function getValidatorJailEndDynasty(uint32 validatorId) external view returns (uint256);
}
