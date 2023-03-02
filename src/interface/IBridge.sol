// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "./../library/Structs.sol";

interface IBridge {
    function setIsSignerDisputed(uint256 dynasty) external;

    function updateBaseParameters(uint256 _baseEpochIncrement, uint256 _baseTimeIncrement) external;

    function getMode() external view returns (uint8 mode);

    function getSignerAddress(uint256 dynasty) external view returns (address);

    function getSignerTransferProof(uint256 dynasty) external view returns (Structs.SignerTransfer memory);

    function getNumParticipantsPerDynasty(uint256 dynasty) external view returns (uint32);

    function getChurnedOutValidatorsPerDynasty(uint256 dynasty) external view returns (uint32[] memory);

    function getThreshold() external view returns (uint32);

    function getValidatorIteration(uint32 validatorId, uint256 dynasty) external view returns (uint256);

    function getIsValidatorSelectedPerDynasty(uint32 validatorId, uint256 dynasty) external view returns (bool);

    function getActiveSetPerDynasty(uint256 dynasty) external view returns (uint32[] memory);
}
