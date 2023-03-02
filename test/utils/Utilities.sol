// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "forge-std/Test.sol";
import "./../../src/library/Random.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract Utilities is Test {
    /**
     * @notice Enum of EpochMode, used to check current state of the network
     * @dev ValidatorSelection: validators for the current dynasty are selected
     *  SignerCreation: selected validators attest and confirm a new public signing address
     *  Signing: blocks are finalized using the new public signing address
     */
    enum EpochMode {
        ValidatorSelection,
        SignerCreation,
        Signing
    }

    /**
     * @notice Enum of BlameType, used to blame a validator for specific behavior that should be penalised.
     *  All validators and culprits should be part of the active set in the current dynasty
     * @dev UnresponsiveSigner: when validator(s) does not participate in SignerCreation,
     *  after being selected in the active set of the current dynasty thereby stalling the network
     * UnresponsiveSigning: when validator(s) create a valid public signing address,
     * but do not participate further in the block signing process therefore do not allow the network to finalize blocks (T + 1 not reached)
     * UnresponsiveNode: when validator(s) creates a valid public signing address,
     * but do not participate further in the block signing process (T + 1 reached)
     * InvalidSigning: the signature being signed by validator(s) is invalid
     */
    enum BlameType {
        UnresponsiveSigner,
        UnresponsiveSigning,
        UnresponsiveNode,
        InvalidSigning
    }

    bytes32 internal _nextUser = keccak256(abi.encodePacked("validator address"));

    function getIteration(uint256 biggestStake, uint256 validatorStake, uint32 stakerId, bytes32 salt, uint32 numValidators)
        external
        pure
        returns (uint256)
    {
        for (uint256 i = 0; i < 1_000_000; i++) {
            bool success = _isElectedProposer(i, biggestStake, validatorStake, stakerId, salt, numValidators);
            if (success) return i;
        }
        return 0;
    }

    function getConfirmTransferSignature(uint256 epoch, address signerAddress, uint256 privKey) external pure returns (bytes memory) {
        bytes32 messageHash = keccak256(abi.encodePacked(epoch, signerAddress));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, messageHash);
        bytes memory sig = bytes.concat(r, s, bytes1(v));
        return sig;
    }

    function getSignature(bytes memory messageData, uint256 privKey) external pure returns (bytes memory) {
        bytes32 messageHash = keccak256(messageData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, messageHash);
        bytes memory sig = bytes.concat(r, s, bytes1(v));
        return sig;
    }

    function getNextUserAddress() external returns (address payable) {
        //bytes32 to address conversion
        address payable user = payable(address(uint160(uint256(_nextUser))));
        _nextUser = keccak256(abi.encodePacked(_nextUser));
        return user;
    }

    /// @notice create users with 100 ether balance
    function createValidators(uint256 userNum) external returns (address payable[] memory) {
        address payable[] memory users = new address payable[](userNum);
        for (uint256 i = 0; i < userNum; i++) {
            address payable user = this.getNextUserAddress();
            vm.deal(user, 100 ether);
            string memory label = string.concat("Validator id ", vm.toString(i + 1));
            vm.label(user, label);
            users[i] = user;
        }
        return users;
    }

    /// @notice move block.number forward by a given number of blocks
    function mineBlocks(uint256 numBlocks) external {
        uint256 targetBlock = block.number + numBlocks;
        vm.roll(targetBlock);
    }

    /// @notice skip number of epochs
    function skipEpoch(uint256 numEpochs, uint256 _epochLength) external {
        uint256 targetEpoch = _epochLength * numEpochs;
        skip(targetEpoch);
    }

    /// @notice skip number of dynasties and always reset epoch count to 1
    function skipDynasty(uint256 _numDynasties, uint256 _epoch, uint256 _dynastyLength, uint256 _epochLength) external {
        uint256 epochsToSkip = (_dynastyLength * _numDynasties) - _epoch;
        this.skipEpoch(epochsToSkip, _epochLength);
    }

    function getAddress(bytes memory pubKey) external pure returns (address addr) {
        bytes memory output = new bytes(20);
        for (uint8 i = 0; i < 20; i++) {
            output[20 - 1 - i] = pubKey[32 - 1 - i];
        }
        assembly {
            addr := mload(add(output, 20))
        }
    }

    function _isElectedProposer(
        uint256 iteration,
        uint256 biggestStake,
        uint256 validatorStake,
        uint32 stakerId,
        bytes32 salt,
        uint32 numValidators
    ) internal pure returns (bool) {
        // generating pseudo random number (range 0..(totalstake - 1)), add (+1) to the result,
        // since prng returns 0 to max-1 and staker start from 1
        //roll an n sided fair die where n == numStakers to select a staker pseudoRandomly
        bytes32 seed1 = Random.prngHash(salt, keccak256(abi.encode(iteration)));
        uint256 rand1 = Random.prng(numValidators, seed1);
        if ((rand1 + 1) != stakerId) {
            return false;
        }
        //toss a biased coin with increasing iteration till the following equation returns true.
        // stake/biggest stake >= prng(iteration,stakerid, salt), staker wins
        // stake/biggest stake < prng(iteration,stakerid, salt), staker loses
        // simplified equation:- stake < prng * biggestStake
        // stake * 2^32 < prng * 2^32 * biggestStake
        // multiplying by 2^32 since seed2 is bytes32 so rand2 goes from 0 to 2^32
        bytes32 seed2 = Random.prngHash(salt, keccak256(abi.encode(stakerId, iteration)));
        uint256 rand2 = Random.prng(2 ** 32, seed2);

        // Below line can't be tested since it can't be assured if it returns true or false
        if (rand2 * (biggestStake) > validatorStake * (2 ** 32)) return (false);
        return true;
    }
}
