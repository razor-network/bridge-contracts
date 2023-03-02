// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Bridge} from "src/core/Bridge.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {StakeManager} from "src/core/StakeManager.sol";
import {BlameManager} from "src/core/BlameManager.sol";

contract BridgeTest is Utilities {
    using stdStorage for StdStorage;

    address public owner;
    address payable public validator1;
    address payable public validator2;
    uint256 public deploymentTime;
    uint256[] public privKeys;
    bytes32[] public pubKeys;
    address public signerAddress;
    Structs.Value[] public values;
    bytes[] public byteValues;
    bytes32 public collectionId1NameHash = keccak256("collectionId1");
    bytes32 public collectionId2NameHash = keccak256("collectionId2");
    uint256 public contractReserve = 10000e18;
    mapping(uint32 => uint256) public stake;

    Bridge public bridge;
    BridgeToken public bridgeToken;
    StakeManager public stakeManager;
    BlameManager public blameManager;

    /**
     * general set up required for signing, hardcoded values and bytes to be used as the message being bridged
     * we also use hardcoded privKeys to act as signerAddress
     */
    function setUp() external {
        deploymentTime = block.timestamp;
        privKeys.push(43788133087041727893459500607664774196458479752328773334909089843514276704194);
        privKeys.push(35843802749631185423785067895403820357061322939561082199809626794025181920029);
        pubKeys.push(0x1c15e2990e76007fdf2fda604513218ce2e31004348fd374856152e1a026283c);
        pubKeys.push(0x0ef0d3d283da84eed8165fa72e96440b320e5c97be316b6049a9f8de8581742d);
        address payable[] memory validators = this.createValidators(2);
        validator1 = validators[0];
        validator2 = validators[1];
        vm.label(validator1, "Validator 1");
        vm.label(validator2, "Validator 2");
        values.push(Structs.Value(1, 1, collectionId1NameHash, 1));
        values.push(Structs.Value(2, 2, collectionId2NameHash, 2));
        byteValues.push(abi.encode(Structs.Value(1, 1, collectionId1NameHash, 1)));
        byteValues.push(abi.encode(Structs.Value(2, 2, collectionId2NameHash, 2)));

        owner = vm.addr(1);
        vm.label(owner, "Owner");
        vm.startPrank(owner);
        bridgeToken = new BridgeToken();
        bridge = new Bridge();

        deploymentTime = bridge.firstDynastyCreation();
        stakeManager = new StakeManager(deploymentTime);
        blameManager = new BlameManager(deploymentTime);
        bridge.initialize(address(stakeManager), address(blameManager));
        stakeManager.initialize(address(bridgeToken), address(bridge));
        blameManager.grantRole(bridge.PENALTY_RESETTER_ROLE(), address(bridge));

        // set suppported chain id so that requests can be created
        bridge.setSupportedChainId(80001, true);

        bridgeToken.transfer(address(stakeManager), contractReserve);
        vm.stopPrank();

        vm.label(address(bridge), "Bridge");
        vm.label(address(stakeManager), "Stake Manager");
        vm.label(address(bridgeToken), "Bridge Token");
        vm.label(address(blameManager), "Blame Manager");
    }

    /**
     * REQUEST TESTS
     */

    /**
     * client should be able to create a request with appropriate details provided
     */
    function testCreateRequest() public {
        uint32 numRequests = 800;
        uint256 epoch = bridge.getEpoch();
        vm.startPrank(owner);

        for (uint32 i = 1; i <= numRequests; i++) {
            bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 80001);
            assertEq(bridge.numRequests(), i);
            (bool _fulfilled, uint32 _requestId, uint256 _epoch, bytes memory _requestData) = bridge.requests(i);
            assertEq(_fulfilled, false);
            assertEq(_requestId, i);
            assertEq(_epoch, epoch);
            bytes memory requestData = abi.encode(vm.addr(1000), 1, vm.addr(100), bytes("sourceFunction()"), 80001);
            assertEq(_requestData, requestData);
        }
        vm.stopPrank();
    }

    /**
     * Only admin should be able to create a request
     */
    function testNegativeRequest() public {
        // test creating a request from an account without required access control
        vm.prank(validator1);
        vm.expectRevert(
            "AccessControl: account 0x0731f35cec842a569bb63d6d3ed94ba888a96b54 is missing role 0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 80001);

        // test creating a request with an unsupported chain ID
        vm.prank(owner);
        vm.expectRevert(Bridge.UnsupportedChain.selector);
        // send chainId 1 which is not currently supported
        bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 1);
    }

    function testDynastyCreationTime() public {
        assertEq(bridge.firstDynastyCreation(), deploymentTime);
    }

    /**
     * DYNASTY, EPOCH, EPOCHMODE CALCULATION TESTS
     */

    /**
     * test for correct dynasty calculation
     */
    function testDynastyCalculation() public {
        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        assertEq(dynasty, 1);

        //skipDynasty(number of dynasties to skip, epoch)
        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
        dynasty = bridge.getDynasty();
        assertEq(dynasty, 2);
    }

    /**
     * test for parameter updation functions
     */

    function testSupportedChainId() public {
        // try to change status of an existing supported chain id to true (80001)
        vm.startPrank(owner);
        vm.expectRevert(Bridge.ChainStatusAlreadySet.selector);
        bridge.setSupportedChainId(80001, true);

        // change the status of the currently supported chain id and try to create request (80001)
        bridge.setSupportedChainId(80001, false);
        assertEq(bridge.isChainSupported(80001), false);
        vm.expectRevert(Bridge.UnsupportedChain.selector);
        // send chainId 80001 whose status is now false
        bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 80001);

        // add new chain id support and create requests successfully for the chain (1)
        bridge.setSupportedChainId(1, true);
        assertEq(bridge.isChainSupported(1), true);
        uint256 numRequests = 10;
        uint256 epoch = bridge.getEpoch();
        for (uint32 i = 1; i <= numRequests; i++) {
            bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 1);
            assertEq(bridge.numRequests(), i);
            (bool _fulfilled, uint32 _requestId, uint256 _epoch, bytes memory _requestData) = bridge.requests(i);
            assertEq(_fulfilled, false);
            assertEq(_requestId, i);
            assertEq(_epoch, epoch);
            bytes memory requestData = abi.encode(vm.addr(1000), 1, vm.addr(100), bytes("sourceFunction()"), 1);
            assertEq(_requestData, requestData);
        }
    }

    function testUpdateParams() public {
        uint256 newEpochLength = 1200;
        uint256 newDynastyLength = 10;
        uint256 newMinStake = 100 * (10 ** 18);
        uint16 newWithdrawLockPeriod = 10;
        uint8 newValidatorSelectionTimelimit = 5;
        uint16 newMaxRequests = 10;
        uint32 newMaxIteration = 100_000;
        uint256 newBlockReward = 1000 * (10 ** 18);
        uint32 newThreshold = 15;
        uint32 newNumParticipants = 20;
        vm.startPrank(owner);
        bridge.setBlockReward(newBlockReward);
        bridge.setMaxIteration(newMaxIteration);
        bridge.setMinStake(newMinStake);
        bridge.setEpochLength(newEpochLength);
        bridge.setDynastyLength(newDynastyLength);
        bridge.setWithdrawLockPeriod(newWithdrawLockPeriod);
        bridge.setValidatorSelectionTimelimit(newValidatorSelectionTimelimit);
        bridge.setMaxRequests(newMaxRequests);

        vm.expectRevert(Bridge.InvalidUpdation.selector);
        bridge.setThreshold(newThreshold);

        newThreshold = 6;
        bridge.setThreshold(newThreshold);

        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.setNumParticipants(newNumParticipants);

        assertEq(newThreshold, bridge.threshold());
        assertEq(newBlockReward, bridge.blockReward());
        assertEq(newMaxIteration, bridge.maxIteration());
        assertEq(newMinStake, bridge.minStake());
        assertEq(newEpochLength, bridge.epochLength());
        assertEq(newDynastyLength, bridge.dynastyLength());
        assertEq(newWithdrawLockPeriod, bridge.withdrawLockPeriod());
        assertEq(newValidatorSelectionTimelimit, bridge.validatorSelectionTimelimit());
        assertEq(newWithdrawLockPeriod, bridge.maxRequests());

        // Following set of code has been to written to test updation of numParticipants parameter

        // reset minStake to avoid LessThanMinStake() errors while staking
        uint256 minStake = 1000 * (10 ** 18);
        bridge.setMinStake(minStake);
        vm.stopPrank();
        // validatorSelection in place
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));

        for (uint8 i = 0; i < 30; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
        }

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        // Once we jumped to the next mode, we cant update threshold
        vm.startPrank(owner);
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.setThreshold(newThreshold);

        // numParticipants can be updated in the signerCreation mode
        bridge.setNumParticipants(newNumParticipants);
        assertEq(newNumParticipants, bridge.numParticipants());
        vm.stopPrank();
    }

    /**
     * test for correct epoch calculation
     */
    function testEpochCalculation() public {
        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();
        assertEq(dynasty, 1);
        assertEq(epoch, 1);

        //Increase time by epoch length to get new epoch count
        this.skipEpoch(1, bridge.epochLength());
        epoch = bridge.getEpoch();
        assertEq(epoch, 2);

        for (uint32 i = 2; i < 20; i++) {
            //New Dynasty, Epoch count continues
            this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
            epoch = bridge.getEpoch();
            dynasty = bridge.getDynasty();
            assertEq(dynasty, i);
            assertEq(epoch, ((i - 1) * bridge.dynastyLength()) + 1);
        }
    }

    /**
     * test for correct epoch modes calculation
     */
    function testEpochModeCalculation() public {
        vm.startPrank(owner);
        bridge.setValidatorSelectionTimelimit(2);
        vm.stopPrank();
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        //first Epoch should always be validatorSelection Mode in a dynasty
        uint8 epochMode = bridge.getMode();
        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();
        assertEq(dynasty, 1);
        assertEq(epoch, 1);
        assertEq(epochMode, uint8(EpochMode.ValidatorSelection));

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        for (uint8 i = 0; i < 5; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
        }

        // should still be in ValidatorSelection due to validatorSelectionTimelimit
        this.skipEpoch(1, bridge.epochLength());
        epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        assertEq(epoch, 2);
        assertEq(epochMode, uint8(EpochMode.ValidatorSelection));

        // should still be in ValidatorSelection due to numParticipants not reached
        this.skipEpoch((bridge.validatorSelectionTimelimit() - epoch) + 1, bridge.epochLength());
        epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        assertEq(epoch, bridge.validatorSelectionTimelimit() + 1);
        assertEq(epochMode, uint8(EpochMode.ValidatorSelection));
        for (uint8 i = 5; i < 10; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
        }

        // should immediately change to SignerCreation
        epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        signerAddress = bridge.signerAddressPerDynasty(dynasty, bridge.modeChange(dynasty));
        assertEq(signerAddress, address(0));
        assertEq(epoch, bridge.validatorSelectionTimelimit() + 1);
        assertEq(epochMode, uint8(EpochMode.SignerCreation));

        // change the numParticipants required and mode should remain as SignerCreation
        epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        vm.startPrank(owner);
        uint32 _numParticipants = 12;
        bridge.setNumParticipants(_numParticipants);
        assertEq(bridge.numParticipants(), _numParticipants);
        signerAddress = bridge.signerAddressPerDynasty(dynasty, bridge.modeChange(dynasty));
        assertEq(signerAddress, address(0));
        assertEq(epochMode, uint8(EpochMode.SignerCreation));
        // revert to default numParticipants after verifying the mode does not change to ValidatorSelection
        // after updating numParticipants
        bridge.setNumParticipants(10);
        vm.stopPrank();

        //PubKey not created yet, should still be in signerCreation mode in the next epoch
        this.skipEpoch(1, bridge.epochLength());
        epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        signerAddress = bridge.signerAddressPerDynasty(dynasty, bridge.modeChange(dynasty));
        assertEq(signerAddress, address(0));
        assertEq(epoch, bridge.validatorSelectionTimelimit() + 2);
        assertEq(epochMode, uint8(EpochMode.SignerCreation));

        // public key has been set in epoch 2. Should still be in signerCreation mode

        address localsignerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        vm.label(localsignerAddress, "Signer Address 1");
        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        _attestSigner(validators, localsignerAddress, bridge.getActiveSetPerDynasty(dynasty));

        //Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, localsignerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        epochMode = bridge.getMode();
        assertEq(epochMode, uint8(EpochMode.SignerCreation));

        //PubKey has been created, should now be in signing mode in the next epoch
        this.skipEpoch(1, bridge.epochLength());
        epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        signerAddress = bridge.signerAddressPerDynasty(dynasty, bridge.modeChange(dynasty));
        assertEq(signerAddress, localsignerAddress);
        assertEq(epoch, bridge.validatorSelectionTimelimit() + 3);
        assertEq(epochMode, uint8(EpochMode.Signing));

        // New Dynasty. Should be now be in validatorSelectionTimelimit
        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        epoch = bridge.getEpoch();
        dynasty = bridge.getDynasty();
        epochMode = bridge.getMode();
        signerAddress = bridge.signerAddressPerDynasty(dynasty, bridge.modeChange(dynasty));
        assertEq(signerAddress, address(0));
        assertEq(epoch, ((dynasty - 1) * bridge.dynastyLength()) + 1);
        assertEq(epochMode, uint8(EpochMode.ValidatorSelection));

        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        for (uint8 i = 0; i < validators.length; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
        }

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();
        epochMode = bridge.getMode();
        assertEq(epochMode, uint8(EpochMode.SignerCreation));

        signerAddress = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(signerAddress, "Signer Address 2");

        _attestSigner(validators, signerAddress, bridge.getActiveSetPerDynasty(dynasty));

        sig = this.getConfirmTransferSignature(epoch, signerAddress, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        //Should now change to signing once transfer is done
        this.skipEpoch(1, bridge.epochLength());
        epochMode = bridge.getMode();
        assertEq(epochMode, uint8(EpochMode.Signing));
    }

    /**
     * Internal function for validators in the active set to attest a signerAddres
     */
    function _attestSigner(address payable[] memory validators, address signer, uint32[] memory activeSet) internal {
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.attestSigner(signer);
        }
    }

    /**
     * internal function to transfer random value of bridge tokens from bridgeToken directly to validators with a min of minStake
     * to stake those tokens, and return the biggest validator ID
     */
    function _mockValidatorStake(address payable[] memory _validators) internal returns (uint32) {
        //Stake minStake for each validator created
        uint32 biggestValidatorId;
        uint256 biggestStake;
        for (uint8 i = 0; i < _validators.length; i++) {
            vm.roll(i + 1);
            uint256 randVal = Random.prng(_validators.length, blockhash(block.number - 1)) + 1;
            vm.startPrank(owner);
            stake[i + 1] = randVal * bridge.minStake();
            bridgeToken.transfer(_validators[i], stake[i + 1]);
            vm.stopPrank();

            vm.startPrank(_validators[i]);
            bridgeToken.approve(address(stakeManager), stake[i + 1]);
            stakeManager.stake(stake[i + 1]);
            vm.stopPrank();

            if (biggestStake < stake[i + 1]) {
                biggestStake = stake[i + 1];
                biggestValidatorId = i + 1;
            }
        }

        return biggestValidatorId;
    }
}
