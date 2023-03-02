// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/library/Random.sol";

import {Bridge} from "src/core/Bridge.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {StakeManager} from "src/core/StakeManager.sol";
import {BlameManager} from "src/core/BlameManager.sol";

contract ValidatorSelect is Utilities {
    using stdStorage for StdStorage;

    address public owner;
    address payable public validator1;
    address payable public validator2;
    uint256 public deploymentTime;
    uint256[] public privKeys;
    bytes32[] public pubKeys;
    address public signerAddress;
    bytes32 public collectionId1NameHash = keccak256("collectionId1");
    bytes32 public collectionId2NameHash = keccak256("collectionId2");
    uint256 public contractReserve = 10000e18;
    mapping(uint32 => uint256) public stake;

    Bridge public bridge;
    BridgeToken public bridgeToken;
    StakeManager public stakeManager;
    BlameManager public blameManager;

    /**
     * general set up required for validator selection
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
        blameManager.initialize(address(bridge), address(stakeManager));

        bridge.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));

        stakeManager.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(bridge));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(blameManager));
        stakeManager.grantRole(bridge.JAILER_ROLE(), address(bridge));

        blameManager.grantRole(bridge.PENALTY_RESETTER_ROLE(), address(bridge));

        bridgeToken.transfer(address(stakeManager), contractReserve);
        vm.stopPrank();

        vm.label(address(bridge), "Bridge");
        vm.label(address(stakeManager), "Stake Manager");
        vm.label(address(bridgeToken), "Bridge Token");
        vm.label(address(blameManager), "Blame Manager");
    }

    /**
     * Tests Validator Selection, create 30 validators and confirm which validators are in active set and their corresponding iteration
     */
    function testValidatorSelection() external {
        address payable[] memory validators = this.createValidators(30);
        //stake a random value of tokens with a minimum of minStake, returns validator ID with biggest stake
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();

        // create a salt, calculate iteration and call validatorSelection for 30 validators
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
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
            //confirm iteration of each validator is equal to the one calculated using getIteration (Utilities)
            assertEq(bridge.validatorIterationPerDynasty(i + 1, dynasty), iteration);
        }
        //number of participants in the network should be equal to the current dynasties Active Set
        uint32[] memory activeSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(activeSet.length, bridge.numParticipants());

        //check which validators are in active set, assert true or false depending if validator ID is present in the active set
        for (uint8 i = 0; i < validators.length; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            if (_validatorInActiveSet(activeSet, validatorId)) {
                assertEq(bridge.isValidatorSelectedPerDynasty(validatorId, dynasty), true);
            } else {
                assertEq(bridge.isValidatorSelectedPerDynasty(validatorId, dynasty), false);
            }
        }

        //validator iterations should be in asc order
        for (uint8 i = 0; i < activeSet.length - 1; i++) {
            assert(
                bridge.validatorIterationPerDynasty(activeSet[i], dynasty) < bridge.validatorIterationPerDynasty(activeSet[i + 1], dynasty)
            );
        }
    }

    /**
     * Tests Validator Selection, and active set depending on the biggestValidatorId sent by the validators
     */
    function testBiggestStakeTests() external {
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();

        uint256 maxBiggestStake = stakeManager.getStake(biggestValidatorId);
        uint256 midBiggestStake = stakeManager.getStake(biggestValidatorId - 1);
        uint256 minBiggestStake = stakeManager.getStake(biggestValidatorId + 1);

        uint32 validatorId;
        uint256 iteration;

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = bridge.getActiveSetPerDynasty(dynasty);

        // validators send midBiggestStake, which is not the biggestValidatorsId, but the mid value.
        // all validators should be added to active set, activeSet expected = 5
        for (uint8 i = 0; i < 5; i++) {
            validatorId = stakeManager.getValidatorId(validators[i]);
            iteration =
                this.getIteration(midBiggestStake, stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators()); // send midBiggestStake
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId - 1); //midBiggestStake
            assertEq(bridge.validatorIterationPerDynasty(validatorId, dynasty), iteration);
            assertEq(bridge.biggestStakePerDynasty(dynasty), midBiggestStake);

            activeSet = bridge.getActiveSetPerDynasty(dynasty);
            assertEq(activeSet.length, i + 1);
        }
        // validators[5] is not added to active set since the biggest stake submitted (minBiggestStake)
        // is lower than the current midBiggestStake sent by prev validators in active set
        validatorId = stakeManager.getValidatorId(validators[5]);
        iteration = this.getIteration(minBiggestStake, stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators()); //minBiggest = 30k
        vm.prank(validators[5]);
        bridge.validatorSelection(iteration, biggestValidatorId + 1);
        assertEq(bridge.validatorIterationPerDynasty(validatorId, dynasty), iteration);
        assertEq(bridge.biggestStakePerDynasty(dynasty), midBiggestStake);
        activeSet = bridge.getActiveSetPerDynasty(dynasty);
        //active set length remains 5
        assertEq(activeSet.length, 5);

        // validators[6] sends the maxBiggestStake, which is more than the current midBiggestStake
        // sent by validators in the current active set. So the validators in the active set are removed
        // and replaced by validators[6] only.
        validatorId = stakeManager.getValidatorId(validators[6]);
        iteration = this.getIteration(maxBiggestStake, stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators());
        vm.prank(validators[6]);
        bridge.validatorSelection(iteration, biggestValidatorId);
        assertEq(bridge.validatorIterationPerDynasty(validatorId, dynasty), iteration);
        assertEq(bridge.biggestStakePerDynasty(dynasty), maxBiggestStake);
        activeSet = bridge.getActiveSetPerDynasty(dynasty);
        //activeSet reset and length is 1 ie, current validators[6] previously added validators are removed
        assertEq(activeSet.length, 1);
        //continue with validatorSelection with the expected max biggest stake
        for (uint8 i = 7; i < validators.length; i++) {
            validatorId = stakeManager.getValidatorId(validators[i]);
            iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
            assertEq(bridge.validatorIterationPerDynasty(i + 1, dynasty), iteration);
        }
        // check that the active set is equal to the number of participants required by the network
        activeSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(activeSet.length, bridge.numParticipants());
        // verify appropriate validators are in the active set
        for (uint8 i = 0; i < validators.length; i++) {
            validatorId = stakeManager.getValidatorId(validators[i]);
            if (_validatorInActiveSet(activeSet, validatorId)) {
                assertEq(bridge.isValidatorSelectedPerDynasty(validatorId, dynasty), true);
            } else {
                assertEq(bridge.isValidatorSelectedPerDynasty(validatorId, dynasty), false);
            }
        }
        // verify that the validators in the active set are inserted appropriately,
        // ie, in ascending order of iteration.
        for (uint8 i = 0; i < activeSet.length - 1; i++) {
            assert(
                bridge.validatorIterationPerDynasty(activeSet[i], dynasty) < bridge.validatorIterationPerDynasty(activeSet[i + 1], dynasty)
            );
        }
    }

    /**
     * Tests all error cases wrt to validatorSelection, handle and check reverts
     */
    function testNegativeValidatorSelection() external {
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32 validatorId = stakeManager.getValidatorId(validators[0]);
        uint256 iteration = this.getIteration(
            stakeManager.getStake(biggestValidatorId), stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators()
        );

        //owner is not a validator, and has no stake in the network (validatorId = 0)
        vm.prank(owner);
        vm.expectRevert(Bridge.InvalidValidator.selector);
        bridge.validatorSelection(iteration, biggestValidatorId);

        //owner now stakes, and becomes a validator, but immediately unstakes and withdraws
        //this ensures owner has a valid validatorId
        vm.startPrank(owner);
        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());
        stakeManager.unstake();
        epoch = bridge.getEpoch();
        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();
        stakeManager.withdraw();

        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        iteration = this.getIteration(
            stakeManager.getStake(biggestValidatorId), stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators()
        );

        //owner is a validator, but since owner has withdrawn all stake, they are not allowed to call validatorSelection
        uint32 ownerValidatorId = stakeManager.getValidatorId(owner);
        vm.expectRevert(abi.encodeWithSelector(Bridge.LessThanMinStake.selector, stakeManager.getStake(ownerValidatorId)));
        bridge.validatorSelection(iteration, biggestValidatorId);
        vm.stopPrank();

        //sending incorrect iteration, check getIteration(), validators[0] not elected in current active set
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.NotElected.selector);
        bridge.validatorSelection(iteration + 1, biggestValidatorId);

        // send the correct iteration
        vm.prank(validators[0]);
        bridge.validatorSelection(iteration, biggestValidatorId);

        //try to call validatorSelection again in the same epoch, after successfully submitting iteration
        //expect revert since this validator has already submitted iteration to contract
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.IterationAlreadyCalculated.selector);
        bridge.validatorSelection(iteration, biggestValidatorId);

        //call validatorSelection for all remaining validators (except validators[0] since they have called above, i = 1)
        for (uint8 i = 1; i < validators.length; i++) {
            validatorId = stakeManager.getValidatorId(validators[i]);
            iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
        }
        //skip epoch, mode is changed from ValidatorSelection to SignerCreation
        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        //expect revert since we can call validatorSelection only in ValidatorSelection mode
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.validatorSelection(iteration, biggestValidatorId);
    }

    /**
     * Test case for only random churning
     */
    function testRandomChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 1);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 1);

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));

        uint256 currentLength = currentActiveSet.length;
        for (uint256 i = 1; i < 3; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);

            if (bridge.isChurnedOut(dynasty, validatorId) || bridge.isValidatorSelectedPerDynasty(validatorId, dynasty)) continue;

            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
            if (currentLength != bridge.numParticipants()) currentLength++;
            currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
            assertEq(currentActiveSet.length, currentLength);
        }
    }

    /**
     * Test case for only random + unstaking churning
     */
    function testRandomUnstakingChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        // one of the activeSet validators unstaking
        vm.prank(validators[activeSet[0] - 1]);
        stakeManager.unstake();

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 2);
        assertEq(churnedOutValidators[0], activeSet[0]);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 2);

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));

        uint256 currentLength = currentActiveSet.length;
        for (uint256 i = 1; i < 3; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);

            if (bridge.isChurnedOut(dynasty, validatorId) || bridge.isValidatorSelectedPerDynasty(validatorId, dynasty)) continue;

            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
            if (currentLength != bridge.numParticipants()) currentLength++;
            currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
            assertEq(currentActiveSet.length, currentLength);
        }
    }

    /**
     * Test case for random + unstaking churning max validators
     */
    function testRandomUnstakingMaxChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        // one of the activeSet validators unstaking
        vm.prank(validators[activeSet[0] - 1]);
        stakeManager.unstake();

        vm.prank(validators[activeSet[1] - 1]);
        stakeManager.unstake();

        vm.prank(validators[activeSet[2] - 1]);
        stakeManager.unstake();

        vm.prank(validators[activeSet[3] - 1]);
        stakeManager.unstake();

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(StakeManager.StillInActiveSet.selector);
        stakeManager.withdraw();

        vm.prank(validators[activeSet[3] - 1]);
        vm.expectRevert(StakeManager.StillInActiveSet.selector);
        stakeManager.withdraw();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32 numValidatorsToChurnOut = (bridge.numParticipants() * bridge.maxChurnPercentage()) / bridge.BASE_DENOMINATOR();

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, numValidatorsToChurnOut);
        assertEq(churnedOutValidators[0], activeSet[0]);
        assertEq(currentActiveSet.length, bridge.numParticipants() - numValidatorsToChurnOut);

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));

        uint256 currentLength = currentActiveSet.length;
        for (uint256 i = 1; i < 6; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);

            if (bridge.isChurnedOut(dynasty, validatorId) || bridge.isValidatorSelectedPerDynasty(validatorId, dynasty)) continue;

            uint256 iteration = this.getIteration(
                stakeManager.getStake(biggestValidatorId),
                stakeManager.getStake(validatorId),
                validatorId,
                salt,
                stakeManager.numValidators()
            );
            vm.prank(validators[i]);
            bridge.validatorSelection(iteration, biggestValidatorId);
            if (currentLength != bridge.numParticipants()) currentLength++;
            currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
            assertEq(currentActiveSet.length, currentLength);
        }

        vm.prank(validators[activeSet[3] - 1]);
        vm.expectRevert(StakeManager.StillInActiveSet.selector);
        stakeManager.withdraw();

        vm.prank(validators[activeSet[0] - 1]);
        stakeManager.withdraw();

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        // unstaking validator should be churned since his withdraw lock had expired the previous dynasty
        vm.prank(validators[activeSet[3] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        vm.prank(validators[activeSet[3] - 1]);

        stakeManager.withdraw();
    }

    /**
     * Test case for churning when the network is inactive for a few dynasties
     */
    function testInactivityChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipDynasty(2, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        (, activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 1);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 1);
    }

    /**
     * Test case for churned out validator taking part in selection again
     */
    function testChurnedOutSelection() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 1);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 1);

        // churned out validator trying to take in selection. Validator wont be added
        vm.prank(validators[churnedOutValidators[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 1);
        assertEq(bridge.isValidatorSelectedPerDynasty(churnedOutValidators[0], dynasty), false);
        assertEq(bridge.isChurnedOut(dynasty, churnedOutValidators[0]), true);
    }

    function testRandomBannedChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        uint8 blameType = 0;
        uint32[] memory culprits = new uint32[](1);
        culprits[0] = activeSet[0];
        bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);

            if (blameManager.hasJumpedDynasty(dynasty)) continue;

            uint32 validatorId = stakeManager.getValidatorId(validators[activeSet[i] - 1]);
            // blameHash should match with blameAttestations attested by validator
            assertEq(_blameHash, blameManager.blameAttestations(validatorId, dynasty, epoch, blameType));
        }

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 2);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 2);
        assertEq(churnedOutValidators[0], culprits[0]);
        assertEq(bridge.isValidatorSelectedPerDynasty(culprits[0], dynasty), false);

        Structs.Validator memory validator = stakeManager.getValidator(culprits[0]);
        assertEq(validator.jailEndDynasty, dynasty + bridge.numJailDynasty());
    }

    function testRandomBannedHighPenChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();

        _attestSigner(validators, signerAddress, activeSet);

        // admin confirms the signerAddress of the 1st dynasty since there is no signerAddress in the previous dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        this.skipEpoch(1, bridge.epochLength());

        epoch = bridge.getEpoch();

        // high penalty points. If no validators are being banned then they can get churned
        uint8 blameType = 1;
        uint32[] memory culprits2 = new uint32[](1);
        culprits2[0] = activeSet[1];
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits2);
        }

        // banned validators
        blameType = 3;
        uint32[] memory culprits = new uint32[](1);
        culprits[0] = activeSet[0];
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);
        }

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 2);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 2);
        assertEq(churnedOutValidators[0], culprits[0]);
        assertEq(bridge.isValidatorSelectedPerDynasty(culprits[0], dynasty), false);
        assertEq(bridge.isValidatorSelectedPerDynasty(culprits2[0], dynasty), true);

        Structs.Validator memory validator = stakeManager.getValidator(culprits[0]);
        assertEq(validator.jailEndDynasty, dynasty + bridge.numJailDynasty());
    }

    function testRandomBannedUnstakeHighPenChurning() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        _attestSigner(validators, signerAddress, activeSet);

        // admin confirms the signerAddress of the 1st dynasty since there is no signerAddress in the previous dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        this.skipEpoch(1, bridge.epochLength());

        // Unstake validator
        uint32 unstakeValidator = activeSet[2];
        vm.prank(validators[activeSet[2] - 1]);
        stakeManager.unstake();

        // High Penalty validator. They wont be churned if banned validators exist
        uint8 blameType = 1;
        uint32[] memory culprits2 = new uint32[](1);
        culprits2[0] = activeSet[3];
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits2);
        }

        // Banned validator
        blameType = 3;
        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1];
        culprits[1] = activeSet[0];
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);
        }

        dynasty = bridge.getDynasty();

        // using the validator in the activeSet so that either it will be churned out or still be in the active set
        // without adding any to the active set
        vm.prank(validators[activeSet[0] - 1]);
        bridge.validatorSelection(0, biggestValidatorId);

        uint32[] memory churnedOutValidators = bridge.getChurnedOutValidatorsPerDynasty(dynasty);
        uint32[] memory currentActiveSet = bridge.getActiveSetPerDynasty(dynasty);
        assertEq(churnedOutValidators.length, 3);
        assertEq(currentActiveSet.length, bridge.numParticipants() - 3);
        assertEq(churnedOutValidators[0], culprits[1]);
        assertEq(churnedOutValidators[1], culprits[0]);
        assertEq(churnedOutValidators[2], unstakeValidator);
        //Banned Churn
        assertEq(bridge.isValidatorSelectedPerDynasty(culprits[0], dynasty), false);
        assertEq(bridge.isValidatorSelectedPerDynasty(culprits[1], dynasty), false);
        //Unstake Churn
        assertEq(bridge.isValidatorSelectedPerDynasty(unstakeValidator, dynasty), false);
        //High Penalty but Churn doesnt go through since validators are being banned
        assertEq(bridge.isValidatorSelectedPerDynasty(culprits2[0], dynasty), true);

        Structs.Validator memory validator = stakeManager.getValidator(culprits[0]);
        assertEq(validator.jailEndDynasty, dynasty + bridge.numJailDynasty());
        validator = stakeManager.getValidator(culprits[1]);
        assertEq(validator.jailEndDynasty, dynasty + bridge.numJailDynasty());
    }

    /**
     * internal function to select validators adding them to the active set of the current dynasty
     */
    function _validatorSelection(address payable[] memory validators, uint32 biggestValidatorId, bytes32 salt)
        internal
        returns (uint32[] memory)
    {
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

        return bridge.getActiveSetPerDynasty(bridge.getDynasty());
    }

    /**
     * internal function for validators in the active set to attest a signerAddres
     */
    function _attestSigner(address payable[] memory validators, address signer, uint32[] memory activeSet) internal {
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.attestSigner(signer);
        }
    }

    // internal function to create validators and mock staking tokens in the network
    function _createValidatorsAndStake() internal returns (address payable[] memory, uint32) {
        // hardcoded signerAddress
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        return (validators, biggestValidatorId);
    }

    // internal function to calculate salt and to select validators
    function _selectValidators(uint256 _dynasty, address payable[] memory _validators, uint32 _biggestValidatorId)
        internal
        returns (bytes32, uint32[] memory)
    {
        // validatorSelection is run for the current dynasty
        bytes32 salt = keccak256(abi.encodePacked(_dynasty, bridge.getActiveSetPerDynasty(_dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(_validators, _biggestValidatorId, salt);
        return (salt, activeSet);
    }

    /**
     * internal function to transfer random value of bridge tokens from bridgeToken directly to validators with a min of minStake
     * and to stake those tokens, and return the biggest validator ID
     */
    function _mockValidatorStake(address payable[] memory _validators) internal returns (uint32) {
        //Stake minStake for each validator created
        uint32 biggestValidatorId;
        uint256 biggestStake;
        for (uint8 i = 0; i < _validators.length; i++) {
            vm.roll(i + 50);
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

    /**
     * internal function that checks if validatorId exists in the current active set
     */
    function _validatorInActiveSet(uint32[] memory activeSet, uint32 validatorId) internal pure returns (bool) {
        for (uint8 i = 0; i < activeSet.length; i++) {
            if (activeSet[i] == validatorId) {
                return true;
            }
        }
        return false;
    }
}
