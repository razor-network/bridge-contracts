// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Bridge} from "src/core/Bridge.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {StakeManager} from "src/core/StakeManager.sol";
import {BlameManager} from "src/core/BlameManager.sol";

contract SigningTest is Utilities {
    using stdStorage for StdStorage;

    address public owner;
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
        privKeys.push(43788133087041727893459500607664774196458479752328773334909089843514276704194);
        privKeys.push(35843802749631185423785067895403820357061322939561082199809626794025181920029);
        pubKeys.push(0x1c15e2990e76007fdf2fda604513218ce2e31004348fd374856152e1a026283c);
        pubKeys.push(0x0ef0d3d283da84eed8165fa72e96440b320e5c97be316b6049a9f8de8581742d);
        values.push(Structs.Value(1, 1, collectionId1NameHash, 1));
        values.push(Structs.Value(2, 2, collectionId2NameHash, 2));
        byteValues.push(abi.encode(Structs.Value(1, 1, collectionId1NameHash, 1)));
        byteValues.push(abi.encode(Structs.Value(2, 2, collectionId2NameHash, 2)));

        owner = vm.addr(1);
        vm.label(owner, "Owner");
        vm.startPrank(owner);
        bridgeToken = new BridgeToken();
        bridge = new Bridge();

        uint256 deploymentTime = bridge.firstDynastyCreation();
        stakeManager = new StakeManager(deploymentTime);
        blameManager = new BlameManager(deploymentTime);

        bridge.initialize(address(stakeManager), address(blameManager));
        stakeManager.initialize(address(bridgeToken), address(bridge));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(bridge));
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
     * COMMIT
     */

    /**
     * Tests valid messages being committed to the network
     */
    function testCommitMessage() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();
        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        // create requests, so that messages can be committed to fulfill them
        _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        // the hardcoded signerAddress is attested by the active set of validators
        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        // format the message data as required, and active set commits this message. number of message votes per epoch is verified
        // along with confirming if each validator in the active set have committed a message in the current epoch.
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.commitMessage(messageData);
            uint32 validatorId = activeSet[i];
            assertEq(bridge.numMessageVotesPerEpoch(dynasty, epoch, keccak256(messageData)), (i + 1));
            assertEq(bridge.hasValidatorCommitMessage(validatorId, dynasty, epoch), true);
        }
        // check if the message committed has passed the threshold and has been set as the message for the current epoch
        assertEq(bridge.messagePerEpoch(dynasty, epoch), keccak256(messageData));
    }

    /**
     * Tests the maximum number of requestIds that can fulfilled in a request per epoch
     */
    function testMaxRequests() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        // create requests, so that messages can be committed to fulfill them
        _createRequest(6);

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
        //setMaxRequests to 2 for testing
        bridge.setMaxRequests(2);
        vm.stopPrank();

        this.skipEpoch(1, bridge.epochLength());

        // requestIds.length(3) is greater than maxRequests(2) allowed
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](3);
        ids[0] = 1;
        ids[1] = 2;
        ids[2] = 3;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        sig = this.getSignature(messageData, privKeys[0]);
        vm.prank(validators[activeSet[0]]);
        // commit message and expect TooManyRequests error since we submit 3 ids to be fulfilled, but maxRequests is 2
        vm.expectRevert(Bridge.TooManyRequests.selector);
        bridge.commitMessage(messageData);
    }

    /**
     * Tests all revert cases for messages being committed to the network
     */
    function testInvalidCommitMessage() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        // create requests, so that messages can be committed to fulfill them
        _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        // the hardcoded signerAddress is attested by the active set of validators
        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());
        // 1st requestId to be fulfilled is sent as 0, but they should begin from 1
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 0;
        ids[1] = 1;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(Bridge.RequestIdCantBeZero.selector);
        bridge.commitMessage(messageData);

        // incorrect requestId order, expected in ascending order
        ids[0] = 2;
        ids[1] = 1;
        messageData = abi.encode(dynasty, epoch, ids, byteValues);

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(Bridge.RequestIdsNotInOrder.selector);
        bridge.commitMessage(messageData);

        // epoch sent is incorrect, not same as current epoch
        ids[0] = 1;
        ids[1] = 2;
        messageData = abi.encode(dynasty, epoch - 1, ids, byteValues);

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(abi.encodeWithSelector(Bridge.InvalidEpochInMessageData.selector, epoch, epoch - 1));
        bridge.commitMessage(messageData);

        // dynasty sent is incorrect, not same as current dynasty
        messageData = abi.encode(dynasty - 1, epoch, ids, byteValues);

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(abi.encodeWithSelector(Bridge.InvalidDynastyInMessageData.selector, dynasty, dynasty - 1));
        bridge.commitMessage(messageData);

        // length of requestIds (0) is not equal to length of values (2)
        bytes[] memory emptyRequestIds = new bytes[](0);
        messageData = abi.encode(dynasty, epoch, emptyRequestIds, byteValues);
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(Bridge.InvalidMessage.selector);
        bridge.commitMessage(messageData);

        // validator trying to commit after already committing successfully in the current epoch
        messageData = abi.encode(dynasty, epoch, ids, byteValues);
        _commitMessage(validators, messageData, activeSet);
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(Bridge.ValidatorAlreadyCommitted.selector);
        bridge.commitMessage(messageData);

        // trying to commit message after the block is confirmed
        sig = this.getSignature(messageData, privKeys[0]);
        vm.prank(validators[activeSet[8] - 1]);
        bridge.finalizeBlock(sig, messageData);
        vm.prank(validators[activeSet[8] - 1]);
        vm.expectRevert(Bridge.BlockAlreadyConfirmed.selector);
        bridge.commitMessage(messageData);

        // sending request id which is already fulfilled (requestId 2 is already fulfilled here)
        this.skipEpoch(1, bridge.epochLength());
        epoch = bridge.getEpoch();
        ids[0] = 2;
        ids[1] = 3;
        messageData = abi.encode(dynasty, epoch, ids, byteValues);

        uint32 requestIdFulfilled;
        for (uint32 i = 0; i < ids.length; i++) {
            (bool _fulfilled,,,) = bridge.requests(ids[i]);
            if (_fulfilled) {
                requestIdFulfilled = ids[i];
                break;
            }
        }
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(abi.encodeWithSelector(Bridge.RequestAlreadyFulfilled.selector, requestIdFulfilled));
        bridge.commitMessage(messageData);

        // previous requestId (id 3) not fulfilled
        ids[0] = 4;
        ids[1] = 5;
        messageData = abi.encode(dynasty, epoch, ids, byteValues);

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(Bridge.PreviousRequestNotFulfilled.selector);
        bridge.commitMessage(messageData);
    }

    /**
     * Tests committing messages trying to fulfill invalid requests which have been created in the same epoch
     */
    function testInvalidCommitEpoch() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();
        // requests are not created in epoch 1
        // _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        // requests created here in epoch: modeChange[dynasty], so each request Struct will have epoch as modeChange[dynasty]
        // expect a revert since we can only fulfill requests created in request.epoch < currentEpoch
        _createRequest(6);
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);

        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(abi.encodeWithSelector(Bridge.IncorrectRequestEpoch.selector, epoch, epoch));
        bridge.commitMessage(messageData);
    }

    /**
     * Tests committing messages in the incorrect EpochMode and with non existent validators
     */
    function testNegativeCommit() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();
        bytes memory messageData = abi.encode(uint32(1), byteValues);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        // check that validators should only be allowed to commit message when in Signing mode
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.commitMessage(messageData);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        _adminConfirmSigner(epoch, signerAddress);

        // this will fail since we can only begin committing messages after epoch
        // in which modeChange has occurred (SignerCreation -> Signing)
        // this.skipEpoch(1,  bridge.epochLength());
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.commitMessage(messageData);

        this.skipEpoch(1, bridge.epochLength());
        epoch = bridge.getEpoch();

        // owner is not a validator
        vm.prank(owner);
        vm.expectRevert(Bridge.ValidatorNotSelected.selector);
        bridge.commitMessage(messageData);
    }

    /**
     * SIGNING
     */

    /**
     * Tests signing and finalizing valid blocks for 2 epochs consecutively
     */
    function testFinalizingBlocks() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        // create requests, so that messages can be committed to fulfill them
        _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        // the hardcoded signerAddress is attested by the active set of validators
        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        // 1st signing epoch, commit valid message and finalize the block
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        _commitMessage(validators, messageData, activeSet);
        sig = this.getSignature(messageData, privKeys[0]);

        vm.recordLogs();
        _finalizeBlock(validators, sig, messageData, activeSet);
        {
            Vm.Log[] memory entries = vm.getRecordedLogs();

            assertEq(entries.length, 1);
            assertEq(entries[0].topics[0], keccak256("FinalizeBlock(uint32,bytes,address,bytes,address,uint256,uint256)"));
            (uint32 winner,,,,) = abi.decode(entries[0].data, (uint32, bytes, address, bytes, uint256));
            assertEq(stakeManager.getStake(winner), stake[winner] + bridge.blockReward());
        }

        this.skipEpoch(1, bridge.epochLength());
        epoch = bridge.getEpoch();
        // skip to next block, to handle foundry issue with emitted events
        vm.roll(block.number + 1);
        // 2nd signing epoch, commit valid message and finalize the block
        ids[0] = 3;
        ids[1] = 4;
        messageData = abi.encode(dynasty, epoch, ids, byteValues);
        _commitMessage(validators, messageData, activeSet);
        sig = this.getSignature(messageData, privKeys[0]);

        vm.recordLogs();
        _finalizeBlock(validators, sig, messageData, activeSet);
        {
            Vm.Log[] memory entries = vm.getRecordedLogs();

            assertEq(entries.length, 1);
            assertEq(entries[0].topics[0], keccak256("FinalizeBlock(uint32,bytes,address,bytes,address,uint256,uint256)"));
            (uint32 winner,,,,) = abi.decode(entries[0].data, (uint32, bytes, address, bytes, uint256));
            assertEq(stakeManager.getStake(winner), stake[winner] + bridge.blockReward());
        }
    }

    /**
     * Tests signing empty messages and finalizing valid empty blocks
     */
    function testEmptyBlockSigningWithRequests() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        // create 2 requests
        _createRequest(2);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        // commit and finalize the block fulfilling 2 requests, so there are no more pending requests (fulfill the 2 created requests)
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        _commitMessage(validators, messageData, activeSet);

        sig = this.getSignature(messageData, privKeys[0]);

        vm.recordLogs();
        _finalizeBlock(validators, sig, messageData, activeSet);

        {
            Vm.Log[] memory entries = vm.getRecordedLogs();

            assertEq(entries.length, 1);
            assertEq(entries[0].topics[0], keccak256("FinalizeBlock(uint32,bytes,address,bytes,address,uint256,uint256)"));
            (uint32 winner,,,,) = abi.decode(entries[0].data, (uint32, bytes, address, bytes, uint256));
            assertEq(stakeManager.getStake(winner), stake[winner] + bridge.blockReward());
        }
        this.skipEpoch(1, bridge.epochLength());

        // verify the signature is valid and the number of requests is equal to number of requests fulfill
        // showing that there are no more pending requests
        epoch = bridge.getEpoch();
        (, bytes memory message, bytes memory signature) = bridge.blocks(epoch - 1);
        assertEq(messageData, message);
        assertEq(sig, signature);
        assertEq(bridge.numRequestsFulfilled(), bridge.numRequests());

        // commit an empty message and finalize the empty block
        messageData = abi.encode(dynasty, epoch, new uint32[](0), new bytes[](0));
        _commitMessage(validators, messageData, activeSet);
        sig = this.getSignature(messageData, privKeys[0]);
        _finalizeBlock(validators, sig, messageData, activeSet);
        this.skipEpoch(1, bridge.epochLength());
        // verify the previous epoch finalized an empty block
        epoch = bridge.getEpoch();
        (, message, signature) = bridge.blocks(epoch - 1);
        assertEq(messageData, message);
        assertEq(sig, signature);
        assertEq(bridge.numRequestsFulfilled(), bridge.numRequests());
    }
    /**
     * Tests validators committing incorrect messages
     */

    function testNegativeEmptyBlockSigningWithRequests() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        // create 2 requests
        _createRequest(2);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        // validators attempt to commit an empty message when there are pending requests
        epoch = bridge.getEpoch();
        bytes memory messageData = abi.encode(dynasty, epoch, new uint32[](0), new bytes[](0));
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            vm.expectRevert(Bridge.InvalidMessage.selector);
            bridge.commitMessage(messageData);
        }

        this.skipEpoch(1, bridge.epochLength());

        // commit valid messages and fulfill all pending requests
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        messageData = abi.encode(dynasty, epoch, ids, byteValues);
        _commitMessage(validators, messageData, activeSet);

        sig = this.getSignature(messageData, privKeys[0]);

        vm.recordLogs();
        _finalizeBlock(validators, sig, messageData, activeSet);

        {
            Vm.Log[] memory entries = vm.getRecordedLogs();

            assertEq(entries.length, 1);
            assertEq(entries[0].topics[0], keccak256("FinalizeBlock(uint32,bytes,address,bytes,address,uint256,uint256)"));
            (uint32 winner,,,,) = abi.decode(entries[0].data, (uint32, bytes, address, bytes, uint256));
            assertEq(stakeManager.getStake(winner), stake[winner] + bridge.blockReward());
        }
        this.skipEpoch(1, bridge.epochLength());
        // verify the previous epoch finalized all pending requests
        epoch = bridge.getEpoch();
        (, bytes memory message, bytes memory signature) = bridge.blocks(epoch - 1);
        assertEq(messageData, message);
        assertEq(sig, signature);
        assertEq(bridge.numRequestsFulfilled(), bridge.numRequests());

        // no pending requests to be fulfilled, only empty blocks allowed
        messageData = abi.encode(dynasty, epoch, ids, byteValues);
        assertEq(bridge.numRequestsFulfilled(), bridge.numRequests());
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            vm.expectRevert(Bridge.EmptyMessageExpected.selector);
            bridge.commitMessage(messageData);
        }
    }

    /**
     * Tests signing and finalizing empty blocks when there are no requests created
     */
    function testEmptyBlockSigningWithNoRequests() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();
        // no requests are created
        // _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        // signing empty block with no created requests
        epoch = bridge.getEpoch();
        bytes memory messageData = abi.encode(dynasty, epoch, new uint32[](0), new bytes[](0));
        _commitMessage(validators, messageData, activeSet);

        sig = this.getSignature(messageData, privKeys[0]);

        _finalizeBlock(validators, sig, messageData, activeSet);
        this.skipEpoch(1, bridge.epochLength());
        // verify the previous epoch's finalized block was empty
        epoch = bridge.getEpoch();
        (, bytes memory message, bytes memory signature) = bridge.blocks(epoch - 1);
        assertEq(messageData, message);
        assertEq(sig, signature);
        assertEq(bridge.numRequestsFulfilled(), bridge.numRequests());
    }

    /**
     * Tests finalizing a block with an incorrect signerAddress
     */
    function testInvalidFinalizeBlockSigning() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipEpoch(1, bridge.epochLength());

        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        _commitMessage(validators, messageData, activeSet);
        // sign the valid message with an incorrect signerAddress
        sig = this.getSignature(messageData, privKeys[1]);
        // invalid signature since privKey[0] was expected
        vm.prank(validators[activeSet[8] - 1]);
        vm.expectRevert(Bridge.InvalidSignature.selector);
        bridge.finalizeBlock(sig, messageData);
    }

    /**
     * Tests all reverts while finalizing a block
     */
    function testNegativeFinalizeBlockSigning() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);
        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        // this.skipEpoch(1,  bridge.epochLength());
        // incorrect mode, actual: SignerCreation expected: Signing
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        sig = this.getSignature(messageData, privKeys[0]);

        vm.prank(validators[0]);
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.finalizeBlock(sig, messageData);

        this.skipEpoch(1, bridge.epochLength());

        epoch = bridge.getEpoch();
        messageData = abi.encode(dynasty, epoch, ids, byteValues);
        // _commitMessage(validators, messageData, activeSet);
        sig = this.getSignature(messageData, privKeys[0]);

        // no message has been committed in the current epoch
        vm.prank(validators[activeSet[8] - 1]);
        vm.expectRevert(Bridge.NoMessageCommitted.selector);
        bridge.finalizeBlock(sig, messageData);

        // commit a valid message, send a different message to finalizeBlock
        _commitMessage(validators, messageData, activeSet);

        vm.prank(validators[activeSet[8] - 1]);
        vm.expectRevert(Bridge.InvalidMessage.selector);
        bridge.finalizeBlock(sig, bytes("InvalidMessageData"));
    }

    /**
     * Test tries to confirm a signerAddress without the validators attesting a signerAddress in that epoch
     */
    function testConfirmSignerWithoutAttestation() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        _createRequest(6);

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        uint8 epochMode = bridge.getMode();
        assertEq(epochMode, uint8(EpochMode.SignerCreation));

        //Skip signerAddress attestations and call confirmSigner
        // _attestSigner(validators, signerAddress, activeSet);
        // admin tries confirms the signerAddress of the 1st dynasty, but reverts since there is no attested signerAddress
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        vm.expectRevert(Bridge.ZeroSignerAddress.selector);
        bridge.confirmSigner(sig);
        vm.stopPrank();
    }

    /**
     * Tests when validators attest a zero address, and when validators try to confirmSigner when there is no attestedSignerAddress
     */
    function testSigningZeroAddress() public {
        //signerAddress is set to a ZERO_ADDRESS
        signerAddress = address(0);
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        _createRequest(6);

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // _attestSigner(validators, signerAddress, activeSet);
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            vm.expectRevert(Bridge.ZeroSignerAddress.selector);
            bridge.attestSigner(signerAddress);
            uint32 validatorId = stakeManager.validatorIds(validators[activeSet[i] - 1]);

            (uint32 _validatorId, address _signerAddress) = bridge.signerAttestations(validatorId, dynasty, epoch);
            // verify that the attestation for the validator is empty since validator tried to attest a ZERO_ADDRESS
            assertEq(_validatorId, 0);
            assertEq(_signerAddress, address(0));
        }

        // admin tries to confirmSigner by sending ZERO_ADDRESS as signerAddress in the signature
        vm.startPrank(owner);
        bytes memory invalidSig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        vm.expectRevert(Bridge.ZeroSignerAddress.selector);
        bridge.confirmSigner(invalidSig);
        vm.stopPrank();

        // admin tries to confirmSigner when there is no attestedSignerAddress for the current dynasty
        vm.startPrank(owner);
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        vm.expectRevert(Bridge.ZeroSignerAddress.selector);
        bridge.confirmSigner(sig);
        vm.stopPrank();
    }

    /**
     * Tests jailing a validator
     */
    function testJailValidator() public {
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        uint32 validatorId = stakeManager.getValidatorId(validators[0]);
        uint32[] memory ids = new uint32[](1);
        ids[0] = validatorId;

        // jail validators[0] and verify the jail end dynasty
        vm.startPrank(owner);
        uint256 dynasty = bridge.getDynasty();
        // grant JAILER_ROLE to owner so they can jail validators
        stakeManager.grantRole(bridge.JAILER_ROLE(), owner);
        stakeManager.jailValidators(ids);
        Structs.Validator memory validator = stakeManager.getValidator(validatorId);
        assertEq(validator.jailEndDynasty, dynasty + bridge.numJailDynasty());
        vm.stopPrank();

        // validitor should be able to participate in the network after jailEndDynasty
        this.skipDynasty(bridge.numJailDynasty(), 0, bridge.dynastyLength(), bridge.epochLength());
        dynasty = bridge.getDynasty();
        vm.startPrank(validators[0]);
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint256 iteration = this.getIteration(
            stakeManager.getStake(biggestValidatorId), stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators()
        );
        bridge.validatorSelection(iteration, biggestValidatorId);
    }

    /**
     * Tests jailing a validator without required conditions
     */
    function testNegativeJailValidator() public {
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        uint32 validatorId = stakeManager.getValidatorId(validators[0]);
        uint32[] memory ids = new uint32[](1);
        ids[0] = validatorId;

        // only address with JAILER_ROLE should be aallowed to jail validator
        vm.startPrank(validators[0]);
        vm.expectRevert(
            "AccessControl: account 0x0731f35cec842a569bb63d6d3ed94ba888a96b54 is missing role 0x3a612eb9ead461499ef30313166f3e259cef70ffda582b57c4dedbb097274d99"
        );
        stakeManager.jailValidators(ids);
        vm.stopPrank();

        vm.startPrank(owner);
        // jail a non-existent validator
        // grant JAILER_ROLE to owner
        stakeManager.grantRole(bridge.JAILER_ROLE(), owner);
        vm.expectRevert(StakeManager.InvalidValidator.selector);
        ids[0] = 0;
        stakeManager.jailValidators(ids);
        ids[0] = 101;
        vm.expectRevert(StakeManager.ValidatorDoesNotExist.selector);
        stakeManager.jailValidators(ids);

        ids[0] = validatorId;
        // cannot jail a validator who is already jailed
        stakeManager.jailValidators(ids);
        vm.expectRevert(StakeManager.ValidatorAlreadyInJail.selector);
        stakeManager.jailValidators(ids);
        vm.stopPrank();

        // validator shouldn't be allowed to participate in validator selection if jailed
        vm.startPrank(validators[0]);
        uint256 dynasty = bridge.getDynasty();
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint256 iteration = this.getIteration(
            stakeManager.getStake(biggestValidatorId), stakeManager.getStake(validatorId), validatorId, salt, stakeManager.numValidators()
        );
        vm.expectRevert(Bridge.ValidatorInJailPeriod.selector);
        bridge.validatorSelection(iteration, biggestValidatorId);
        vm.stopPrank();
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

    /**
     * internal function to create requests in the network that need to be fulfilled
     */
    function _createRequest(uint8 numRequests) internal {
        for (uint32 i = numRequests; i > 0; i--) {
            vm.prank(owner);
            bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 80001);
        }
    }

    /**
     * internal function for validators to commit messages in the network
     */
    function _commitMessage(address payable[] memory validators, bytes memory messageData, uint32[] memory activeSet) internal {
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.commitMessage(messageData);
        }
    }

    /**
     * internal function for validators to finalize blocks in the network
     */
    function _finalizeBlock(address payable[] memory validators, bytes memory sig, bytes memory messageData, uint32[] memory activeSet)
        internal
    {
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.finalizeBlock(sig, messageData);
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
            vm.roll(i + 50);
            uint256 randVal = Random.prng(_validators.length, blockhash(block.number - 1)) + 1;
            vm.startPrank(owner);
            stake[i + 1] = (randVal) * bridge.minStake();
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

    // internal function to create validators and mock staking tokens in the network
    function _createValidatorsAndStake() internal returns (address payable[] memory, uint32) {
        // hardcoded signerAddress
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        vm.label(signerAddress, "Signer Address 1");
        return (validators, biggestValidatorId);
    }

    // internal function for the admin to confirmSigner in the 1st dynasty
    function _adminConfirmSigner(uint256 _epoch, address _signerAddress) internal returns (bytes memory) {
        // admin confirms the signerAddress of the 1st dynasty since there is no signerAddress in the previous dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(_epoch, _signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();
        return (sig);
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

    // internal function to get the validatorId of the validator with the biggest stake in the network
    function _getBiggestValidatorId(address payable[] memory validators) internal view returns (uint32) {
        uint32 biggestValidatorId;
        uint256 biggestStake;
        for (uint8 i = 0; i < validators.length; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            uint256 validatorStake = stakeManager.getStake(validatorId);

            if (biggestStake < validatorStake) {
                biggestStake = validatorStake;
                biggestValidatorId = validatorId;
            }
        }

        return biggestValidatorId;
    }
}
