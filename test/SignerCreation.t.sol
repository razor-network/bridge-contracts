// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Bridge} from "src/core/Bridge.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {StakeManager} from "src/core/StakeManager.sol";
import {BlameManager} from "src/core/BlameManager.sol";

/**
 * Tests for keygen and signer transfer
 */
contract SignerCreationTest is Utilities {
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
     * General setup which includes deployment of contracts and initializing it, hardcoded values are used for
     * simulating message to be bridged. Hardcoded privKeys are used which act as signerAddress
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
        blameManager.initialize(address(bridge), address(stakeManager));

        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(blameManager));
        stakeManager.grantRole(bridge.JAILER_ROLE(), address(blameManager));

        stakeManager.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));
        bridge.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));
        bridge.grantRole(bridge.SET_DISPUTED_ROLE(), address(blameManager));

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

    // KEYGEN

    /**
     * test when the active set validators attest same signer address
     */
    function testSinglePubKeySigner() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();
        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.attestSigner(signerAddress);
            uint32 validatorId = stakeManager.validatorIds(validators[activeSet[i] - 1]);
            (uint32 _validatorId, address _signerAddress) = bridge.signerAttestations(validatorId, dynasty, epoch);
            assertEq(_validatorId, validatorId);
            assertEq(_signerAddress, signerAddress);
        }

        _adminConfirmSigner(epoch, signerAddress);

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);
        assertEq(bridge.signerVotesPerAttestation(dynasty, epoch, signerAddress), activeSet.length);

        this.skipEpoch(1, bridge.epochLength());
        uint8 epochMode = bridge.getMode();
        assertEq(epochMode, uint8(EpochMode.Signing));
    }

    /**
     * test when the active set validators attest different signer address
     */
    function testMulPubKeySigner() public {
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        address[] memory signerAddresss = new address[](4);
        uint8[] memory votes = new uint8[](4);
        for (uint8 i = 0; i < signerAddresss.length; i++) {
            votes[i] = 0;
        }
        signerAddresss[0] = address(100);
        signerAddresss[1] = address(101);
        signerAddresss[2] = address(102);
        signerAddresss[3] = address(103);
        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            uint256 j = i % signerAddresss.length;
            bridge.attestSigner(signerAddresss[j]);
            votes[j] = votes[j] + 1;
            uint32 validatorId = stakeManager.validatorIds(validators[activeSet[i] - 1]);
            (uint32 _validatorId, address _signerAddress) = bridge.signerAttestations(validatorId, dynasty, epoch);
            assertEq(_validatorId, validatorId);
            assertEq(_signerAddress, signerAddresss[j]);
        }

        uint8 maxIndex = 0;
        uint8 maxVote = votes[0];
        for (uint8 i = 0; i < signerAddresss.length; i++) {
            assertEq(bridge.signerVotesPerAttestation(dynasty, epoch, signerAddresss[i]), votes[i]);

            if (maxVote < votes[i]) {
                maxIndex = i;
                maxVote = votes[i];
            }
        }

        uint256 minVotes = bridge.threshold() + 1;

        // if votes for particular signer address are more than minVotes, then confirm transfer takes place
        if (minVotes <= maxVote) {
            vm.startPrank(owner);
            bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddresss[maxIndex], 1);
            bridge.confirmSigner(sig);
            vm.stopPrank();

            assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddresss[maxIndex]);
            this.skipEpoch(1, bridge.epochLength());
            uint8 epochMode = bridge.getMode();
            assertEq(epochMode, uint8(EpochMode.Signing));
        } else {
            assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), address(0));
            this.skipEpoch(1, bridge.epochLength());
            uint8 epochMode = bridge.getMode();
            assertEq(epochMode, uint8(EpochMode.SignerCreation));
        }
    }

    /**
     * Negative test cases for attest signer
     */
    function testNegativeSigner() external {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();
        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            bridge.attestSigner(signerAddress);
        }

        vm.startPrank(owner);
        bytes32 messageHash = keccak256(abi.encodePacked(epoch, signerAddress));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(1, messageHash);
        bytes memory sig = bytes.concat(r, s, bytes1(v));
        bridge.confirmSigner(sig);
        vm.stopPrank();

        // attest signer should be only performed in SignerCreation mode only
        this.skipEpoch(1, bridge.epochLength());
        epoch = bridge.getEpoch();
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.attestSigner(signerAddress);

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        epoch = bridge.getEpoch();
        dynasty = bridge.getDynasty();

        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        // Only existing validator should be able to attest signer
        vm.prank(owner);
        vm.expectRevert(Bridge.InvalidValidator.selector);
        bridge.attestSigner(signerAddress);

        // validator can attest signer only once in an epoch
        vm.prank(validators[activeSet[0] - 1]);
        bridge.attestSigner(signerAddress);
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(Bridge.AlreadyAttested.selector);
        bridge.attestSigner(signerAddress);

        vm.startPrank(owner);
        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());
        stakeManager.unstake();
        epoch = bridge.getEpoch();
        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
        stakeManager.withdraw();
        vm.stopPrank();

        epoch = bridge.getEpoch();
        dynasty = bridge.getDynasty();

        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        // only validators that are part of active set should be able to attest signer
        vm.prank(owner);
        vm.expectRevert(Bridge.ValidatorNotSelected.selector);
        bridge.attestSigner(signerAddress);
    }

    // SIGNER TRANSFER

    /**
     * Tests for signer transfer
     */
    function testSignerTransfer() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();
        uint256 dynasty = bridge.getDynasty();

        uint256 epoch = bridge.getEpoch();
        _createRequest(6);

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
        //Keygen with new address
        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        signerAddress = this.getAddress(bytes.concat(pubKeys[1]));
        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        // attest new signer address
        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);

        epoch = bridge.getEpoch();
        sig = this.getConfirmTransferSignature(epoch, signerAddress, privKeys[0]);

        // confirm new signer address
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);
        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        (address newSignerAddress, uint256 _epoch, bytes memory signature) = bridge.signerTransferProofs(dynasty);
        assertEq(epoch, _epoch);
        assertEq(newSignerAddress, signerAddress);
        assertEq(signature, sig);
    }

    /**
     * Test case for disputing the signer sent on bridge based on the fact that double signing took place on
     * native and destination chains where the new signer addresses were different
     */
    function testBridgeTransferProof() external {
        // Starting off on setting the signer address
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        vm.label(signerAddress, "Signer Address 1");

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        // validator selection takes place
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        //Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // repeating the entire process
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        // validator selection takes place
        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, newSignerAddressSign, activeSet);

        // previous signer address transfers ownership to the newly attested signer address. This is a valid transfer signature
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        // previous signer address also creates a signature for destination chains where the signer address is different
        address invalidAddress = vm.addr(10);
        bytes memory invalidSig = this.getConfirmTransferSignature(epoch, invalidAddress, privKeys[0]);

        // malicious proof sent to result manager is sent to bridge for dispute
        blameManager.resultManagerProofDispute(Structs.SignerTransfer(invalidAddress, epoch, invalidSig));

        // all the validators should be slashed and jailed
        uint32[] memory prevActiveSet = bridge.getActiveSetPerDynasty(dynasty - 1);
        for (uint32 i = 0; i < prevActiveSet.length; i++) {
            uint32 validatorId = prevActiveSet[i];
            uint256 jailEndDynasty = stakeManager.getValidatorJailEndDynasty(validatorId);
            uint256 stakerStake = stakeManager.getStake(validatorId);
            assertEq(dynasty + bridge.numJailDynasty(), jailEndDynasty);
            assert(stakerStake < stake[validatorId]);
        }

        uint256 newDynasty = bridge.getDynasty();
        uint256 newEpoch = bridge.getEpoch();

        assertEq(newDynasty, dynasty + 1);
        assertEq(newEpoch, (dynasty * bridge.dynastyLength()) + 1);
        assertEq(newDynasty, stakeManager.getDynasty());
        assertEq(newEpoch, stakeManager.getEpoch());
        assertEq(newDynasty, blameManager.getDynasty());
        assertEq(newEpoch, blameManager.getEpoch());

        {
            bytes32 _salt = keccak256(abi.encodePacked(newDynasty, bridge.getActiveSetPerDynasty(newDynasty - 1)));
            address payable[] memory _validators = validators;
            uint32 _biggestValidatorId = _getBiggestValidatorId(_validators);

            uint32 _validatorId = stakeManager.getValidatorId(_validators[0]);
            uint256 iteration = this.getIteration(
                stakeManager.getStake(_biggestValidatorId),
                stakeManager.getStake(_validatorId),
                _validatorId,
                _salt,
                stakeManager.numValidators()
            );
            vm.prank(_validators[0]);
            bridge.validatorSelection(iteration, _biggestValidatorId);

            assertEq(bridge.getActiveSetPerDynasty(newDynasty).length, 1);
        }
    }

    /**
     * Test case for disputing the signer sent on bridge based on the fact that double signing took place on
     * native and destination chains where the epochs were different
     */
    function testEpochBridgeTransferProof() external {
        // Starting off on setting the signer address
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        // validator selection takes place
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        //Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // repeating the entire process
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        // validator selection takes place
        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, newSignerAddressSign, activeSet);

        // previous signer address transfers ownership to the newly attested signer address. This is a valid transfer signature
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        // previous signer address also creates a signature for destination chains where the epoch is different
        bytes memory invalidSig = this.getConfirmTransferSignature(epoch + 100, newSignerAddressSign, privKeys[0]);

        // malicious proof sent to result manager is sent to bridge for dispute
        blameManager.resultManagerProofDispute(Structs.SignerTransfer(newSignerAddressSign, epoch + 100, invalidSig));

        // all the validators should be slashed and jailed
        uint32[] memory prevActiveSet = bridge.getActiveSetPerDynasty(dynasty - 1);
        for (uint32 i = 0; i < prevActiveSet.length; i++) {
            uint32 validatorId = prevActiveSet[i];
            uint256 jailEndDynasty = stakeManager.getValidatorJailEndDynasty(validatorId);
            uint256 stakerStake = stakeManager.getStake(validatorId);
            assertEq(dynasty + bridge.numJailDynasty(), jailEndDynasty);
            assert(stakerStake < stake[validatorId]);
        }

        uint256 newDynasty = bridge.getDynasty();
        uint256 newEpoch = bridge.getEpoch();

        assertEq(newDynasty, dynasty + 1);
        assertEq(newEpoch, (dynasty * bridge.dynastyLength()) + 1);
        assertEq(newDynasty, stakeManager.getDynasty());
        assertEq(newEpoch, stakeManager.getEpoch());
        assertEq(newDynasty, blameManager.getDynasty());
        assertEq(newEpoch, blameManager.getEpoch());

        {
            bytes32 _salt = keccak256(abi.encodePacked(newDynasty, bridge.getActiveSetPerDynasty(newDynasty - 1)));
            address payable[] memory _validators = validators;
            uint32 _biggestValidatorId = _getBiggestValidatorId(_validators);

            uint32 _validatorId = stakeManager.getValidatorId(_validators[0]);
            uint256 iteration = this.getIteration(
                stakeManager.getStake(_biggestValidatorId),
                stakeManager.getStake(_validatorId),
                _validatorId,
                _salt,
                stakeManager.numValidators()
            );
            vm.prank(_validators[0]);
            bridge.validatorSelection(iteration, _biggestValidatorId);

            assertEq(bridge.getActiveSetPerDynasty(newDynasty).length, 1);
        }
    }

    /**
     * Negative test cases on dispute function on the native chain
     */
    function testNegativeBridgeTransferProof() external {
        // Starting off on setting the signer address
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        // validator selection takes place
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        vm.expectRevert(Bridge.ZeroSignerAddress.selector);
        blameManager.resultManagerProofDispute(Structs.SignerTransfer(address(0), 0, bytes("")));

        //Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // repeating the entire process
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        // validator selection takes place
        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, newSignerAddressSign, activeSet);

        // previous signer address transfers ownership to the newly attested signer address. This is a valid transfer signature
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        // sending same details as stored on the native chain
        vm.expectRevert(BlameManager.InvalidDetailsDispute.selector);
        blameManager.resultManagerProofDispute(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));

        // signatures done by different address other than the previous signer address then revert
        address invalidAddress = vm.addr(10);
        bytes memory invalidSig2 = this.getConfirmTransferSignature(epoch + 1, invalidAddress, 10);
        vm.expectRevert(BlameManager.InvalidSignatureDispute.selector);
        blameManager.resultManagerProofDispute(Structs.SignerTransfer(invalidAddress, epoch + 1, invalidSig2));
    }

    /**
     * Invalid signature related test cases for signer transfer
     */
    function testNegativeSignerTransferSign() public {
        address oldSignerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        _createRequest(6);

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, oldSignerAddress, activeSet);

        //admin confirms the signerAddress of the 1st dynasty since there is no signerAddress in the previous dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, oldSignerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        //Should not be in SignerTransfer since this is first dynasty
        this.skipEpoch(1, bridge.epochLength());
        uint8 epochMode = bridge.getMode();
        epoch = bridge.getEpoch();
        assertEq(epochMode, uint8(EpochMode.Signing));

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());
        //Keygen with new address
        address newSignerAddress = this.getAddress(bytes.concat(pubKeys[1]));

        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, newSignerAddress, activeSet);

        epoch = bridge.getEpoch();
        sig = this.getConfirmTransferSignature(epoch, oldSignerAddress, privKeys[0]);

        // confirm signer should fail if previous dynasty signer address is not confirming signer with attested signer address
        // of current dynasty
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.InvalidSignature.selector);
        bridge.confirmSigner(sig);

        sig = this.getConfirmTransferSignature(epoch, newSignerAddress, privKeys[1]);

        // confirm signer should fail if signature is not generated from previous signer address
        vm.prank(validators[0]);
        vm.expectRevert(Bridge.InvalidSignature.selector);
        bridge.confirmSigner(sig);
    }

    /**
     * generalised negative test cases for signer transfer
     */
    function testNegativeSignerTransfer() public {
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        signerAddress = this.getAddress(bytes.concat(pubKeys[1]));

        epoch = bridge.getEpoch();
        dynasty = bridge.getDynasty();

        biggestValidatorId = _getBiggestValidatorId(validators);
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        _attestSigner(validators, signerAddress, activeSet);

        epoch = bridge.getEpoch();
        sig = this.getConfirmTransferSignature(epoch, signerAddress, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        //cant send signature twice
        vm.expectRevert(Bridge.SignerAlreadyConfirmed.selector);
        bridge.confirmSigner(sig);

        this.skipEpoch(1, bridge.epochLength());
        //signature should be sent only in signer creation mode
        vm.expectRevert(Bridge.IncorrectMode.selector);
        bridge.confirmSigner(sig);
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
     * internal function to create requests in the network that need to be fulfilled
     */
    function _createRequest(uint8 numRequests) internal {
        for (uint32 i = numRequests; i > 0; i--) {
            vm.prank(owner);
            bridge.createRequest(vm.addr(1000), 1, vm.addr(100), "sourceFunction()", 80001);
        }
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

    // internal function to create validators and mock staking tokens in the network
    function _createValidatorsAndStake() internal returns (address payable[] memory, uint32) {
        // hardcoded signerAddress
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        vm.label(signerAddress, "Signer Address 1");
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
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

    /**
     * internal function to get the validatorId of the validator with the biggest stake in the network
     */
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
