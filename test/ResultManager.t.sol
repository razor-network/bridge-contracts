// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Bridge} from "src/core/Bridge.sol";
import {ResultManager} from "src/core/ResultManager.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {StakeManager} from "src/core/StakeManager.sol";
import {BlameManager} from "src/core/BlameManager.sol";

contract ResultManagerTest is Utilities {
    using stdStorage for StdStorage;

    uint256 public deploymentTime;
    uint256 public polygonFork;
    uint256 public skaleFork;
    uint256[] public privKeys;
    bytes32[] public pubKeys;
    address public signerAddress;
    address public owner;
    Structs.Value[] public values;
    bytes[] public byteValues;
    bytes32 public collectionId1NameHash = keccak256("collectionId1");
    bytes32 public collectionId2NameHash = keccak256("collectionId2");
    uint256 public contractReserve = 10000e18;
    mapping(uint32 => uint256) public stake;

    string public polygonUrl = vm.rpcUrl("polygon");
    string public skaleUrl = vm.rpcUrl("skale");

    Bridge public bridge;
    ResultManager public resultManager;
    BridgeToken public bridgeToken;
    StakeManager public stakeManager;
    BlameManager public blameManager;

    /**
     * general set up required for signing, hardcoded values and bytes to be used as the message being bridged
     * we also use hardcoded privKeys to act as signerAddress. For result manager tests, we are also setting up chain forks
     * where we are deploying result manager on polygon fork and the rest on the skale fork
     * Polygon - destination chain
     * Skale - native chain
     */
    function setUp() external {
        owner = vm.addr(1);
        vm.label(owner, "Owner");
        polygonFork = vm.createFork(polygonUrl);
        skaleFork = vm.createFork(skaleUrl);

        privKeys.push(43788133087041727893459500607664774196458479752328773334909089843514276704194);
        privKeys.push(35843802749631185423785067895403820357061322939561082199809626794025181920029);
        pubKeys.push(0x1c15e2990e76007fdf2fda604513218ce2e31004348fd374856152e1a026283c);
        pubKeys.push(0x0ef0d3d283da84eed8165fa72e96440b320e5c97be316b6049a9f8de8581742d);
        values.push(Structs.Value(1, 1, collectionId1NameHash, 1));
        values.push(Structs.Value(2, 2, collectionId2NameHash, 2));
        byteValues.push(abi.encode(Structs.Value(1, 1, collectionId1NameHash, 1)));
        byteValues.push(abi.encode(Structs.Value(2, 2, collectionId2NameHash, 2)));

        vm.selectFork(polygonFork);
        vm.startPrank(owner);
        resultManager = new ResultManager();
        vm.stopPrank();

        vm.selectFork(skaleFork);

        vm.startPrank(owner);
        bridgeToken = new BridgeToken();
        bridge = new Bridge();

        deploymentTime = bridge.firstDynastyCreation();
        stakeManager = new StakeManager(deploymentTime);
        blameManager = new BlameManager(deploymentTime);

        bridge.initialize(address(stakeManager), address(blameManager));
        stakeManager.initialize(address(bridgeToken), address(bridge));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(bridge));
        stakeManager.grantRole(bridge.JAILER_ROLE(), address(bridge));

        stakeManager.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));
        bridge.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));

        blameManager.grantRole(bridge.PENALTY_RESETTER_ROLE(), address(bridge));

        // set suppported chain id so that requests can be created
        bridge.setSupportedChainId(80001, true);

        bridgeToken.transfer(address(stakeManager), contractReserve);
        vm.stopPrank();

        vm.label(address(bridge), "Bridge");
        vm.label(address(stakeManager), "Stake Manager");
        vm.label(address(bridgeToken), "Bridge Token");
        vm.label(address(blameManager), "Blame Manager");
        vm.label(address(resultManager), "Result Manager");
    }

    /**
     * Test case for setting up the signer on destination chain once it is confirmed on native chain
     */
    function testSetSignerAddress() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        // Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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

        // previous signer address transfers ownership to the newly attested signer address
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Anyone can set the signer address now since previous signer address exists on the result manager
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, newSignerAddressSign);
    }

    function testSetSignerAddressAfterNetworkStall() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        // Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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

        // previous signer address transfers ownership to the newly attested signer address
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Anyone can set the signer address now since previous signer address exists on the result manager
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, newSignerAddressSign);

        vm.selectFork(skaleFork);

        signerAddress = vm.addr(1000);
        // such an increase is required due to timeskip issues in forking environment tests
        this.skipDynasty(1 + 2, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());

        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        // admin has to be make the call since network stalled
        vm.startPrank(owner);
        sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting since network stalled
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);
    }

    /**
     * Negative test case for setting up the signer on destination chain once it is confirmed on native chain
     */
    function testNegativeSetSigner() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        // Only admin does this call as this is the first dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        //Only admin does this call as this is the first dynasty
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        this.skipDynasty(1, (((epoch - 1) % bridge.dynastyLength()) - 2), bridge.dynastyLength(), bridge.epochLength());

        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");
        dynasty = bridge.getDynasty();
        epoch = bridge.getEpoch();

        biggestValidatorId = _getBiggestValidatorId(validators);

        // validator selection takes place
        salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, newSignerAddressSign, activeSet);

        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);

        // previous signer address transfers ownership to the newly attested signer address
        vm.prank(validators[0]);
        bridge.confirmSigner(sig);

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // incorrect signer being sent
        vm.prank(validators[0]);
        vm.expectRevert(ResultManager.InvalidSignature.selector);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));

        //incorrect signer
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[1]);
        vm.prank(validators[0]);
        vm.expectRevert(ResultManager.InvalidSignature.selector);
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));

        //Power already transferred
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        vm.prank(validators[0]);
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));

        vm.prank(validators[0]);
        vm.expectRevert(ResultManager.InvalidSignature.selector);
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
    }

    /**
     * Test case for disputing the signer sent on result manager based on the fact that double signing took place on
     * native and destination chains where the new signer addresses were different
     */
    function testDisputeSigner() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        //Only admin does this call as this is the first dynasty
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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

        vm.selectFork(polygonFork);
        // Prev signer setting malicious transfer proof
        resultManager.setSigner(Structs.SignerTransfer(invalidAddress, epoch, invalidSig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, invalidAddress);

        // anyone can dispute as long as it is within the dispute period
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).isDisputed, true);
    }

    /**
     * Test case for disputing the signer sent on result manager based on the fact that double signing took place on
     * native and destination chains where epoch were different
     */
    function tesEpochDisputeSigner() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        //Only admin does this call as this is the first dynasty
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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

        vm.selectFork(polygonFork);
        // Prev signer setting malicious transfer proof
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch + 100, invalidSig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, newSignerAddressSign);

        // anyone can dispute as long as it is within the dispute period
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).isDisputed, true);
    }

    function testNegativeDisputeSigner() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        //Only admin does this call as this is the first dynasty
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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
        bytes memory invalidSig = this.getConfirmTransferSignature(epoch, invalidAddress, 10);

        vm.selectFork(polygonFork);
        // Prev signer setting malicious transfer proof
        resultManager.setSigner(Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, newSignerAddressSign);

        // Invalid Dynasty being sent
        vm.expectRevert(ResultManager.InvalidDynasty.selector);
        resultManager.disputeSigner(dynasty + 1, Structs.SignerTransfer(invalidAddress, epoch, invalidSig));

        // Signer proof sent is not signed by the previous signer address
        vm.expectRevert(ResultManager.InvalidSignatureDispute.selector);
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(invalidAddress, epoch, invalidSig));

        // Signer proof sent is same as what it was set previously
        vm.expectRevert(ResultManager.InvalidDetailsDispute.selector);
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(newSignerAddressSign, epoch, sig));

        skip(resultManager.DISPUTE_TIME_PERIOD());

        // Dispute Time period has expired
        vm.expectRevert(ResultManager.DisputeExpired.selector);
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(invalidAddress, epoch, invalidSig));
    }

    /**
     * Test case when the active set do not confirmSigner on native chain and submit invalid blocks on destination chain
     * the admin can confirmSigner and dispute the signerAddress on the destination chain
     */
    function testAdminDisputeSigner() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (bytes32 salt, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        assertEq(bridge.signerAddressPerDynasty(dynasty, epoch), signerAddress);

        epoch = bridge.getEpoch();

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        //Only admin does this call as this is the first dynasty
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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

        // previous signer address DOES NOT transfer ownership to the newly attested signer address
        // sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        // vm.prank(validators[0]);
        // bridge.confirmSigner(sig);

        //Admin confirms the valid newSignerAddress and transfers the power
        vm.startPrank(owner);
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        // previous signer address creates a signature for destination chains where the signer address is malicious
        address invalidAddress = vm.addr(10);
        vm.label(invalidAddress, "Malicious");
        bytes memory invalidSig = this.getConfirmTransferSignature(epoch, invalidAddress, privKeys[0]);

        vm.selectFork(polygonFork);
        // set the malicious address as the signer on the destination chain
        resultManager.setSigner(Structs.SignerTransfer(invalidAddress, epoch, invalidSig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, invalidAddress);

        //Admin disputes the malicious signer address set on the destination chain
        vm.selectFork(polygonFork);
        vm.startPrank(owner);
        vm.label(newSignerAddressSign, "Legit");
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        // assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, newSignerAddressSign);
        assertEq(resultManager.getSignerAddressDetails(dynasty).isDisputed, true);
    }

    /**
     * Test case for setting the block on destination chain once it is confirmed on native chain
     */
    function testSetBlock() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        _createRequest(6);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));

        // signers confirm block on the native chain
        vm.selectFork(skaleFork);
        this.skipEpoch(1 + 2, bridge.epochLength());

        // first signing epoch
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        // commit valid messages and fulfill all pending requests
        _commitMessage(validators, messageData, activeSet);
        sig = this.getSignature(messageData, privKeys[0]);

        // creating a signature on the committed message
        _finalizeBlock(validators, sig, messageData, activeSet);

        (uint256 timestamp, bytes memory message, bytes memory signature) = bridge.blocks(epoch);
        this.skipEpoch(1, bridge.epochLength());
        epoch = bridge.getEpoch();

        // moving to destination to set block on result manager
        vm.selectFork(polygonFork);

        skip(resultManager.DISPUTE_TIME_PERIOD());

        // Anyone can set a confirmed block
        resultManager.setBlock(Structs.Block(timestamp, message, signature));

        Structs.Block memory resultBlock = resultManager.getBlock(epoch - 1);
        assertEq(resultBlock.message, messageData);
        assertEq(resultBlock.signature, sig);

        (uint256 value, int8 pow) = resultManager.getResultFromID(1);
        assertEq(value, 1);
        assertEq(pow, 1);

        (value, pow) = resultManager.getResult(collectionId2NameHash);
        assertEq(value, 2);
        assertEq(pow, 2);

        uint16 id = resultManager.getCollectionID(collectionId1NameHash);
        assertEq(id, 1);

        id = resultManager.getCollectionID(collectionId2NameHash);
        assertEq(id, 2);

        uint16 collectionId = resultManager.getRequestToCollection(1);
        assertEq(collectionId, 1);

        collectionId = resultManager.getRequestToCollection(2);
        assertEq(collectionId, 2);

        uint16[] memory activeCollections = resultManager.getActiveCollections();
        assertEq(activeCollections.length, 2);

        assertEq(resultManager.getCollectionStatus(1), true);
        assertEq(resultManager.getCollectionStatus(2), true);
    }

    /**
     * Test case for making the a signer address is rate limited on destination chains
     */
    function testBlockLimit() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        _createRequest(6);
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

        uint256 dynastyLength = bridge.dynastyLength();
        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));

        // confirming blocks till numBlocksLimit becomes zero
        uint32[] memory ids = new uint32[](2);

        uint32 j = 1;
        for (uint256 i = epoch + 1; i <= dynastyLength; i++) {
            ids[0] = j;
            ids[1] = j + 1;
            bytes memory messageData = abi.encode(dynasty, i, ids, byteValues);
            sig = this.getSignature(messageData, privKeys[0]);
            resultManager.setBlock(Structs.Block(block.timestamp, messageData, sig));
            j += 2;
        }

        ids[0] = j;
        ids[1] = j + 1;
        sig = this.getSignature(abi.encode(dynasty, dynastyLength + 1, ids, byteValues), privKeys[0]);
        // should not be able to set block since block limit has become 0
        vm.expectRevert(ResultManager.BlockLimitReached.selector);
        resultManager.setBlock(Structs.Block(block.timestamp, abi.encode(dynasty, dynastyLength + 1, ids, byteValues), sig));
    }

    /**
     * Test case for discarding a blocks confirmed during the dispute period after a signer address gets disputed
     */
    function testDiscardBlocksAfterDispute() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
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

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, signerAddress);

        // repeating the entire process on the native chain
        vm.selectFork(skaleFork);
        address newSignerAddressSign = this.getAddress(bytes.concat(pubKeys[1]));
        vm.label(newSignerAddressSign, "Signer Address 2");

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength() - 2), bridge.dynastyLength(), bridge.epochLength());
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

        vm.selectFork(polygonFork);
        // Prev signer setting malicious transfer proof
        resultManager.setSigner(Structs.SignerTransfer(invalidAddress, epoch, invalidSig));
        assertEq(resultManager.getSignerAddressDetails(dynasty).signerAddress, invalidAddress);

        //blocks being set during the dispute period
        uint32[] memory ids = new uint32[](2);
        uint32 j = 1;
        for (uint256 i = epoch + 1; i <= epoch + 5; i++) {
            ids[0] = j;
            ids[1] = j + 1;
            bytes memory messageData = abi.encode(dynasty, i, ids, byteValues);
            sig = this.getSignature(messageData, 10);
            resultManager.setBlock(Structs.Block(block.timestamp, messageData, sig));
            j += 2;
            assertEq(resultManager.getSignerAddressDetails(dynasty).blocksConfirmedDuringDisputePeriod.length, i - epoch);
        }

        // anyone can dispute as long as it is within the dispute period
        sig = this.getConfirmTransferSignature(epoch, newSignerAddressSign, privKeys[0]);
        resultManager.disputeSigner(dynasty, Structs.SignerTransfer(newSignerAddressSign, epoch, sig));
        Structs.SignerAddressDetails memory details = resultManager.getSignerAddressDetails(dynasty);
        assertEq(details.isDisputed, true);

        // checking whether blocks confirmed during the dispute period are removed
        for (uint256 i = 0; i < details.blocksConfirmedDuringDisputePeriod.length; i++) {
            Structs.Block memory resultBlocks = resultManager.getBlock(details.blocksConfirmedDuringDisputePeriod[i]);
            assertEq(resultBlocks.message, bytes(""));
            assertEq(resultBlocks.signature, bytes(""));
        }

        ids[0] = j;
        ids[1] = j + 1;
        sig = this.getSignature(abi.encode(dynasty, epoch + 6, ids, byteValues), privKeys[0]);
        // should not be able to set block since signer address disputed
        vm.expectRevert(ResultManager.SignerAddressDisputed.selector);
        resultManager.setBlock(Structs.Block(block.timestamp, abi.encode(dynasty, epoch + 6, ids, byteValues), sig));
    }

    /**
     * Signature related negative test case for setting the block on destination chain once it is confirmed on native chain
     */
    function testNegativeSetBlockSignature() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        _createRequest(6);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));

        // signers confirm block on the native chain
        vm.selectFork(skaleFork);
        this.skipEpoch(1 + 2, bridge.epochLength());

        // first signing epoch
        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        // commit valid messages and fulfill all pending requests
        _commitMessage(validators, messageData, activeSet);
        bytes32 messageHash = keccak256(messageData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKeys[0], messageHash);
        sig = bytes.concat(r, s, bytes1(v));

        // creating a signature on the committed message
        _finalizeBlock(validators, sig, messageData, activeSet);

        this.skipEpoch(1, bridge.epochLength());

        if (v == 27) {
            sig = bytes.concat(r, s, (bytes1(v + 1)));
        } else {
            sig = bytes.concat(r, s, (bytes1(v - 1)));
        }

        // moving to destination to set block on result manager
        vm.selectFork(polygonFork);

        skip(resultManager.DISPUTE_TIME_PERIOD());

        // manipulating the signature and sending it to result manager
        vm.expectRevert(ResultManager.InvalidSignature.selector);
        resultManager.setBlock(Structs.Block(block.timestamp, messageData, sig));
    }

    /**
     * Message related negative test case for setting the block on destination chain once it is confirmed on native chain
     */
    function testNegativeSetBlockMessage() external {
        // Starting off on the native chain
        vm.selectFork(skaleFork);
        (address payable[] memory validators, uint32 biggestValidatorId) = _createValidatorsAndStake();

        _createRequest(6);

        uint256 dynasty = bridge.getDynasty();
        uint256 epoch = bridge.getEpoch();

        (, uint32[] memory activeSet) = _selectValidators(dynasty, validators, biggestValidatorId);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );

        epoch = bridge.getEpoch();
        // signer being attested by selected validators
        _attestSigner(validators, signerAddress, activeSet);

        (bytes memory sig) = _adminConfirmSigner(epoch, signerAddress);

        // moving to destination to set signer on result manager
        vm.selectFork(polygonFork);
        // Admin is setting 1st signer since there is no previous signer set on the destination
        vm.prank(owner);
        resultManager.setSigner(Structs.SignerTransfer(signerAddress, epoch, sig));

        // signers confirm block on the native chain
        vm.selectFork(skaleFork);
        this.skipEpoch(1 + 2, bridge.epochLength());

        epoch = bridge.getEpoch();
        uint32[] memory ids = new uint32[](2);
        ids[0] = 1;
        ids[1] = 2;
        bytes memory messageData = abi.encode(dynasty, epoch, ids, byteValues);
        // commit valid messages and fulfill all pending requests
        _commitMessage(validators, messageData, activeSet);
        sig = this.getSignature(messageData, privKeys[0]);
        // creating a signature on the committed message
        _finalizeBlock(validators, sig, messageData, activeSet);
        (uint256 timestamp, bytes memory message, bytes memory signature) = bridge.blocks(epoch);

        this.skipEpoch(1, bridge.epochLength());

        messageData = abi.encode(dynasty, epoch - 2, ids, byteValues);
        sig = this.getSignature(messageData, privKeys[0]);

        vm.selectFork(polygonFork);

        skip(resultManager.DISPUTE_TIME_PERIOD());

        //incorrect block sent
        vm.expectRevert(ResultManager.IncorrectBlockSent.selector);
        resultManager.setBlock(Structs.Block(block.timestamp, messageData, sig));

        resultManager.setBlock(Structs.Block(timestamp, message, signature));

        //block already set
        vm.expectRevert(ResultManager.BlockAlreadySet.selector);
        resultManager.setBlock(Structs.Block(timestamp, message, signature));
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
