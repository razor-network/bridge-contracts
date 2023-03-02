// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Bridge} from "src/core/Bridge.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {BlameManager} from "../src/core/BlameManager.sol";
import {StakeManager} from "src/core/StakeManager.sol";

// Tests for Blame Manager
contract BlameManagerTest is Utilities {
    using stdStorage for StdStorage;

    address public owner;
    uint256 public deploymentTime;
    mapping(uint32 => uint256) public stake;
    uint256 public contractReserve = 10000e18;
    address public signerAddress;
    uint256[] public privKeys;
    bytes32[] public pubKeys;

    Bridge public bridge;
    BridgeToken public bridgeToken;
    BlameManager public blameManager;
    StakeManager public stakeManager;

    /**
     * General setup which includes deployment of contracts and initializing it
     */
    function setUp() external {
        privKeys.push(43788133087041727893459500607664774196458479752328773334909089843514276704194);

        pubKeys.push(0x1c15e2990e76007fdf2fda604513218ce2e31004348fd374856152e1a026283c);

        owner = vm.addr(1);
        vm.label(owner, "Owner");
        vm.startPrank(owner);

        bridgeToken = new BridgeToken();
        bridge = new Bridge();

        deploymentTime = bridge.firstDynastyCreation();
        blameManager = new BlameManager(deploymentTime);
        stakeManager = new StakeManager(deploymentTime);

        bridge.initialize(address(stakeManager), address(blameManager));
        stakeManager.initialize(address(bridgeToken), address(bridge));
        blameManager.initialize(address(bridge), address(stakeManager));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(bridge));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(blameManager));

        stakeManager.grantRole(bridge.BASE_MODIFIER_ROLE(), address(bridge));
        stakeManager.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));
        blameManager.grantRole(bridge.BASE_MODIFIER_ROLE(), address(bridge));
        bridge.grantRole(bridge.BASE_MODIFIER_ROLE(), address(blameManager));
        bridgeToken.transfer(address(stakeManager), contractReserve);

        vm.stopPrank();
        vm.label(address(bridge), "Bridge");
        vm.label(address(stakeManager), "Stake Manager");
        vm.label(address(blameManager), "Blame Manager");
        vm.label(address(bridgeToken), "Bridge Token");
    }

    /**
     * A validator from active set should be able to attest blame with culprits in an epoch, dynasty.
     * all the culprits must be part of active set.
     */
    function testBlame() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        uint8 blameType = 0;
        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1];
        culprits[1] = activeSet[0];
        bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);

            if (blameManager.hasJumpedDynasty(dynasty)) continue;
            uint32 validatorId = stakeManager.getValidatorId(validators[activeSet[i] - 1]);
            // blameHash should match with blameAttestations attested by validator
            assertEq(_blameHash, blameManager.blameAttestations(validatorId, dynasty, epoch, blameType));
        }

        uint32[] memory _culprits = blameManager.getBlamesPerEpoch(dynasty, epoch, blameType);
        // check that the culprits are set for the current blame
        assert(_culprits.length != 0);

        uint16[4] memory penaltyPoints = blameManager.getPenaltyPoints();
        for (uint8 i = 0; i < _culprits.length; i++) {
            // once threshold is reached, culprits must match with culprits attested in blame
            assertEq(_culprits[i], culprits[i]);
            // checking whether penalty points given to validator
            assertEq(penaltyPoints[blameType], blameManager.blamePointsPerValidator(culprits[i]));
        }
        assertEq(blameManager.blameVotesPerAttestation(dynasty, epoch, _blameHash), blameManager.blameThreshold() + 1);

        assertEq(blameManager.getDynasty(), dynasty + 1);
        assertEq(stakeManager.getDynasty(), dynasty + 1);
        assertEq(bridge.getDynasty(), dynasty + 1);

        assertEq(blameManager.getEpoch(), (dynasty * bridge.dynastyLength()) + 1);
        assertEq(stakeManager.getEpoch(), (dynasty * bridge.dynastyLength()) + 1);
        assertEq(bridge.getEpoch(), (dynasty * bridge.dynastyLength()) + 1);
    }

    /**
     * A validator from active set should be able to attest blame with culprits in an epoch, dynasty.
     * culprits are slashed depending on the unresponsiveSignerSlashPercentage
     */
    function testUnresponsiveSignerSlashing() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        // test unresponsive signer blame and its corresponding slashing percentage
        uint8 blameType = 0;
        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1];
        culprits[1] = activeSet[0];
        bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));

        //make sure the blame type is as expected
        assertEq(blameType, uint8(BlameType.UnresponsiveSigner));

        uint256 culpritOneInitialStake = stakeManager.getStake(culprits[0]);
        uint256 culpritTwoInitialStake = stakeManager.getStake(culprits[1]);
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);

            uint32 validatorId = stakeManager.getValidatorId(validators[activeSet[i] - 1]);
            if (blameManager.hasJumpedDynasty(dynasty)) continue;
            // blameHash should match with blameAttestations attested by validator
            assertEq(_blameHash, blameManager.blameAttestations(validatorId, bridge.getDynasty(), bridge.getEpoch(), blameType));
        }

        uint32[] memory _culprits = blameManager.getBlamesPerEpoch(dynasty, epoch, blameType);

        // check that the culprits are set for the current blame
        assert(_culprits.length != 0);
        for (uint8 i = 0; i < _culprits.length; i++) {
            // once threshold is reached, culprits must match with culprits attested in blame
            assertEq(_culprits[i], culprits[i]);
        }
        assertEq(blameManager.blameVotesPerAttestation(dynasty, epoch, _blameHash), blameManager.blameThreshold() + 1);
        assertEq(
            stakeManager.getStake(_culprits[0]),
            culpritOneInitialStake - culpritOneInitialStake * bridge.unresponsiveSignerSlashPercentage() / bridge.BASE_DENOMINATOR()
        );
        assertEq(
            stakeManager.getStake(_culprits[1]),
            culpritTwoInitialStake - ((culpritTwoInitialStake * bridge.unresponsiveSignerSlashPercentage()) / bridge.BASE_DENOMINATOR())
        );
    }

    /**
     * A validator from active set should be able to attest blame with culprits in an epoch, dynasty.
     * culprits are slashed depending on the invalidSigningSlashPercentage
     */
    function testInvalidSigningSlashing() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

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

        // test invalid signing blame and its corresponding slashing percentage
        uint8 blameType = 3;
        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1];
        culprits[1] = activeSet[0];
        bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));

        //make sure the blame type is as expected
        assertEq(blameType, uint8(BlameType.InvalidSigning));

        uint256 culpritOneInitialStake = stakeManager.getStake(culprits[0]);
        uint256 culpritTwoInitialStake = stakeManager.getStake(culprits[1]);
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);

            uint32 validatorId = stakeManager.getValidatorId(validators[activeSet[i] - 1]);
            if (blameManager.hasJumpedDynasty(dynasty)) continue;
            // blameHash should match with blameAttestations attested by validator
            assertEq(_blameHash, blameManager.blameAttestations(validatorId, bridge.getDynasty(), bridge.getEpoch(), blameType));
        }

        uint32[] memory _culprits = blameManager.getBlamesPerEpoch(dynasty, epoch, blameType);

        // check that the culprits are set for the current blame
        assert(_culprits.length != 0);
        for (uint8 i = 0; i < _culprits.length; i++) {
            // once threshold is reached, culprits must match with culprits attested in blame
            assertEq(_culprits[i], culprits[i]);
        }
        assertEq(blameManager.blameVotesPerAttestation(dynasty, epoch, _blameHash), blameManager.blameThreshold() + 1);
        assertEq(
            stakeManager.getStake(_culprits[0]),
            culpritOneInitialStake - culpritOneInitialStake * bridge.invalidSigningSlashPercentage() / bridge.BASE_DENOMINATOR()
        );
        assertEq(
            stakeManager.getStake(_culprits[1]),
            culpritTwoInitialStake - ((culpritTwoInitialStake * bridge.invalidSigningSlashPercentage()) / bridge.BASE_DENOMINATOR())
        );
    }

    /**
     * A validator from active set should be able to attest blame with culprits in an epoch, dynasty.
     * culprits are not slashed since the blame type is not UnresponsiveSigner or InvalidSigning
     */
    function testBlameWithoutSlashing() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

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

        // test unresponsive node blame and its corresponding slashing percentage
        uint8 blameType = 2;
        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1];
        culprits[1] = activeSet[0];
        bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));

        //make sure the blame type is as expected
        assertEq(blameType, uint8(BlameType.UnresponsiveNode));

        uint256 culpritOneInitialStake = stakeManager.getStake(culprits[0]);
        uint256 culpritTwoInitialStake = stakeManager.getStake(culprits[1]);
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);

            uint32 validatorId = stakeManager.getValidatorId(validators[activeSet[i] - 1]);
            if (blameManager.hasJumpedDynasty(dynasty)) continue;
            // blameHash should match with blameAttestations attested by validator
            assertEq(_blameHash, blameManager.blameAttestations(validatorId, bridge.getDynasty(), bridge.getEpoch(), blameType));
        }

        uint32[] memory _culprits = blameManager.getBlamesPerEpoch(dynasty, epoch, blameType);

        // check that the culprits are set for the current blame
        assert(_culprits.length != 0);
        for (uint8 i = 0; i < _culprits.length; i++) {
            // once threshold is reached, culprits must match with culprits attested in blame
            assertEq(_culprits[i], culprits[i]);
        }
        assertEq(blameManager.blameVotesPerAttestation(dynasty, epoch, _blameHash), activeSet.length);
        assertEq(stakeManager.getStake(_culprits[0]), culpritOneInitialStake);
        assertEq(stakeManager.getStake(_culprits[1]), culpritTwoInitialStake);
    }

    /**
     * Test blame threshold by trying to change the blameThreshold and attesting blames
     * according to the requirements. If blame threshold is not reached, culprits should be empty for current epoch, dynasty.
     */
    function testBlameThreshold() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // cannot change the blame threshold to a value greater than bridge threshold
        vm.startPrank(owner);
        uint32 _invalidThreshold = bridge.getThreshold() + 1;
        vm.expectRevert(BlameManager.InvalidUpdation.selector);
        blameManager.setThreshold(_invalidThreshold);

        blameManager.setThreshold(6);
        vm.stopPrank();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

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

        // cannot change the blame threshold if we are not in ValidatorSelection Mode
        vm.prank(owner);
        vm.expectRevert(BlameManager.IncorrectMode.selector);
        blameManager.setThreshold(5);

        {
            address payable[] memory _validators = validators;
            uint256 _epoch = bridge.getEpoch();
            uint256 _dynasty = bridge.getDynasty();
            uint8 blameType = 1;
            uint32[] memory culprits = new uint32[](2);
            culprits[0] = activeSet[1];
            culprits[1] = activeSet[0];
            bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));

            // only attestBlame with the validators of the activeSet < blameThreshold length (6)
            // only 5 validators have attested blame here
            for (uint8 i = 0; i < blameManager.blameThreshold() - 1; i++) {
                vm.prank(_validators[activeSet[i] - 1]);
                blameManager.attestBlame(blameType, culprits);

                uint32 validatorId = stakeManager.getValidatorId(_validators[activeSet[i] - 1]);
                // blameHash should match with blameAttestations attested by validator
                assertEq(_blameHash, blameManager.blameAttestations(validatorId, _dynasty, _epoch, blameType));
            }

            // check that the culprits are NOT set for the current blame, since the threshold was not reached
            uint32[] memory _culprits = blameManager.getBlamesPerEpoch(_dynasty, _epoch, blameType);
            assertEq(_culprits.length, 0);

            // attest blame with the rest of the validators in the active set
            uint8 _blameThreshold = uint8(blameManager.blameThreshold());
            for (uint8 i = _blameThreshold - 1; i <= _blameThreshold; i++) {
                vm.prank(_validators[activeSet[i] - 1]);
                blameManager.attestBlame(blameType, culprits);

                uint32 validatorId = stakeManager.getValidatorId(_validators[activeSet[i] - 1]);
                // blameHash should match with blameAttestations attested by validator
                assertEq(_blameHash, blameManager.blameAttestations(validatorId, _dynasty, bridge.getEpoch(), blameType));
            }

            _culprits = blameManager.getBlamesPerEpoch(_dynasty, _epoch, blameType);
            assert(_culprits.length != 0);

            for (uint8 i = 0; i < _culprits.length; i++) {
                // once threshold is reached, culprits must match with culprits attested in blame
                assertEq(_culprits[i], culprits[i]);
            }
            assertEq(blameManager.blameVotesPerAttestation(_dynasty, _epoch, _blameHash), 7);
        }
    }

    function testNegativeBlameMode() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        uint32[] memory culprits = new uint32[](1);
        culprits[0] = activeSet[0];

        vm.startPrank(validators[activeSet[0] - 1]);
        vm.expectRevert(abi.encodeWithSelector(BlameManager.IncorrectBlameTypeMode.selector, bridge.getMode()));
        blameManager.attestBlame(1, culprits);

        vm.expectRevert(abi.encodeWithSelector(BlameManager.IncorrectBlameTypeMode.selector, bridge.getMode()));
        blameManager.attestBlame(2, culprits);

        vm.expectRevert(abi.encodeWithSelector(BlameManager.IncorrectBlameTypeMode.selector, bridge.getMode()));
        blameManager.attestBlame(3, culprits);
        vm.stopPrank();

        _attestSigner(validators, signerAddress, activeSet);

        // admin confirms the signerAddress of the 1st dynasty since there is no signerAddress in the previous dynasty
        vm.startPrank(owner);
        bytes memory sig = this.getConfirmTransferSignature(epoch, signerAddress, 1);
        bridge.confirmSigner(sig);
        vm.stopPrank();

        this.skipEpoch(1, bridge.epochLength());

        vm.startPrank(validators[activeSet[0] - 1]);
        vm.expectRevert(abi.encodeWithSelector(BlameManager.IncorrectBlameTypeMode.selector, bridge.getMode()));
        blameManager.attestBlame(0, culprits);
        vm.stopPrank();
    }

    function testMaxPenaltyPoints() external {
        address payable[] memory validators = this.createValidators(10);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        // perform validator selection
        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        uint8 blameType = 0;
        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1];
        culprits[1] = activeSet[0];
        bytes32 _blameHash = keccak256(abi.encode(blameType, culprits));
        for (uint8 i = 0; i < activeSet.length; i++) {
            vm.prank(validators[activeSet[i] - 1]);
            blameManager.attestBlame(blameType, culprits);

            if (blameManager.hasJumpedDynasty(dynasty)) continue;

            uint32 validatorId = stakeManager.getValidatorId(validators[activeSet[i] - 1]);
            // blameHash should match with blameAttestations attested by validator
            assertEq(_blameHash, blameManager.blameAttestations(validatorId, dynasty, epoch, blameType));
        }

        for (uint8 i = 0; i < culprits.length; i++) {
            // checking whether penalty points given to validator
            assertEq(blameManager.MAX_POINTS(), blameManager.blamePointsPerValidator(culprits[i]));
        }
    }

    /**
     * Negative tests for attest blame
     */
    function testNegativeBlame() external {
        address payable[] memory validators = this.createValidators(11);
        uint32 biggestValidatorId = _mockValidatorStake(validators);

        uint256 epoch = bridge.getEpoch();
        uint256 dynasty = bridge.getDynasty();

        bytes32 salt = keccak256(abi.encodePacked(dynasty, bridge.getActiveSetPerDynasty(dynasty - 1)));
        uint32[] memory activeSet = _validatorSelection(validators, biggestValidatorId, salt);

        address payable validatorNotSelected;
        for (uint32 i = 0; i < validators.length; i++) {
            uint32 validatorId = stakeManager.getValidatorId(validators[i]);
            if (!bridge.getIsValidatorSelectedPerDynasty(validatorId, dynasty)) {
                validatorNotSelected = validators[i];
                break;
            }
        }

        this.skipEpoch(
            (bridge.validatorSelectionTimelimit() - (epoch - ((dynasty - 1) * bridge.dynastyLength()))) + 1, bridge.epochLength()
        );
        epoch = bridge.getEpoch();

        uint32[] memory culprits = new uint32[](2);
        culprits[0] = activeSet[1]; // 8
        culprits[1] = activeSet[0]; // 7

        // culprits should be in ascending order current culprits are set as [8, 7]
        // expected order should be in asc order ie, [7, 8]
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(BlameManager.CulpritsOrder.selector);
        blameManager.attestBlame(0, culprits);

        // should not be able to attest blame for culprit which is not selected in active set.
        vm.startPrank(validatorNotSelected);
        vm.expectRevert(
            abi.encodeWithSelector(
                BlameManager.ValidatorNotSelected.selector, stakeManager.getValidatorId(validatorNotSelected), bridge.getDynasty()
            )
        );
        blameManager.attestBlame(0, culprits);
        vm.stopPrank();

        // type of blame should be from BlameType
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(BlameManager.InvalidBlameType.selector);
        blameManager.attestBlame(4, culprits);

        // non validator should not be able attest blame
        vm.prank(owner);
        vm.expectRevert(BlameManager.InvalidValidator.selector);
        blameManager.attestBlame(0, culprits);

        // should not be able blame without culprits
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(BlameManager.NoCulprits.selector);
        blameManager.attestBlame(0, new uint32[](0));

        // culprits should be valid validators IDs
        culprits[0] = 0;
        vm.prank(validators[activeSet[0] - 1]);
        vm.expectRevert(BlameManager.InvalidCulprits.selector);
        blameManager.attestBlame(0, culprits);
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
     * internal function to transfer random value of bridge tokens from bridgeToken directly to validators with a min of minStake
     * to stake those tokens, and return the biggest validator ID
     */
    function _mockValidatorStake(address payable[] memory _validators) internal returns (uint32) {
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
