// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "src/library/Structs.sol";
import "./utils/Utilities.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {Bridge} from "src/core/Bridge.sol";
import {BridgeToken} from "../src/token/BridgeToken.sol";
import {StakeManager} from "src/core/StakeManager.sol";
import {BlameManager} from "src/core/BlameManager.sol";

// Tests for Stake Manager
contract StakingTest is Utilities {
    using stdStorage for StdStorage;

    address public owner;
    address payable public validator1;
    address payable public validator2;
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

        uint256 deploymentTime = bridge.firstDynastyCreation();
        stakeManager = new StakeManager(deploymentTime);
        blameManager = new BlameManager(deploymentTime);

        bridge.initialize(address(stakeManager), address(blameManager));
        stakeManager.initialize(address(bridgeToken), address(bridge));
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), address(bridge));

        bridgeToken.transfer(address(stakeManager), contractReserve);
        vm.stopPrank();

        vm.label(address(bridge), "Bridge");
        vm.label(address(stakeManager), "Stake Manager");
        vm.label(address(bridgeToken), "Bridge Token");
        vm.label(address(blameManager), "Blame Manager");
    }

    /**
     * STAKE, UNSTAKE, WITHDRAW TESTS
     */

    /**
     * A user should be able to stake seamlessly if they want to be a validator on the network as long as
     * their stake is greater than or equal to minStake
     */
    function testStake() public {
        vm.startPrank(owner);
        bridgeToken.transfer(validator1, bridge.minStake());
        vm.stopPrank();

        vm.startPrank(validator1);
        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());

        uint32 validatorId1 = stakeManager.getValidatorId(validator1);
        Structs.Validator memory validator = stakeManager.getValidator(validatorId1);
        assertEq(validator.id, 1);
        assertEq(validator.stake, bridge.minStake());
        assertEq(validator._validatorAddress, validator1);
        assertEq(bridgeToken.balanceOf(validator1), 0);
        assertEq(bridgeToken.balanceOf(address(stakeManager)), contractReserve + bridge.minStake());
    }

    /**
     * A validator should be able to start the unstaking process by calling the unstake function
     * to signal to the network they are want to withdraw their staked funds
     */
    function testUnstake() public {
        uint256 epoch = bridge.getEpoch();
        vm.startPrank(owner);
        bridgeToken.transfer(validator1, bridge.minStake());
        vm.stopPrank();

        vm.startPrank(validator1);
        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        stakeManager.unstake();

        // an withdraw lock is created after unstake where the validator can withdraw their funds only after the
        // expiry of the lock
        uint256 unlockAfter = stakeManager.withdrawAfterPerValidator(validator1);
        uint256 dynasty = bridge.getDynasty();

        assertEq(unlockAfter, dynasty + bridge.withdrawLockPeriod());
    }

    /**
     * Once a validator had called the unstake function, the validator should be able to withdraw their funds
     * sucessfully after their lock has expired
     */
    function testWithdraw() public {
        uint256 epoch = bridge.getEpoch();
        vm.startPrank(owner);
        bridgeToken.transfer(validator1, bridge.minStake());
        vm.stopPrank();

        vm.startPrank(validator1);
        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());

        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        // validator calls unstake function to signal to the network it wants to unstake
        stakeManager.unstake();
        epoch = bridge.getEpoch();

        // waiting for the lock period to end
        this.skipDynasty(1, ((epoch - 1) % bridge.dynastyLength()), bridge.dynastyLength(), bridge.epochLength());

        //validator withdraws after lock experies
        stakeManager.withdraw();

        // lock is reset to zero once funds are withdrawn
        uint256 unlockAfter = stakeManager.withdrawAfterPerValidator(validator1);
        uint32 validatorId1 = stakeManager.getValidatorId(validator1);
        uint256 validator1Stake = stakeManager.getStake(validatorId1);

        assertEq(validator1Stake, 0);
        assertEq(unlockAfter, 0);
        assertEq(bridgeToken.balanceOf(validator1), bridge.minStake());
        assertEq(bridgeToken.balanceOf(address(stakeManager)), contractReserve);
    }

    /**
     * Negative test cases for stake function
     */
    function testNegativeStake() public {
        vm.startPrank(owner);
        bridgeToken.transfer(validator1, bridge.minStake());
        vm.stopPrank();

        //not sending right amount of stake
        vm.startPrank(validator1);
        uint256 minStake = bridge.minStake();
        bridgeToken.approve(address(stakeManager), minStake);
        vm.expectRevert(StakeManager.LessThanMinStake.selector);
        stakeManager.stake(minStake - 1e18);
        vm.stopPrank();

        vm.startPrank(validator1);
        stakeManager.stake(minStake);

        // validator cant stake again
        vm.expectRevert(abi.encodeWithSelector(StakeManager.AlreadyValidator.selector, stakeManager.getValidatorId(validator1)));
        stakeManager.stake(minStake);
    }

    /**
     * Negative test cases for unstake function
     */
    function testNegativeUnstake() public {
        vm.startPrank(owner);
        bridgeToken.transfer(validator1, bridge.minStake());
        vm.stopPrank();

        vm.startPrank(validator1);
        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());
        vm.stopPrank();

        //only validators can unstake
        vm.startPrank(validator2);
        vm.expectRevert(StakeManager.InvalidValidator.selector);
        stakeManager.unstake();
        vm.stopPrank();

        //can't unstake without completing the previous unstake process
        vm.startPrank(validator1);
        stakeManager.unstake();
        uint256 unlockAfter = stakeManager.withdrawAfterPerValidator(validator1);
        vm.expectRevert(abi.encodeWithSelector(StakeManager.ExistingWithdrawLock.selector, unlockAfter));
        stakeManager.unstake();
    }

    /**
     * Basic Negative test cases for withdraw function
     */
    function testNegativeWithdraw() public {
        vm.startPrank(owner);
        bridgeToken.transfer(validator1, bridge.minStake());
        vm.stopPrank();

        vm.startPrank(validator1);

        bridgeToken.approve(address(stakeManager), bridge.minStake());
        stakeManager.stake(bridge.minStake());
        // should not be able to withdraw if no withdraw lock is in place
        vm.expectRevert(StakeManager.NoWithdrawLock.selector);
        stakeManager.withdraw();

        stakeManager.unstake();

        // should not be able to withdraw if lock has not expired
        vm.expectRevert(StakeManager.InvalidWithdrawRequest.selector);
        stakeManager.withdraw();

        vm.stopPrank();

        vm.startPrank(validator2);
        // only a validator should be able withdraw
        vm.expectRevert(StakeManager.InvalidValidator.selector);
        stakeManager.withdraw();

        vm.stopPrank();
    }

    /**
     * These testcases focus on the participation of a validator during a withdraw lock
     * Ideally, a validator should not be able to withdraw if they have taken part in validator selection
     * can only withdraw if they are validator selection mode
     */
    function testNegativeWithdrawSigner() public {
        signerAddress = this.getAddress(bytes.concat(pubKeys[0]));
        address payable[] memory validators = this.createValidators(30);
        uint32 biggestValidatorId = _mockValidatorStake(validators);
        vm.label(signerAddress, "Signer Address 1");

        vm.prank(validators[0]);
        stakeManager.unstake();

        uint256 dynasty = bridge.getDynasty();
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
        }

        // should not be able to withdraw since taken part in validator selection
        vm.prank(validators[0]);
        vm.expectRevert(StakeManager.AlreadyParticipated.selector);
        stakeManager.withdraw();

        // should not be able to withdraw since current mode is not validator selection
        this.skipEpoch(bridge.validatorSelectionTimelimit(), bridge.epochLength());
        vm.prank(validators[0]);
        vm.expectRevert(StakeManager.IncorrectMode.selector);
        stakeManager.withdraw();
    }

    /**
     * A testcase to make sure that a slashing mechanism works as intended
     */
    function testValidatorSlashed() public {
        address payable[] memory validators = this.createValidators(100);
        _mockValidatorStake(validators);
        uint32 validatorId = stakeManager.getValidatorId(validators[0]);
        Structs.Validator memory validator = stakeManager.getValidator(validatorId);

        vm.startPrank(owner);
        //grant STAKE_MODIFIER_ROLE to owner
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), owner);
        uint32[] memory ids = new uint32[](1);
        ids[0] = validatorId;
        stakeManager.slashValidators(ids, bridge.slashPercentage());
        uint256 validatorSlashedStake = stakeManager.getStake(validatorId);
        uint256 slashedAmount = (validator.stake * bridge.slashPercentage()) / bridge.BASE_DENOMINATOR();
        assertEq(validatorSlashedStake, validator.stake - slashedAmount);
    }

    /**
     * Basic Negative test cases for slash function
     */
    function testNegativeValidatorSlashed() public {
        address payable[] memory validators = this.createValidators(100);
        _mockValidatorStake(validators);
        uint32 validatorId = stakeManager.getValidatorId(validators[0]);
        uint32[] memory ids = new uint32[](1);
        ids[0] = validatorId;
        uint32 slashPercentage = bridge.slashPercentage();
        // Structs.Validator memory validator = bridge.getValidator(validatorId);

        //Only address with STAKE_MODIFIER_ROLE allowed to call slashValidators()
        vm.startPrank(validators[0]);

        vm.expectRevert(
            "AccessControl: account 0x3a224765641d6ebb6cd9d3c6d1516837448581b1 is missing role 0xdbaaaff2c3744aa215ebd99971829e1c1b728703a0bf252f96685d29011fc804"
        );
        stakeManager.slashValidators(ids, slashPercentage);
        vm.stopPrank();

        //Slash non-existent validator
        vm.startPrank(owner);
        //grant STAKE_MODIFIER_ROLE to owner
        stakeManager.grantRole(bridge.STAKE_MODIFIER_ROLE(), owner);
        ids[0] = 101;
        vm.expectRevert(StakeManager.ValidatorDoesNotExist.selector);
        stakeManager.slashValidators(ids, slashPercentage);
        ids[0] = 0;
        vm.expectRevert(StakeManager.InvalidValidator.selector);
        stakeManager.slashValidators(ids, slashPercentage);
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
