// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.15;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract Parameters is AccessControl {
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

    /// @notice epoch length in seconds
    uint256 public epochLength = 1200;

    /// @notice length of a dynasty in epochs
    uint256 public dynastyLength = 100;

    /// @notice minimum stake required to be a validator
    uint256 public minStake = 1000 * (10 ** 18);

    /// @notice block reward given to validator for each finalized block
    uint256 public blockReward = 10 * (10 ** 18);

    /// @notice number of dynasties a validator will be jailed
    uint256 public numJailDynasty = 10;

    /// @notice number of epochs in which a validator should be selected
    uint8 public validatorSelectionTimelimit = 2;

    /// @notice number of epochs stake is locked before allowing withdrawal
    uint16 public withdrawLockPeriod = 1;

    /// @notice maximum number of iterations for electing proposer
    uint32 public maxIteration = 100_000;

    /// @notice maximum number of requestIds that can be fulfilled per request
    uint16 public maxRequests = 20;

    /// @notice percentage by which unresponsive signer blamed validators stake is penalised
    uint32 public unresponsiveSignerSlashPercentage = 200_000; // 2%

    /// @notice percentage by which invalid signer blamed validators stake is penalised
    uint32 public invalidSigningSlashPercentage = 500_000; // 5%

    /// @notice percentage by which validators stake is penalised as a default
    uint32 public slashPercentage = 1_000_000; // 10%

    uint32 public maxChurnPercentage = 3_300_000; // 33%

    //keccak256(STAKE_MODIFIER_ROLE)
    bytes32 public constant STAKE_MODIFIER_ROLE = 0xdbaaaff2c3744aa215ebd99971829e1c1b728703a0bf252f96685d29011fc804;
    // slither-disable-next-line too-many-digits
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;

    /// @notice denominator used to calculate stake amount to be burned
    uint32 public constant BASE_DENOMINATOR = 10_000_000; // 100%

    // kecckeccak256(JAILER_ROLE)
    bytes32 public constant JAILER_ROLE = 0x3a612eb9ead461499ef30313166f3e259cef70ffda582b57c4dedbb097274d99;

    // keccak256(BASE_MODIFIER_ROLE)
    bytes32 public constant BASE_MODIFIER_ROLE = 0x51053cf7af63fc6b96ba407869e545d500b12200989281339d9fd33087b2f3ed;

    // keccak256(SET_DISPUTED_ROLE)
    bytes32 public constant SET_DISPUTED_ROLE = 0x04b904adcd08afc352a93338566c84d3fed7a79d936de391ea8821f85f463414;

    // keccak256(PENALTY_RESETTER_ROLE)
    bytes32 public constant PENALTY_RESETTER_ROLE = 0x6a7d1deabc49894eb19fefd85dca1d5a58ab4fdce235be0866cf1a6136a7648f;

    uint16 public constant MAX_POINTS = 5;

    uint16 public constant THRESHOLD_POINTS = 3;

    /// @notice sets max iteration for electing a proposer
    function setMaxIteration(uint32 _maxIteration) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxIteration = _maxIteration;
    }

    /// @notice sets time limit in epochs allowing for validator selection
    function setValidatorSelectionTimelimit(uint8 _validatorSelectionTimelimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        validatorSelectionTimelimit = _validatorSelectionTimelimit;
    }

    /// @notice sets block reward validator receives for each finalized block
    function setBlockReward(uint256 _blockReward) external onlyRole(DEFAULT_ADMIN_ROLE) {
        blockReward = _blockReward;
    }

    /// @notice sets minimum stake required to be a validator
    function setMinStake(uint256 _minStake) external onlyRole(DEFAULT_ADMIN_ROLE) {
        minStake = _minStake;
    }

    /// @notice sets withdraw lock period in epochs
    function setWithdrawLockPeriod(uint16 _withdrawLockPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
        withdrawLockPeriod = _withdrawLockPeriod;
    }

    /// @notice sets dynasty length in epochs
    function setDynastyLength(uint256 _dynastyLength) external onlyRole(DEFAULT_ADMIN_ROLE) {
        dynastyLength = _dynastyLength;
    }

    /// @notice sets epoch length in seconds
    function setEpochLength(uint256 _epochLength) external onlyRole(DEFAULT_ADMIN_ROLE) {
        epochLength = _epochLength;
    }

    /// @notice sets maximum requestIds that can be fulfilled per request
    function setMaxRequests(uint16 _maxRequests) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxRequests = _maxRequests;
    }

    /// @notice sets slash percentage by which validators stake will be penalised
    function setMaxChurnPercentage(uint32 _maxChurnPercentage) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxChurnPercentage = _maxChurnPercentage;
    }

    /// @notice sets slash percentage by which validators stake will be penalised for unresponsive signer blame
    function setUnresponsiveSignerSlashPercentage(uint32 _unresponsiveSignerSlashPercentage) external onlyRole(DEFAULT_ADMIN_ROLE) {
        unresponsiveSignerSlashPercentage = _unresponsiveSignerSlashPercentage;
    }

    /// @notice sets slash percentage by which validators stake will be penalised for invalid signing blame
    function setInvalidSigningSlashPercentage(uint32 _invalidSigningSlashPercentage) external onlyRole(DEFAULT_ADMIN_ROLE) {
        invalidSigningSlashPercentage = _invalidSigningSlashPercentage;
    }

    /// @notice sets slash percentage by which validators stake will be penalised
    function setSlashPercentage(uint32 _slashPercentage) external onlyRole(DEFAULT_ADMIN_ROLE) {
        slashPercentage = _slashPercentage;
    }

    /// @notice sets number of dynasties a validator will be jailed for
    function setNumJailDynasty(uint256 _numJailDynasty) external onlyRole(DEFAULT_ADMIN_ROLE) {
        numJailDynasty = _numJailDynasty;
    }
}
