// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title tGt Random Reward Distributor (v2-compatible, Secure Rolling Pool)
 * @notice
 *  - Uses off-chain Merkle trees to allocate rewards per cycle
 *  - Authorized rootSetter (e.g., multisig / DAO) sets Merkle roots (once per cycle)
 *  - Each cycle has a limited claim window (cycle end + 60 days)
 *  - Unclaimed tokens remain in the pool and can be reallocated in future cycles
 *  - Planned for 10 years, but continues AFTER 10 years until remainingPool() <= MIN_REMAINING
 *
 * IMPORTANT (Merkle):
 *  - Leaf format is: keccak256(abi.encode(account, amount))
 *  - Your off-chain Merkle generator MUST use the exact same leaf format.
 */
contract tGtRandomDistributorV2 is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // -----------------------------------------------------------------------
    // Immutable Configuration
    // -----------------------------------------------------------------------

    IERC20  public immutable rewardToken;     // tGt v2 token address
    address public immutable rootSetter;      // Authorized Merkle root setter

    uint256 public immutable totalPool;       // Logical total allocated to this program
    uint256 public immutable cycleDuration;   // Duration of each cycle (e.g., 60 days)
    uint256 public immutable startTime;       // Program start timestamp

    // Planned program duration: 10 years (does NOT stop automatically)
    uint256 public constant PROGRAM_DURATION = 365 days * 10;

    // Claim window after cycle end
    uint256 public constant CLAIM_WINDOW = 60 days;

    // Root can be set during the cycle or up to this window after cycle end
    uint256 public constant ROOT_SETTING_WINDOW = 14 days;

    // Program continues until remainingPool() <= MIN_REMAINING
    uint256 public constant MIN_REMAINING = 50_000 * 1e18;

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    // cycle => Merkle root
    mapping(uint256 => bytes32) public merkleRoots;

    // cycle => user => claimed?
    mapping(uint256 => mapping(address => bool)) public claimed;

    // cycle => total claimed in that cycle (analytics)
    mapping(uint256 => uint256) public claimedInCycle;

    // total claimed across all cycles
    uint256 public totalClaimed;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    event MerkleRootSet(uint256 indexed cycle, bytes32 merkleRoot, address indexed setter);
    event Claimed(uint256 indexed cycle, address indexed account, uint256 amount);

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor(
        address _rewardToken,
        address _rootSetter,
        uint256 _startTime,
        uint256 _cycleDuration,
        uint256 _totalPool
    ) {
        require(_rewardToken != address(0), "Invalid token");
        require(_rootSetter != address(0), "Invalid rootSetter");
        require(_startTime > block.timestamp, "Start must be future");
        require(_cycleDuration > 0, "Invalid cycleDuration");
        require(_totalPool > MIN_REMAINING, "Pool <= MIN_REMAINING");

        rewardToken = IERC20(_rewardToken);
        rootSetter = _rootSetter;
        startTime = _startTime;
        cycleDuration = _cycleDuration;
        totalPool = _totalPool;
    }

    // -----------------------------------------------------------------------
    // View Functions
    // -----------------------------------------------------------------------

    function currentCycle() public view returns (uint256) {
        if (block.timestamp < startTime) return 0;
        return (block.timestamp - startTime) / cycleDuration;
    }

    function cycleStartTime(uint256 cycle) public view returns (uint256) {
        return startTime + cycle * cycleDuration;
    }

    function cycleEndTime(uint256 cycle) public view returns (uint256) {
        return startTime + (cycle + 1) * cycleDuration;
    }

    function plannedEndTime() external view returns (uint256) {
        return startTime + PROGRAM_DURATION;
    }

    function remainingPool() public view returns (uint256) {
        if (totalClaimed >= totalPool) return 0;
        return totalPool - totalClaimed;
    }

    function remainingDistributable() public view returns (uint256) {
        uint256 remaining = remainingPool();
        if (remaining <= MIN_REMAINING) return 0;
        return remaining - MIN_REMAINING;
    }

    function contractBalance() external view returns (uint256) {
        return rewardToken.balanceOf(address(this));
    }

    function isProgramFinished() external view returns (bool) {
        return remainingDistributable() == 0;
    }

    function hasClaimed(uint256 cycle, address account) external view returns (bool) {
        return claimed[cycle][account];
    }

    // -----------------------------------------------------------------------
    // Merkle Root Management
    // -----------------------------------------------------------------------

    function setMerkleRoot(uint256 cycle, bytes32 merkleRoot) external {
        require(msg.sender == rootSetter, "Only rootSetter");
        require(merkleRoot != bytes32(0), "Empty root");
        require(merkleRoots[cycle] == bytes32(0), "Root already set");

        uint256 cStart = cycleStartTime(cycle);
        uint256 cEnd   = cycleEndTime(cycle);

        require(block.timestamp >= cStart, "Cycle not started");
        require(block.timestamp <= cEnd + ROOT_SETTING_WINDOW, "Root window closed");

        merkleRoots[cycle] = merkleRoot;
        emit MerkleRootSet(cycle, merkleRoot, msg.sender);
    }

    // -----------------------------------------------------------------------
    // Claim
    // -----------------------------------------------------------------------

    function claim(
        uint256 cycle,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external nonReentrant {
        require(amount > 0, "Zero amount");
        require(!claimed[cycle][msg.sender], "Already claimed");

        bytes32 root = merkleRoots[cycle];
        require(root != bytes32(0), "Root not set");

        // Claim must be within window after cycle end
        require(block.timestamp <= cycleEndTime(cycle) + CLAIM_WINDOW, "Claim closed");

        // Global program must still be distributable
        uint256 distributable = remainingDistributable();
        require(distributable > 0, "Program finished");
        require(amount <= distributable, "Exceeds distributable");

        // Merkle verification (v2-safe leaf format)
        // leaf = keccak256(abi.encode(account, amount))
        bytes32 leaf = keccak256(abi.encode(msg.sender, amount));
        require(MerkleProof.verifyCalldata(merkleProof, root, leaf), "Bad proof");

        // Accounting ceiling
        uint256 newTotalClaimed = totalClaimed + amount;
        require(newTotalClaimed <= totalPool, "Exceeds total pool");

        // Optional but safer: ensure contract holds enough tokens right now
        require(rewardToken.balanceOf(address(this)) >= amount, "Insufficient balance");

        // Effects
        claimed[cycle][msg.sender] = true;
        claimedInCycle[cycle] += amount;
        totalClaimed = newTotalClaimed;

        // Interaction (SafeERC20 for broad ERC20 compatibility)
        rewardToken.safeTransfer(msg.sender, amount);

        emit Claimed(cycle, msg.sender, amount);
    }
}
