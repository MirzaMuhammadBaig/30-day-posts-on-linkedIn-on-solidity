// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableBridge {
    event BridgeRequest(address indexed sender, uint128 amount);

    mapping(address => uint128) public pending;

    function bridge(uint256 amount) external payable {
        require(msg.value == amount, "Wrong ETH");
        uint128 bridged = uint128(amount); // silent truncation if amount > 2^128-1
        pending[msg.sender] += bridged;
        emit BridgeRequest(msg.sender, bridged);
    }
}

library SafeCast {
    error CastOverflow(uint256 value, string targetType);

    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max)
            revert CastOverflow(value, "uint128");
        return uint128(value);
    }

    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max)
            revert CastOverflow(value, "uint64");
        return uint64(value);
    }

    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max)
            revert CastOverflow(value, "uint32");
        return uint32(value);
    }
}

contract SecureBridge {
    using SafeCast for uint256;

    event BridgeRequest(address indexed sender, uint128 amount);

    mapping(address => uint128) public pending;

    function bridge(uint256 amount) external payable {
        require(msg.value == amount, "Wrong ETH");
        uint128 bridged = amount.toUint128(); // reverts on overflow instead of truncating
        pending[msg.sender] += bridged;
        emit BridgeRequest(msg.sender, bridged);
    }
}

contract HiddenDowncasts {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    uint32 public lastUpdate = uint32(block.timestamp); // silently wrong after year 2106

    mapping(address => uint96) public balances; // wraps if amount > ~79 billion tokens

    function unsafeCredit(address to, uint256 amount) external onlyOwner {
        balances[to] += uint96(amount); // truncates silently if amount > 2^96-1
    }

    uint32 public safeTimestamp;

    function updateTimestamp() external {
        require(block.timestamp <= type(uint32).max, "Timestamp overflow");
        safeTimestamp = uint32(block.timestamp);
    }
}
