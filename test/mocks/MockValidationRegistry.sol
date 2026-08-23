// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../../contracts/IValidationRegistry.sol";

/// @notice Minimal in-memory stand-in for the real ERC-8004 Validation
///         Registry, matching the actual validationRequest/validationResponse
///         signatures from erc-8004/erc-8004-contracts. Skips the Identity
///         Registry ownership check that the real contract performs on
///         validationRequest — tests call it directly as if already authorized.
///         Do NOT deploy this to a real chain — it is a test double only.
contract MockValidationRegistry is IValidationRegistry {
    struct Status {
        address validatorAddress;
        uint256 agentId;
        uint8 response;
        bytes32 responseHash;
        string tag;
        uint256 lastUpdate;
        bool hasResponse;
    }

    mapping(bytes32 => Status) public statuses;

    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external override {
        require(statuses[requestHash].validatorAddress == address(0), "exists");
        statuses[requestHash] = Status(validatorAddress, agentId, 0, bytes32(0), "", block.timestamp, false);
        emit ValidationRequest(validatorAddress, agentId, requestURI, requestHash);
    }

    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external override {
        Status storage s = statuses[requestHash];
        require(s.validatorAddress != address(0), "unknown");
        require(msg.sender == s.validatorAddress, "not validator");
        s.response = response;
        s.responseHash = responseHash;
        s.tag = tag;
        s.lastUpdate = block.timestamp;
        s.hasResponse = true;
        emit ValidationResponse(s.validatorAddress, s.agentId, requestHash, response, responseURI, responseHash, tag);
    }

    function getValidationStatus(bytes32 requestHash)
        external
        view
        override
        returns (address, uint256, uint8, bytes32, string memory, uint256)
    {
        Status memory s = statuses[requestHash];
        require(s.validatorAddress != address(0), "unknown");
        return (s.validatorAddress, s.agentId, s.response, s.responseHash, s.tag, s.lastUpdate);
    }
}

