// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../contracts/IValidationRegistry.sol";

/// @notice Minimal in-memory stand-in for the real ERC-8004 Validation
///         Registry, used only for local Foundry tests. Do NOT deploy this
///         to a real chain — it is not the standard, just a test double.
contract MockValidationRegistry is IValidationRegistry {
    struct Request {
        uint256 agentId;
        address requester;
        bool responded;
    }

    struct Response {
        uint8 result;
        bytes32 evidenceHash;
        string evidenceURI;
        address validator;
    }

    mapping(bytes32 => Request) public requests;
    mapping(bytes32 => Response) public responses;

    function requestValidation(
        uint256 agentId,
        bytes32 requestHash,
        string calldata dataURI
    ) external override {
        requests[requestHash] = Request({agentId: agentId, requester: msg.sender, responded: false});
        emit ValidationRequested(requestHash, agentId, msg.sender);
    }

    function respondValidation(
        bytes32 requestHash,
        uint256 agentId,
        uint8 result,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external override {
        require(requests[requestHash].requester != address(0), "no such request");
        require(!requests[requestHash].responded, "already responded");
        requests[requestHash].responded = true;
        responses[requestHash] = Response(result, evidenceHash, evidenceURI, msg.sender);
        emit ValidationResponded(requestHash, agentId, msg.sender, result, evidenceHash, evidenceURI);
    }
}
