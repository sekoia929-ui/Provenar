// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Interface matching the real ERC-8004 ValidationRegistryUpgradeable
///         contract (erc-8004/erc-8004-contracts), not the spec-text guess
///         this file originally contained. Confirmed against the actual
///         Solidity source on 2026-08-23.
/// @dev Key departure from a naive read of the EIP: the AGENT (its owner or
///      an approved operator on the Identity Registry) calls
///      validationRequest, naming the validator's address. The validator
///      then calls validationResponse. Provenar acts as the validator, so
///      Provenar never calls validationRequest itself — it only ever calls
///      validationResponse once an agent's request has named it.
interface IValidationRegistry {
    event ValidationRequest(
        address indexed validatorAddress,
        uint256 indexed agentId,
        string requestURI,
        bytes32 indexed requestHash
    );

    event ValidationResponse(
        address indexed validatorAddress,
        uint256 indexed agentId,
        bytes32 indexed requestHash,
        uint8 response, // 0..100
        string responseURI,
        bytes32 responseHash,
        string tag
    );

    /// @dev Called by the agent's owner/approved operator, NOT by Provenar.
    function validationRequest(
        address validatorAddress,
        uint256 agentId,
        string calldata requestURI,
        bytes32 requestHash
    ) external;

    /// @dev Called by Provenar, since Provenar is the named validatorAddress.
    function validationResponse(
        bytes32 requestHash,
        uint8 response,
        string calldata responseURI,
        bytes32 responseHash,
        string calldata tag
    ) external;

    function getValidationStatus(bytes32 requestHash)
        external
        view
        returns (
            address validatorAddress,
            uint256 agentId,
            uint8 response,
            bytes32 responseHash,
            string memory tag,
            uint256 lastUpdate
        );
}

