// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal interface for the ERC-8004 Validation Registry.
/// @dev Mirrors the reference registry: validators post pass/fail results
///      against a (agentId, requestHash) pair. Exact selector names should
///      be confirmed against the deployed registry address on the target
///      chain before mainnet use — this is written from the public spec,
///      not a copied ABI.
interface IValidationRegistry {
    event ValidationRequested(
        bytes32 indexed requestHash,
        uint256 indexed agentId,
        address indexed requester
    );

    event ValidationResponded(
        bytes32 indexed requestHash,
        uint256 indexed agentId,
        address indexed validator,
        uint8 result, // 0 = fail, 1 = pass, 2 = degraded/partial
        bytes32 evidenceHash,
        string evidenceURI
    );

    function requestValidation(
        uint256 agentId,
        bytes32 requestHash,
        string calldata dataURI
    ) external;

    function respondValidation(
        bytes32 requestHash,
        uint256 agentId,
        uint8 result,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external;
}
