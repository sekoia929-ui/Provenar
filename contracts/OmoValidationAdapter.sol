// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IValidationRegistry.sol";

/// @title OmoValidationAdapter
/// @notice Bridges omo's precommit/seal/reveal pattern into the ERC-8004
///         Validation Registry. Two on-chain moments per decision:
///           1. seal()   — publish only the hash of a not-yet-executed
///                         agent decision, before any action is taken.
///           2. reveal() — open the preimage, and forward a pass/fail
///                         validation result to the registry so any other
///                         agent or marketplace can query it via the
///                         standard interface instead of a bespoke API.
/// @dev This contract deliberately holds no funds and has no trading
///      authority — it is a proof/attestation layer only, same separation
///      of concerns as omo's burner commit key vs. trading key.
contract OmoValidationAdapter {
    struct Commitment {
        bytes32 hash;       // sha256(canonical decision json + nonce)
        uint256 agentId;    // ERC-8004 Identity Registry token id
        uint64  sealedAt;   // block.timestamp at seal()
        bool    revealed;
    }

    IValidationRegistry public immutable registry;
    address public immutable operator; // burner key, memo-only equivalent

    mapping(bytes32 => Commitment) public commitments; // requestHash => Commitment

    event Sealed(bytes32 indexed requestHash, uint256 indexed agentId, uint64 sealedAt);
    event Revealed(bytes32 indexed requestHash, uint256 indexed agentId, uint8 result);

    error NotOperator();
    error AlreadySealed();
    error UnknownCommitment();
    error AlreadyRevealed();
    error HashMismatch();

    modifier onlyOperator() {
        if (msg.sender != operator) revert NotOperator();
        _;
    }

    constructor(address _registry, address _operator) {
        registry = IValidationRegistry(_registry);
        operator = _operator;
    }

    /// @notice Step 1: seal a decision before it is acted on.
    /// @param requestHash sha256 of the canonical decision payload (off-chain).
    function seal(bytes32 requestHash, uint256 agentId) external onlyOperator {
        if (commitments[requestHash].sealedAt != 0) revert AlreadySealed();
        commitments[requestHash] = Commitment({
            hash: requestHash,
            agentId: agentId,
            sealedAt: uint64(block.timestamp),
            revealed: false
        });
        emit Sealed(requestHash, agentId, uint64(block.timestamp));
        // Also register the request with the standard registry so it is
        // independently discoverable, not just readable from this contract.
        registry.requestValidation(agentId, requestHash, "");
    }

    /// @notice Step 2: reveal the preimage and publish the validation result.
    /// @param requestHash the same hash used at seal()
    /// @param preimageHash sha256 recomputed off-chain by the caller from the
    ///        revealed plaintext; must match what was sealed, or this reverts.
    /// @param result 0=fail, 1=pass, 2=degraded — per the rule-gate outcome.
    /// @param evidenceURI where the plaintext decision + fill record are published.
    function reveal(
        bytes32 requestHash,
        bytes32 preimageHash,
        uint8 result,
        bytes32 evidenceHash,
        string calldata evidenceURI
    ) external onlyOperator {
        Commitment storage c = commitments[requestHash];
        if (c.sealedAt == 0) revert UnknownCommitment();
        if (c.revealed) revert AlreadyRevealed();
        if (preimageHash != c.hash) revert HashMismatch();

        c.revealed = true;
        emit Revealed(requestHash, c.agentId, result);

        registry.respondValidation(
            requestHash,
            c.agentId,
            result,
            evidenceHash,
            evidenceURI
        );
    }
}
