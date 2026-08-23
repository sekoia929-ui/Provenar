// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./IValidationRegistry.sol";

/// @title OmoValidationAdapter
/// @notice Bridges omo's precommit/seal/reveal pattern into the real
///         ERC-8004 Validation Registry. Two on-chain moments per decision:
///           1. seal()   — Provenar publishes only the hash of a
///                         not-yet-executed agent decision, before any
///                         action is taken. This is Provenar's OWN
///                         precommit, independent of the registry — the
///                         registry has no concept of "seal before act".
///           2. reveal() — Provenar opens the preimage and, PROVIDED the
///                         agent has already called validationRequest()
///                         naming this adapter's address as the validator,
///                         posts the pass/fail score to the registry.
/// @dev Correction from an earlier draft: the ERC-8004 ValidationRegistry
///      requires the AGENT (its owner or an approved operator) to call
///      validationRequest first, naming this contract as validatorAddress.
///      Provenar never calls validationRequest itself. reveal() will
///      revert on the registry side if no such request exists yet — that
///      is registry-enforced, not re-checked here.
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
    event Revealed(bytes32 indexed requestHash, uint256 indexed agentId, uint8 score);

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

    /// @notice Step 1: seal a decision before it is acted on. This is
    ///         Provenar's own record — it does NOT touch the ERC-8004
    ///         registry, since only the agent can initiate a request there.
    function seal(bytes32 requestHash, uint256 agentId) external onlyOperator {
        if (commitments[requestHash].sealedAt != 0) revert AlreadySealed();
        commitments[requestHash] = Commitment({
            hash: requestHash,
            agentId: agentId,
            sealedAt: uint64(block.timestamp),
            revealed: false
        });
        emit Sealed(requestHash, agentId, uint64(block.timestamp));
    }

    /// @notice Step 2: reveal the preimage and publish the score to the
    ///         ERC-8004 registry via validationResponse. Requires the
    ///         agent to have already called validationRequest() on the
    ///         real registry naming this contract's address as validator
    ///         — the registry itself reverts if that hasn't happened.
    /// @param requestHash the same hash used at seal() AND the hash the
    ///        agent used when calling validationRequest — these must be
    ///        the same value for the registry to recognize this response.
    /// @param preimageHash sha256 recomputed off-chain by the caller from
    ///        the revealed plaintext; must match what was sealed, or this
    ///        reverts before ever touching the registry.
    /// @param score 0-100, per ERC-8004's response range (not a boolean).
    function reveal(
        bytes32 requestHash,
        bytes32 preimageHash,
        uint8 score,
        bytes32 evidenceHash,
        string calldata evidenceURI,
        string calldata tag
    ) external onlyOperator {
        Commitment storage c = commitments[requestHash];
        if (c.sealedAt == 0) revert UnknownCommitment();
        if (c.revealed) revert AlreadyRevealed();
        if (preimageHash != c.hash) revert HashMismatch();

        c.revealed = true;
        emit Revealed(requestHash, c.agentId, score);

        registry.validationResponse(requestHash, score, evidenceURI, evidenceHash, tag);
    }
}

