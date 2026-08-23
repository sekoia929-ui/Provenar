// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/OmoValidationAdapter.sol";
import "./mocks/MockValidationRegistry.sol";

contract OmoValidationAdapterTest is Test {
    OmoValidationAdapter adapter;
    MockValidationRegistry registry;

    address operator = address(0xBEEF);
    address stranger = address(0xC0FFEE);
    uint256 constant AGENT_ID = 1;

    function setUp() public {
        registry = new MockValidationRegistry();
        adapter = new OmoValidationAdapter(address(registry), operator);
    }

    function _hash(string memory decision, string memory nonce) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(decision, nonce));
    }

    function test_seal_then_reveal_happy_path() public {
        bytes32 h = _hash("buy TEST @ thesis X", "nonce-1");

        vm.prank(operator);
        adapter.seal(h, AGENT_ID);

        (bytes32 storedHash, uint256 agentId, uint64 sealedAt, bool revealed) = adapter.commitments(h);
        assertEq(storedHash, h);
        assertEq(agentId, AGENT_ID);
        assertGt(sealedAt, 0);
        assertFalse(revealed);

        vm.prank(operator);
        adapter.reveal(h, h, 1, keccak256("evidence"), "ipfs://evidence-cid");

        (, , , bool revealedAfter) = adapter.commitments(h);
        assertTrue(revealedAfter);
    }

    function test_reveal_reverts_on_hash_mismatch() public {
        bytes32 sealed_ = _hash("buy TEST", "nonce-1");
        bytes32 tampered = _hash("sell TEST", "nonce-1"); // different plaintext

        vm.prank(operator);
        adapter.seal(sealed_, AGENT_ID);

        vm.prank(operator);
        vm.expectRevert(OmoValidationAdapter.HashMismatch.selector);
        adapter.reveal(sealed_, tampered, 1, bytes32(0), "");
    }

    function test_only_operator_can_seal() public {
        bytes32 h = _hash("buy TEST", "nonce-1");
        vm.prank(stranger);
        vm.expectRevert(OmoValidationAdapter.NotOperator.selector);
        adapter.seal(h, AGENT_ID);
    }

    function test_cannot_double_seal() public {
        bytes32 h = _hash("buy TEST", "nonce-1");
        vm.startPrank(operator);
        adapter.seal(h, AGENT_ID);
        vm.expectRevert(OmoValidationAdapter.AlreadySealed.selector);
        adapter.seal(h, AGENT_ID);
        vm.stopPrank();
    }

    function test_cannot_double_reveal() public {
        bytes32 h = _hash("buy TEST", "nonce-1");
        vm.startPrank(operator);
        adapter.seal(h, AGENT_ID);
        adapter.reveal(h, h, 1, bytes32(0), "");
        vm.expectRevert(OmoValidationAdapter.AlreadyRevealed.selector);
        adapter.reveal(h, h, 1, bytes32(0), "");
        vm.stopPrank();
    }

    function test_cannot_reveal_unknown_commitment() public {
        bytes32 h = _hash("never sealed", "nonce-x");
        vm.prank(operator);
        vm.expectRevert(OmoValidationAdapter.UnknownCommitment.selector);
        adapter.reveal(h, h, 1, bytes32(0), "");
    }
}
