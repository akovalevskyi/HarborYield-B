// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * TradeJournal (Oasis)
 * - один контракт на Oasis
 * - релэйер пишет квитанцию: batchId -> сведения об оплате и доставках
 */
contract TradeJournal is AccessControl {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    struct Receipt {
        address payer;
        bytes32 basketHash;

        // где была оплата
        uint256 payChainId;
        bytes32 payTxHash;

        // куда доставили (списки одинаковой длины)
        uint256[] deliveryChainIds;
        bytes32[] deliveryTxHashes;

        uint64 recordedAt;
    }

    mapping(bytes32 => Receipt) private _receipts;
    mapping(bytes32 => bool) public hasReceipt;

    event ReceiptRecorded(
        bytes32 indexed batchId,
        address indexed payer,
        bytes32 indexed basketHash,
        uint256 payChainId,
        bytes32 payTxHash
    );

    constructor(address admin, address relayer) {
        require(admin != address(0), "admin=0");
        require(relayer != address(0), "relayer=0");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, relayer);
    }

    function recordReceipt(
        bytes32 batchId,
        address payer,
        bytes32 basketHash,
        uint256 payChainId,
        bytes32 payTxHash,
        uint256[] calldata deliveryChainIds,
        bytes32[] calldata deliveryTxHashes
    ) external onlyRole(RELAYER_ROLE) {
        require(batchId != bytes32(0), "batchId=0");
        require(payer != address(0), "payer=0");
        require(deliveryChainIds.length == deliveryTxHashes.length, "len mismatch");
        require(!hasReceipt[batchId], "already recorded");

        Receipt storage r = _receipts[batchId];
        r.payer = payer;
        r.basketHash = basketHash;
        r.payChainId = payChainId;
        r.payTxHash = payTxHash;
        r.recordedAt = uint64(block.timestamp);

        // копируем массивы в storage
        for (uint256 i = 0; i < deliveryChainIds.length; i++) {
            r.deliveryChainIds.push(deliveryChainIds[i]);
            r.deliveryTxHashes.push(deliveryTxHashes[i]);
        }

        hasReceipt[batchId] = true;

        emit ReceiptRecorded(batchId, payer, basketHash, payChainId, payTxHash);
    }

    function getReceipt(bytes32 batchId)
        external
        view
        returns (
            address payer,
            bytes32 basketHash,
            uint256 payChainId,
            bytes32 payTxHash,
            uint256[] memory deliveryChainIds,
            bytes32[] memory deliveryTxHashes,
            uint64 recordedAt
        )
    {
        require(hasReceipt[batchId], "not found");
        Receipt storage r = _receipts[batchId];

        // memory copies
        uint256 len = r.deliveryChainIds.length;
        uint256[] memory cids = new uint256[](len);
        bytes32[] memory txs = new bytes32[](len);

        for (uint256 i = 0; i < len; i++) {
            cids[i] = r.deliveryChainIds[i];
            txs[i] = r.deliveryTxHashes[i];
        }

        return (r.payer, r.basketHash, r.payChainId, r.payTxHash, cids, txs, r.recordedAt);
    }
}
