// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * OasisNEW (MVP Journal)
 * - Single contract on Oasis
 * - Relayer records all movements/sales as canonical history
 * - Open data (no encryption)
 */
contract OasisNEW is AccessControl {
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    uint8 public constant KIND_PAY = 1;
    uint8 public constant KIND_DELIVERY = 2;
    uint8 public constant KIND_TRADE = 3;
    uint8 public constant KIND_TRANSFER = 4;
    uint8 public constant KIND_LIST = 5;
    uint8 public constant KIND_CANCEL = 6;
    uint8 public constant KIND_SUMMARY = 7;

    struct Entry {
        uint8 kind;
        bytes32 batchId;
        uint256 chainId;
        address rwa1155;
        uint256 tokenId;
        address from;
        address to;
        uint256 amount;
        uint256 price;
        bytes32 txHash;
        bytes32 basketHash;
        uint256 payChainId;
        bytes32 payTxHash;
        uint64 recordedAt;
    }

    mapping(uint256 => Entry) private _entries;
    uint256 public nextEntryId = 1;

    mapping(address => uint256[]) private _byUser;
    mapping(bytes32 => uint256[]) private _byAsset;
    mapping(bytes32 => uint256[]) private _byBatch;
    mapping(bytes32 => Entry) private _summaryByBatch;
    mapping(bytes32 => bool) public hasSummary;

    event EntryRecorded(
        uint256 indexed entryId,
        uint8 indexed kind,
        bytes32 indexed batchId,
        uint256 chainId,
        address rwa1155,
        uint256 tokenId,
        address from,
        address to,
        uint256 amount,
        uint256 price,
        bytes32 txHash
    );

    event BatchSummaryRecorded(
        bytes32 indexed batchId,
        uint256 payChainId,
        bytes32 payTxHash,
        uint256 totalPaid
    );

    constructor(address admin, address relayer) {
        require(admin != address(0), "admin=0");
        require(relayer != address(0), "relayer=0");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, relayer);
    }

    function recordPayment(
        bytes32 batchId,
        address payer,
        bytes32 basketHash,
        uint256 payChainId,
        bytes32 payTxHash,
        uint256 totalPaid
    ) external onlyRole(RELAYER_ROLE) returns (uint256 entryId) {
        require(batchId != bytes32(0), "batchId=0");
        require(payer != address(0), "payer=0");

        entryId = _storeEntry(
            Entry({
                kind: KIND_PAY,
                batchId: batchId,
                chainId: 0,
                rwa1155: address(0),
                tokenId: 0,
                from: payer,
                to: address(0),
                amount: 0,
                price: totalPaid,
                txHash: bytes32(0),
                basketHash: basketHash,
                payChainId: payChainId,
                payTxHash: payTxHash,
                recordedAt: uint64(block.timestamp)
            })
        );
    }

    function recordMovement(
        uint8 kind,
        bytes32 batchId,
        uint256 chainId,
        address rwa1155,
        uint256 tokenId,
        address from,
        address to,
        uint256 amount,
        uint256 price,
        bytes32 txHash
    ) external onlyRole(RELAYER_ROLE) returns (uint256 entryId) {
        require(
            kind == KIND_DELIVERY ||
            kind == KIND_TRADE ||
            kind == KIND_TRANSFER ||
            kind == KIND_LIST ||
            kind == KIND_CANCEL,
            "bad kind"
        );
        require(chainId != 0, "chainId=0");
        require(rwa1155 != address(0), "rwa=0");
        require(amount > 0, "amount=0");

        entryId = _storeEntry(
            Entry({
                kind: kind,
                batchId: batchId,
                chainId: chainId,
                rwa1155: rwa1155,
                tokenId: tokenId,
                from: from,
                to: to,
                amount: amount,
                price: price,
                txHash: txHash,
                basketHash: bytes32(0),
                payChainId: 0,
                payTxHash: bytes32(0),
                recordedAt: uint64(block.timestamp)
            })
        );
    }

    function recordBatchSummary(
        bytes32 batchId,
        address payer,
        bytes32 basketHash,
        uint256 totalPaid,
        uint256 payChainId,
        bytes32 payTxHash,
        uint256[] calldata deliveryChainIds,
        bytes32[] calldata deliveryTxHashes
    ) external onlyRole(RELAYER_ROLE) {
        require(batchId != bytes32(0), "batchId=0");
        require(!hasSummary[batchId], "summary exists");
        require(deliveryChainIds.length == deliveryTxHashes.length, "len mismatch");

        Entry memory e = Entry({
            kind: KIND_SUMMARY,
            batchId: batchId,
            chainId: 0,
            rwa1155: address(0),
            tokenId: 0,
            from: payer,
            to: address(0),
            amount: 0,
            price: totalPaid,
            txHash: bytes32(0),
            basketHash: basketHash,
            payChainId: payChainId,
            payTxHash: payTxHash,
            recordedAt: uint64(block.timestamp)
        });

        _summaryByBatch[batchId] = e;
        hasSummary[batchId] = true;

        emit BatchSummaryRecorded(batchId, payChainId, payTxHash, totalPaid);
    }

    function getBatchSummary(bytes32 batchId) external view returns (Entry memory summary) {
        require(hasSummary[batchId], "summary not found");
        return _summaryByBatch[batchId];
    }

    function getEntry(uint256 entryId) external view returns (Entry memory) {
        require(entryId > 0 && entryId < nextEntryId, "not found");
        return _entries[entryId];
    }

    function getEntryCount() external view returns (uint256) {
        return nextEntryId - 1;
    }

    function getEntryIdsByUser(address user, uint256 start, uint256 limit)
        external
        view
        returns (uint256[] memory)
    {
        return _slice(_byUser[user], start, limit);
    }

    function getEntryIdsByAsset(
        uint256 chainId,
        address rwa1155,
        uint256 tokenId,
        uint256 start,
        uint256 limit
    ) external view returns (uint256[] memory) {
        bytes32 key = _assetKey(chainId, rwa1155, tokenId);
        return _slice(_byAsset[key], start, limit);
    }

    function getEntryIdsByBatch(bytes32 batchId, uint256 start, uint256 limit)
        external
        view
        returns (uint256[] memory)
    {
        return _slice(_byBatch[batchId], start, limit);
    }

    function _storeEntry(Entry memory e) internal returns (uint256 entryId) {
        entryId = nextEntryId++;
        _entries[entryId] = e;

        if (e.from != address(0)) _byUser[e.from].push(entryId);
        if (e.to != address(0) && e.to != e.from) _byUser[e.to].push(entryId);

        if (e.rwa1155 != address(0)) {
            bytes32 key = _assetKey(e.chainId, e.rwa1155, e.tokenId);
            _byAsset[key].push(entryId);
        }

        if (e.batchId != bytes32(0)) {
            _byBatch[e.batchId].push(entryId);
        }

        emit EntryRecorded(
            entryId,
            e.kind,
            e.batchId,
            e.chainId,
            e.rwa1155,
            e.tokenId,
            e.from,
            e.to,
            e.amount,
            e.price,
            e.txHash
        );
    }

    function _assetKey(uint256 chainId, address rwa1155, uint256 tokenId)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(chainId, rwa1155, tokenId));
    }

    function _slice(uint256[] storage arr, uint256 start, uint256 limit)
        internal
        view
        returns (uint256[] memory)
    {
        uint256 len = arr.length;
        if (start >= len) return new uint256[](0);

        uint256 end = start + limit;
        if (end > len) end = len;

        uint256 outLen = end - start;
        uint256[] memory out = new uint256[](outLen);
        for (uint256 i = 0; i < outLen; i++) {
            out[i] = arr[start + i];
        }
        return out;
    }
}
