// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * RouteDeliveryTradeMarketplace (MVP, meta-tx)
 * - One per chain (Sepolia/Amoy)
 * - meta-list/buy/transfer for relayer execution (no wallet chain switch)
 * - approvals still required (ERC20 approve + ERC1155 setApprovalForAll)
 */
contract RouteDeliveryTradeMarketplace is AccessControl, ReentrancyGuard, ERC1155Holder, EIP712 {
    using SafeERC20 for IERC20;

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    IERC20 public immutable usdx;

    struct Listing {
        address seller;
        address rwa1155;
        uint256 tokenId;
        uint256 amount;
        uint256 pricePerUnit;
        bool active;
    }

    // listingId => listing
    mapping(uint256 => Listing) public listings;
    uint256 public nextListingId = 1;
    uint256[] private _activeListingIds;
    mapping(uint256 => uint256) private _activeIndex;

    // EIP-712 nonces
    mapping(address => uint256) public nonces;

    bytes32 private constant CREATE_LISTING_TYPEHASH =
        keccak256(
            "CreateListing(address seller,address rwa1155,uint256 tokenId,uint256 amount,uint256 pricePerUnit,uint256 nonce,uint256 deadline)"
        );
    bytes32 private constant BUY_LISTING_TYPEHASH =
        keccak256(
            "BuyListing(address buyer,uint256 listingId,uint256 amount,uint256 nonce,uint256 deadline)"
        );
    bytes32 private constant TRANSFER_ASSET_TYPEHASH =
        keccak256(
            "TransferAsset(address from,address rwa1155,address to,uint256 tokenId,uint256 amount,uint256 nonce,uint256 deadline)"
        );
    bytes32 private constant CANCEL_LISTING_TYPEHASH =
        keccak256(
            "CancelListing(address seller,uint256 listingId,uint256 nonce,uint256 deadline)"
        );

    event ListingCreated(
        uint256 indexed listingId,
        address indexed seller,
        address indexed rwa1155,
        uint256 tokenId,
        uint256 amount,
        uint256 pricePerUnit
    );

    event ListingCancelled(uint256 indexed listingId, address indexed seller);

    event ListingUpdated(uint256 indexed listingId, uint256 remaining, bool active);

    event TradeExecuted(
        uint256 indexed listingId,
        address indexed buyer,
        address indexed seller,
        address rwa1155,
        uint256 tokenId,
        uint256 amount,
        uint256 pricePerUnit,
        uint256 totalPrice
    );

    event AssetTransferred(
        address indexed from,
        address indexed to,
        address indexed rwa1155,
        uint256 tokenId,
        uint256 amount
    );

    event MetaTxUsed(address indexed signer, uint256 indexed nonce, bytes32 indexed typehash);

    constructor(address usdx_, address admin, address relayer)
        EIP712("RouteDeliveryTradeMarketplace", "1")
    {
        require(usdx_ != address(0), "usdx=0");
        require(admin != address(0), "admin=0");
        require(relayer != address(0), "relayer=0");

        usdx = IERC20(usdx_);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, relayer);
    }

    // ----- Direct (optional) -----
    function createListing(
        address rwa1155,
        uint256 tokenId,
        uint256 amount,
        uint256 pricePerUnit
    ) external nonReentrant returns (uint256 listingId) {
        listingId = _createListing(msg.sender, rwa1155, tokenId, amount, pricePerUnit);
    }

    function cancelListing(uint256 listingId) external nonReentrant {
        _cancelListing(msg.sender, listingId);
    }

    function buyListing(uint256 listingId, uint256 amount) external nonReentrant {
        _buyListing(msg.sender, listingId, amount);
    }

    function transferAsset(
        address rwa1155,
        address to,
        uint256 tokenId,
        uint256 amount
    ) external nonReentrant {
        _transferAsset(msg.sender, rwa1155, to, tokenId, amount);
    }

    // ----- Meta-tx (relayer) -----
    function createListingWithSig(
        address seller,
        address rwa1155,
        uint256 tokenId,
        uint256 amount,
        uint256 pricePerUnit,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant onlyRole(RELAYER_ROLE) returns (uint256 listingId) {
        uint256 nonce = _useNonce(seller);
        _verifySignature(
            seller,
            CREATE_LISTING_TYPEHASH,
            keccak256(abi.encode(CREATE_LISTING_TYPEHASH, seller, rwa1155, tokenId, amount, pricePerUnit, nonce, deadline)),
            deadline,
            signature
        );
        listingId = _createListing(seller, rwa1155, tokenId, amount, pricePerUnit);
    }

    function cancelListingWithSig(
        address seller,
        uint256 listingId,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        uint256 nonce = _useNonce(seller);
        _verifySignature(
            seller,
            CANCEL_LISTING_TYPEHASH,
            keccak256(abi.encode(CANCEL_LISTING_TYPEHASH, seller, listingId, nonce, deadline)),
            deadline,
            signature
        );
        _cancelListing(seller, listingId);
    }

    function buyListingWithSig(
        address buyer,
        uint256 listingId,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        uint256 nonce = _useNonce(buyer);
        _verifySignature(
            buyer,
            BUY_LISTING_TYPEHASH,
            keccak256(abi.encode(BUY_LISTING_TYPEHASH, buyer, listingId, amount, nonce, deadline)),
            deadline,
            signature
        );
        _buyListing(buyer, listingId, amount);
    }

    function transferAssetWithSig(
        address from,
        address rwa1155,
        address to,
        uint256 tokenId,
        uint256 amount,
        uint256 deadline,
        bytes calldata signature
    ) external nonReentrant onlyRole(RELAYER_ROLE) {
        uint256 nonce = _useNonce(from);
        _verifySignature(
            from,
            TRANSFER_ASSET_TYPEHASH,
            keccak256(abi.encode(TRANSFER_ASSET_TYPEHASH, from, rwa1155, to, tokenId, amount, nonce, deadline)),
            deadline,
            signature
        );
        _transferAsset(from, rwa1155, to, tokenId, amount);
    }

    // ----- Internal helpers -----
    function _createListing(
        address seller,
        address rwa1155,
        uint256 tokenId,
        uint256 amount,
        uint256 pricePerUnit
    ) internal returns (uint256 listingId) {
        require(rwa1155 != address(0), "rwa=0");
        require(amount > 0, "amount=0");
        require(pricePerUnit > 0, "price=0");
        require(
            IERC1155(rwa1155).isApprovedForAll(seller, address(this)),
            "approve required"
        );

        IERC1155(rwa1155).safeTransferFrom(seller, address(this), tokenId, amount, "0x");

        listingId = nextListingId++;
        listings[listingId] = Listing({
            seller: seller,
            rwa1155: rwa1155,
            tokenId: tokenId,
            amount: amount,
            pricePerUnit: pricePerUnit,
            active: true
        });
        _addActiveListing(listingId);

        emit ListingCreated(listingId, seller, rwa1155, tokenId, amount, pricePerUnit);
    }

    function _cancelListing(address seller, uint256 listingId) internal {
        Listing storage l = listings[listingId];
        require(l.active, "inactive");
        require(l.seller == seller, "not seller");
        l.active = false;
        _removeActiveListing(listingId);

        if (l.amount > 0) {
            IERC1155(l.rwa1155).safeTransferFrom(address(this), seller, l.tokenId, l.amount, "0x");
            l.amount = 0;
        }
        emit ListingUpdated(listingId, 0, false);
        emit ListingCancelled(listingId, seller);
    }

    function _buyListing(address buyer, uint256 listingId, uint256 amount) internal {
        Listing storage l = listings[listingId];
        require(l.active, "inactive");
        require(amount > 0, "amount=0");
        require(amount <= l.amount, "amount>listed");

        uint256 totalPrice = amount * l.pricePerUnit;

        l.amount -= amount;
        if (l.amount == 0) {
            l.active = false;
            _removeActiveListing(listingId);
        }

        usdx.safeTransferFrom(buyer, l.seller, totalPrice);
        IERC1155(l.rwa1155).safeTransferFrom(address(this), buyer, l.tokenId, amount, "0x");

        emit TradeExecuted(
            listingId,
            buyer,
            l.seller,
            l.rwa1155,
            l.tokenId,
            amount,
            l.pricePerUnit,
            totalPrice
        );
        emit ListingUpdated(listingId, l.amount, l.active);
    }

    function _transferAsset(
        address from,
        address rwa1155,
        address to,
        uint256 tokenId,
        uint256 amount
    ) internal {
        require(to != address(0), "to=0");
        require(amount > 0, "amount=0");
        IERC1155(rwa1155).safeTransferFrom(from, to, tokenId, amount, "0x");
        emit AssetTransferred(from, to, rwa1155, tokenId, amount);
    }

    function _useNonce(address signer) internal returns (uint256 nonce) {
        nonce = nonces[signer];
        nonces[signer] = nonce + 1;
    }

    function _verifySignature(
        address signer,
        bytes32 typehash,
        bytes32 structHash,
        uint256 deadline,
        bytes calldata signature
    ) internal {
        require(deadline >= block.timestamp, "expired");
        bytes32 digest = _hashTypedDataV4(structHash);
        address recovered = ECDSA.recover(digest, signature);
        require(recovered == signer, "bad sig");
        emit MetaTxUsed(signer, nonces[signer] - 1, typehash);
    }

    function getActiveListingCount() external view returns (uint256) {
        return _activeListingIds.length;
    }

    function getActiveListingIds(uint256 start, uint256 limit)
        external
        view
        returns (uint256[] memory)
    {
        uint256 len = _activeListingIds.length;
        if (start >= len) return new uint256[](0);

        uint256 end = start + limit;
        if (end > len) end = len;

        uint256 outLen = end - start;
        uint256[] memory out = new uint256[](outLen);
        for (uint256 i = 0; i < outLen; i++) {
            out[i] = _activeListingIds[start + i];
        }
        return out;
    }

    function _addActiveListing(uint256 listingId) internal {
        _activeIndex[listingId] = _activeListingIds.length;
        _activeListingIds.push(listingId);
    }

    function _removeActiveListing(uint256 listingId) internal {
        uint256 idx = _activeIndex[listingId];
        uint256 lastIdx = _activeListingIds.length - 1;
        if (idx != lastIdx) {
            uint256 lastId = _activeListingIds[lastIdx];
            _activeListingIds[idx] = lastId;
            _activeIndex[lastId] = idx;
        }
        _activeListingIds.pop();
        delete _activeIndex[listingId];
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl, ERC1155Holder)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
