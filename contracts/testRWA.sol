// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * RwaCatalog1155 (Mock)
 * - 1 contract per chain
 * - Many RWA assets as tokenId (ERC1155)
 * - Admin lists tokenIds (catalog)
 * - MINTER can mint/mintBatch (for DeliveryVault/relayer)
 * - getListedTokenIds(start, limit) pagination for frontend/backends
 */
contract RwaCatalog1155 is ERC1155, ERC1155Supply, AccessControl {
    bytes32 public constant LISTER_ROLE = keccak256("LISTER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // Optional: base URI (can be ipfs://.../{id}.json)
    string private _baseUri;

    // Catalog storage
    uint256[] private _listed;
    mapping(uint256 => bool) public isListed;
    mapping(uint256 => uint256) public maxSupply;

    event TokenListed(uint256 indexed tokenId);
    event BaseURISet(string newBaseUri);
    event MaxSupplySet(uint256 indexed tokenId, uint256 maxSupply);

    constructor(string memory baseUri_, address admin) ERC1155("") {
        require(admin != address(0), "admin=0");
        _baseUri = baseUri_;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(LISTER_ROLE, admin);
        _grantRole(MINTER_ROLE, admin);
    }

    function setBaseURI(string calldata baseUri_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _baseUri = baseUri_;
        emit BaseURISet(baseUri_);
    }

    function uri(uint256 /*id*/) public view override returns (string memory) {
        return _baseUri;
    }

    // --- Catalog (listing) ---

    function listToken(uint256 tokenId) external onlyRole(LISTER_ROLE) {
        if (!isListed[tokenId]) {
            isListed[tokenId] = true;
            _listed.push(tokenId);
            emit TokenListed(tokenId);
        }
    }

    function listBatch(uint256[] calldata tokenIds) external onlyRole(LISTER_ROLE) {
        uint256 n = tokenIds.length;
        for (uint256 i = 0; i < n; i++) {
            uint256 tokenId = tokenIds[i];
            if (!isListed[tokenId]) {
                isListed[tokenId] = true;
                _listed.push(tokenId);
                emit TokenListed(tokenId);
            }
        }
    }

    // --- Supply limits ---

    function setMaxSupply(uint256 tokenId, uint256 max) external onlyRole(LISTER_ROLE) {
        require(isListed[tokenId], "not listed");
        require(max > 0, "max=0");
        require(max >= totalSupply(tokenId), "max < minted");
        maxSupply[tokenId] = max;
        emit MaxSupplySet(tokenId, max);
    }

    function setMaxSupplyBatch(uint256[] calldata tokenIds, uint256[] calldata maxes)
        external
        onlyRole(LISTER_ROLE)
    {
        uint256 n = tokenIds.length;
        require(n == maxes.length, "len mismatch");
        for (uint256 i = 0; i < n; i++) {
            uint256 tokenId = tokenIds[i];
            uint256 max = maxes[i];
            require(isListed[tokenId], "not listed");
            require(max > 0, "max=0");
            require(max >= totalSupply(tokenId), "max < minted");
            maxSupply[tokenId] = max;
            emit MaxSupplySet(tokenId, max);
        }
    }

    function getListedCount() external view returns (uint256) {
        return _listed.length;
    }

    /// @notice Pagination getter. If start >= len => returns empty array.
    function getListedTokenIds(uint256 start, uint256 limit)
        external
        view
        returns (uint256[] memory)
    {
        uint256 len = _listed.length;
        if (start >= len) return new uint256[](0);

        uint256 end = start + limit;
        if (end > len) end = len;

        uint256 outLen = end - start;
        uint256[] memory out = new uint256[](outLen);

        for (uint256 i = 0; i < outLen; i++) {
            out[i] = _listed[start + i];
        }
        return out;
    }

    // --- Minting (for relayer / DeliveryVault) ---

    function mint(address to, uint256 tokenId, uint256 amount, bytes calldata data)
        external
        onlyRole(MINTER_ROLE)
    {
        require(isListed[tokenId], "not listed");
        uint256 max = maxSupply[tokenId];
        require(max > 0, "max not set");
        require(totalSupply(tokenId) + amount <= max, "max supply exceeded");
        _mint(to, tokenId, amount, data);
    }

    function mintBatch(address to, uint256[] calldata tokenIds, uint256[] calldata amounts, bytes calldata data)
        external
        onlyRole(MINTER_ROLE)
    {
        uint256 n = tokenIds.length;
        require(n == amounts.length, "len mismatch");
        for (uint256 i = 0; i < n; i++) {
            require(isListed[tokenIds[i]], "not listed");
            uint256 max = maxSupply[tokenIds[i]];
            require(max > 0, "max not set");
            require(totalSupply(tokenIds[i]) + amounts[i] <= max, "max supply exceeded");
        }
        _mintBatch(to, tokenIds, amounts, data);
    }

    // --- Required overrides ---

    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    ) internal override(ERC1155, ERC1155Supply) {
        super._update(from, to, ids, values);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
