// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IRwa1155Minter {
    function mintBatch(
        address to,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}

/**
 * RouteAndDelivery (MVP)
 * - Deploy одинаково в каждой сети (Sepolia, Amoy)
 * - pay(): юзер платит USDx и создает batchId + сохраняет encryptedBasket
 * - deliver(): релэйер доставляет ассеты в этой сети (mintBatch ERC1155), идемпотентно по batchId
 *
 * Важно: на каждой сети этот контракт должен иметь право MINTER_ROLE в вашем RwaCatalog1155,
 * иначе mintBatch не пройдет.
 */
contract RouteAndDelivery is AccessControl {
    using SafeERC20 for IERC20;

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

    IERC20 public immutable usdx;

    struct Order {
        address payer;
        uint256 paidAmount;      // в минимальных единицах USDx (6 decimals)
        bytes32 basketHash;      // hash от расшифрованной корзины (или канонического представления)
        bytes encryptedBasket;   // зашифрованный payload (bytes), как вы и планировали
        uint64  createdAt;
    }

    // batchId => order
    mapping(bytes32 => Order) private _orders;

    // batchId => paid (exists)
    mapping(bytes32 => bool) public isPaid;

    // batchId => delivered in THIS chain
    mapping(bytes32 => bool) public isDeliveredHere;

    event Paid(
        bytes32 indexed batchId,
        address indexed payer,
        uint256 amount,
        bytes32 indexed basketHash,
        bytes encryptedBasket
    );

    event DeliveredHere(
        bytes32 indexed batchId,
        address indexed to,
        address indexed rwa1155,
        uint256[] tokenIds,
        uint256[] amounts
    );

    constructor(address usdx_, address admin, address relayer) {
        require(usdx_ != address(0), "usdx=0");
        require(admin != address(0), "admin=0");
        require(relayer != address(0), "relayer=0");

        usdx = IERC20(usdx_);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RELAYER_ROLE, relayer);
    }

    /**
     * pay()
     * - USDx transferFrom(payer -> this)
     * - batchId детерминируется внутри (уникальный для данной сети и данного деплоя)
     * - order сохраняется (чтобы релэйер мог забрать encryptedBasket по batchId)
     *
     * NOTE: tx не может "вернуть" batchId фронту напрямую, поэтому фронт берет batchId из события Paid.
     */
    function pay(
        uint256 amount,
        bytes32 basketHash,
        bytes calldata encryptedBasket
    ) external returns (bytes32 batchId) {
        require(amount > 0, "amount=0");
        require(encryptedBasket.length > 0, "payload=0");

        // 1) забираем USDx
        usdx.safeTransferFrom(msg.sender, address(this), amount);

        // 2) генерим batchId
        // достаточно уникальный для MVP. relayer берет его из event Paid.
        batchId = keccak256(
            abi.encodePacked(
                address(this),
                block.chainid,
                msg.sender,
                amount,
                basketHash,
                block.timestamp,
                block.number
            )
        );

        require(!isPaid[batchId], "batch exists");

        // 3) сохраняем заказ
        _orders[batchId] = Order({
            payer: msg.sender,
            paidAmount: amount,
            basketHash: basketHash,
            encryptedBasket: encryptedBasket,
            createdAt: uint64(block.timestamp)
        });

        isPaid[batchId] = true;

        emit Paid(batchId, msg.sender, amount, basketHash, encryptedBasket);
    }

    function getOrder(bytes32 batchId)
        external
        view
        returns (
            address payer,
            uint256 paidAmount,
            bytes32 basketHash,
            bytes memory encryptedBasket,
            uint64 createdAt
        )
    {
        require(isPaid[batchId], "not found");
        Order storage o = _orders[batchId];
        return (o.payer, o.paidAmount, o.basketHash, o.encryptedBasket, o.createdAt);
    }

    /**
     * deliver()
     * - вызывается релэйером в каждой сети отдельно
     * - mintBatch на RWA ERC1155 контракт
     * - идемпотентность: один batchId можно "доставить" в каждой сети максимум 1 раз
     */
    function deliver(
        bytes32 batchId,
        address to,
        address rwa1155,
        uint256[] calldata tokenIds,
        uint256[] calldata amounts
    ) external onlyRole(RELAYER_ROLE) {
        require(to != address(0), "to=0");
        require(rwa1155 != address(0), "rwa=0");
        require(tokenIds.length > 0, "ids=0");
        require(tokenIds.length == amounts.length, "len mismatch");
        require(!isDeliveredHere[batchId], "already delivered");

        // В этой сети мы НЕ проверяем, что pay был именно здесь.
        // MVP: релэйер сам гарантирует, что batchId валиден и оплачен в "сети оплаты".
        isDeliveredHere[batchId] = true;

        IRwa1155Minter(rwa1155).mintBatch(to, tokenIds, amounts, "0x");

        emit DeliveredHere(batchId, to, rwa1155, tokenIds, amounts);
    }

    // MVP convenience: вывести собранный USDx на трежери (только админ)
    function sweepUSDx(address to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(to != address(0), "to=0");
        usdx.safeTransfer(to, amount);
    }
}
