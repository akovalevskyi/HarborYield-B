import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const {
  PORT = "8080",
  SEPOLIA_RPC,
  AMOY_RPC,
  OASIS_RPC,
  SEPOLIA_WS,
  AMOY_WS,
  RELAYER_PK,
  ROUTER_SEPOLIA,
  ROUTER_AMOY,
  JOURNAL_OASIS,
  AES_KEY_B64,
  CORS_ORIGINS = "",
  AUTO_EXECUTE = "false",
} = process.env;

function must(v, name) {
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

must(SEPOLIA_RPC, "SEPOLIA_RPC");
must(AMOY_RPC, "AMOY_RPC");
must(OASIS_RPC, "OASIS_RPC");
must(RELAYER_PK, "RELAYER_PK");
must(ROUTER_SEPOLIA, "ROUTER_SEPOLIA");
must(ROUTER_AMOY, "ROUTER_AMOY");
must(JOURNAL_OASIS, "JOURNAL_OASIS");
must(AES_KEY_B64, "AES_KEY_B64");

// --------- Providers / Wallets ----------
const sepolia = SEPOLIA_WS
  ? new ethers.WebSocketProvider(SEPOLIA_WS)
  : new ethers.JsonRpcProvider(SEPOLIA_RPC);
const amoy = AMOY_WS
  ? new ethers.WebSocketProvider(AMOY_WS)
  : new ethers.JsonRpcProvider(AMOY_RPC);
const oasis = new ethers.JsonRpcProvider(OASIS_RPC);

const walletSepolia = new ethers.Wallet(RELAYER_PK, sepolia);
const walletAmoy = new ethers.Wallet(RELAYER_PK, amoy);
const walletOasis = new ethers.Wallet(RELAYER_PK, oasis);

// --------- Minimal ABIs ----------
const RouteDeliveryTradeAbi = [
  "event Paid(bytes32 indexed batchId, address indexed payer, uint256 amount, bytes32 indexed basketHash, bytes encryptedBasket)",
  "function getOrder(bytes32 batchId) view returns (address payer,uint256 paidAmount,bytes32 basketHash,bytes encryptedBasket,uint64 createdAt)",
  "function isDeliveredHere(bytes32 batchId) view returns (bool)",
  "function deliver(bytes32 batchId,address to,address rwa1155,uint256[] tokenIds,uint256[] amounts) external",
  "function createListingWithSig(address seller,address rwa1155,uint256 tokenId,uint256 amount,uint256 pricePerUnit,uint256 deadline,bytes signature) external returns (uint256)",
  "function buyListingWithSig(address buyer,uint256 listingId,uint256 amount,uint256 deadline,bytes signature) external",
  "function transferAssetWithSig(address from,address rwa1155,address to,uint256 tokenId,uint256 amount,uint256 deadline,bytes signature) external",
  "function cancelListingWithSig(address seller,uint256 listingId,uint256 deadline,bytes signature) external",
  "function listings(uint256 listingId) view returns (address seller,address rwa1155,uint256 tokenId,uint256 amount,uint256 pricePerUnit,bool active)",
  "function nonces(address user) view returns (uint256)",
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function RELAYER_ROLE() view returns (bytes32)",
];

const OasisNewAbi = [
  "function recordPayment(bytes32 batchId,address payer,bytes32 basketHash,uint256 payChainId,bytes32 payTxHash,uint256 totalPaid) external returns (uint256)",
  "function recordMovement(uint8 kind,bytes32 batchId,uint256 chainId,address rwa1155,uint256 tokenId,address from,address to,uint256 amount,uint256 price,bytes32 txHash) external returns (uint256)",
  // recordBatchSummary / getBatchSummary intentionally omitted (old Oasis contract)
  "function getEntry(uint256 entryId) view returns (tuple(uint8 kind,bytes32 batchId,uint256 chainId,address rwa1155,uint256 tokenId,address from,address to,uint256 amount,uint256 price,bytes32 txHash,bytes32 basketHash,uint256 payChainId,bytes32 payTxHash,uint64 recordedAt))",
  "function getEntryIdsByBatch(bytes32 batchId,uint256 start,uint256 limit) view returns (uint256[])",
  "function getEntryIdsByUser(address user,uint256 start,uint256 limit) view returns (uint256[])",
  "function getEntryIdsByAsset(uint256 chainId,address rwa1155,uint256 tokenId,uint256 start,uint256 limit) view returns (uint256[])",
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function RELAYER_ROLE() view returns (bytes32)",
];

const AccessControlAbi = [
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function RELAYER_ROLE() view returns (bytes32)",
  "function MINTER_ROLE() view returns (bytes32)",
];

// Contracts
const routerSepolia = new ethers.Contract(ROUTER_SEPOLIA, RouteDeliveryTradeAbi, walletSepolia);
const routerAmoy = new ethers.Contract(ROUTER_AMOY, RouteDeliveryTradeAbi, walletAmoy);
const journal = new ethers.Contract(JOURNAL_OASIS, OasisNewAbi, walletOasis);

function log(...args) {
  console.log(new Date().toISOString(), "-", ...args);
}

function logErr(...args) {
  console.error(new Date().toISOString(), "-", ...args);
}

// --------- CORS ----------
const ALLOWED_ORIGINS = new Set(
  CORS_ORIGINS.split(",")
    .map((s) => s.trim())
    .filter(Boolean)
);

function applyCors(req, res) {
  const origin = req.headers.origin;
  if (!origin) return;

  if (ALLOWED_ORIGINS.size === 0) {
    // If no origins configured, allow all (no credentials).
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  } else {
    return;
  }

  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// --------- AES-GCM helpers ----------
const AES_KEY = Buffer.from(AES_KEY_B64, "base64"); // 32 bytes

function encryptBasketToHex(obj) {
  const plaintext = Buffer.from(JSON.stringify(obj), "utf8");
  const iv = crypto.randomBytes(12); // GCM standard
  const cipher = crypto.createCipheriv("aes-256-gcm", AES_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // payload = iv(12) || tag(16) || ciphertext(N)
  const packed = Buffer.concat([iv, tag, ciphertext]);
  return "0x" + packed.toString("hex");
}

function decryptBasketFromHex(hex) {
  const buf = Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);

  const decipher = crypto.createDecipheriv("aes-256-gcm", AES_KEY, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

function basketHash(obj) {
  // канонизируй как хочешь. Для MVP: keccak256 от JSON string.
  const s = JSON.stringify(obj);
  return ethers.keccak256(ethers.toUtf8Bytes(s));
}

// --------- Chain routing ----------
const CHAINS = {
  11155111: { name: "sepolia", router: routerSepolia, wallet: walletSepolia },
  80002: { name: "amoy", router: routerAmoy, wallet: walletAmoy },
};

function getChainInfo(chainId) {
  const info = CHAINS[Number(chainId)];
  if (!info) throw new Error(`Unsupported chainId: ${chainId}`);
  return info;
}

function loadAssets() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const file = path.join(__dirname, "assets.json");
  try {
    const raw = fs.readFileSync(file, "utf8");
    return JSON.parse(raw);
  } catch (_e) {
    return null;
  }
}

async function checkRoles() {
  const relayerSepolia = walletSepolia.address;
  const relayerAmoy = walletAmoy.address;
  const relayerOasis = walletOasis.address;
  const results = [];
  const getCodeSafe = async (provider, address) => {
    try {
      return await provider.getCode(address);
    } catch (_e) {
      return "0x";
    }
  };

  // RouteDeliveryTrade RELAYER_ROLE (Sepolia/Amoy)
  const sepoliaCode = await getCodeSafe(sepolia, routerSepolia.target ?? routerSepolia.address);
  if (sepoliaCode === "0x") {
    results.push({
      ok: false,
      msg: `NO CONTRACT CODE on Sepolia for router ${routerSepolia.target ?? routerSepolia.address}`,
    });
  } else {
    const routerRelayerRoleSepolia = await routerSepolia.RELAYER_ROLE();
    const hasRelayerSepolia = await routerSepolia.hasRole(routerRelayerRoleSepolia, relayerSepolia);
    results.push({
      ok: hasRelayerSepolia,
      msg: hasRelayerSepolia
        ? `OK RELAYER_ROLE on Sepolia RouteDeliveryTrade for ${relayerSepolia}`
        : `MISSING RELAYER_ROLE on Sepolia RouteDeliveryTrade for ${relayerSepolia}`,
    });
  }

  const amoyCode = await getCodeSafe(amoy, routerAmoy.target ?? routerAmoy.address);
  if (amoyCode === "0x") {
    results.push({
      ok: false,
      msg: `NO CONTRACT CODE on Amoy for router ${routerAmoy.target ?? routerAmoy.address}`,
    });
  } else {
    const routerRelayerRoleAmoy = await routerAmoy.RELAYER_ROLE();
    const hasRelayerAmoy = await routerAmoy.hasRole(routerRelayerRoleAmoy, relayerAmoy);
    results.push({
      ok: hasRelayerAmoy,
      msg: hasRelayerAmoy
        ? `OK RELAYER_ROLE on Amoy RouteDeliveryTrade for ${relayerAmoy}`
        : `MISSING RELAYER_ROLE on Amoy RouteDeliveryTrade for ${relayerAmoy}`,
    });
  }

  // OasisNEW RELAYER_ROLE (Oasis)
  const oasisCode = await getCodeSafe(oasis, journal.target ?? journal.address);
  if (oasisCode === "0x") {
    results.push({
      ok: false,
      msg: `NO CONTRACT CODE on Oasis for journal ${journal.target ?? journal.address}`,
    });
  } else {
    const journalRole = await journal.RELAYER_ROLE();
    const hasJournalRelayer = await journal.hasRole(journalRole, relayerOasis);
    results.push({
      ok: hasJournalRelayer,
      msg: hasJournalRelayer
        ? `OK RELAYER_ROLE on OasisNEW for ${relayerOasis}`
        : `MISSING RELAYER_ROLE on OasisNEW for ${relayerOasis}`,
    });
  }

  // RWA MINTER_ROLE for RouteDeliveryTrade (from assets.json if present)
  const fmt = loadAssets();
  const networks = fmt?.networks || {};
  const rwaByChain = new Map();
  for (const [chainId, info] of Object.entries(networks)) {
    if (info?.rwa1155) rwaByChain.set(Number(chainId), info.rwa1155);
  }

  for (const [chainId, rwaAddr] of rwaByChain.entries()) {
    const info = CHAINS[chainId];
    if (!info) continue;
    const rwaCode = await getCodeSafe(info.wallet.provider, rwaAddr);
    if (rwaCode === "0x") {
      results.push({
        ok: false,
        msg: `NO CONTRACT CODE on chain ${chainId} for RWA ${rwaAddr}`,
      });
      continue;
    }
    const rwa = new ethers.Contract(rwaAddr, AccessControlAbi, info.wallet);
    const minterRole = await rwa.MINTER_ROLE();
    const hasMinter = await rwa.hasRole(minterRole, info.router.target ?? info.router.address);
    results.push({
      ok: hasMinter,
      msg: hasMinter
        ? `OK MINTER_ROLE on RWA ${rwaAddr} for router ${info.router.target ?? info.router.address} (chain ${chainId})`
        : `MISSING MINTER_ROLE on RWA ${rwaAddr} for router ${info.router.target ?? info.router.address} (chain ${chainId})`,
    });
  }

  return results;
}

// --------- Execute core ----------
async function executeBatch({ payChainId, batchId, payTxHash }) {
  log("[execute] start", { payChainId, batchId, payTxHash });
  if (!CHAINS[payChainId]) throw new Error(`Unsupported payChainId: ${payChainId}`);
  if (!batchId || !ethers.isHexString(batchId, 32)) throw new Error("batchId must be bytes32 hex (0x..32 bytes)");

  // 1) get order from pay chain router
  const payRouter = CHAINS[payChainId].router;
  log("[execute] getOrder", { payChainId, router: payRouter.target ?? payRouter.address });
  const [payer, paidAmount, onchainHash, encryptedBasket, createdAt] = await payRouter.getOrder(batchId);
  log("[execute] order", {
    payer,
    paidAmount: paidAmount.toString(),
    onchainHash,
    encryptedLen: encryptedBasket?.length ?? 0,
    createdAt: Number(createdAt),
  });

  // Oasis entries by batch (used for idempotency decisions)
  const existingIds = await journal.getEntryIdsByBatch(batchId, 0, 1);
  const hasAnyEntry = Array.isArray(existingIds) && existingIds.length > 0;
  log("[execute] journal.hasAnyEntry", { hasAnyEntry });

  // 2) decrypt basket
  log("[execute] decrypt basket");
  const basket = decryptBasketFromHex(encryptedBasket);
  const computedHash = basketHash(basket);

  if (computedHash.toLowerCase() !== onchainHash.toLowerCase()) {
    throw new Error(`basketHash mismatch: computed ${computedHash} != onchain ${onchainHash}`);
  }
  log("[execute] basket hash ok");

  // basket format (MVP):
  // {
  //   "to": "0xUser...",
  //   "legs": [
  //     { "chainId": 11155111, "rwa1155": "0x...", "tokenIds": [1,2,3], "amounts": [1,1,1] },
  //     { "chainId": 80002,    "rwa1155": "0x...", "tokenIds": [10],    "amounts": [2] }
  //   ]
  // }
  const to = basket.to;
  const legs = Array.isArray(basket.legs) ? basket.legs : [];
  if (!ethers.isAddress(to)) throw new Error("basket.to invalid");
  if (legs.length === 0) throw new Error("basket.legs empty");
  log("[execute] basket", { to, legsCount: legs.length });

  // 3) deliver in each leg chain
  const deliveryChainIds = [];
  const deliveryTxHashes = [];
  const deliveredLegs = [];

  for (const leg of legs) {
    const chainId = Number(leg.chainId);
    const info = CHAINS[chainId];
    if (!info) throw new Error(`Unsupported leg chainId: ${chainId}`);

    const rwa = leg.rwa1155;
    const tokenIds = leg.tokenIds;
    const amounts = leg.amounts;

    log("[execute] leg", { chainId, rwa, tokenIds, amounts });
    if (!ethers.isAddress(rwa)) throw new Error(`leg.rwa1155 invalid for chain ${chainId}`);
    if (!Array.isArray(tokenIds) || tokenIds.length === 0) throw new Error(`leg.tokenIds invalid for chain ${chainId}`);
    if (!Array.isArray(amounts) || amounts.length !== tokenIds.length) throw new Error(`leg.amounts mismatch for chain ${chainId}`);

    // idempotency check on-chain
    const already = await info.router.isDeliveredHere(batchId);
    if (already) {
    // Уже доставлено в этой сети — пропускаем.
    log("[execute] already delivered", { chainId });
    continue;
  }

    log("[execute] deliver tx send", { chainId });
    const tx = await info.router.deliver(batchId, to, rwa, tokenIds, amounts);
    log("[execute] deliver tx hash", { chainId, txHash: tx.hash });
    const rcpt = await tx.wait(1);
    log("[execute] deliver tx mined", { chainId, txHash: rcpt.hash, status: rcpt.status });

    deliveryChainIds.push(chainId);
    deliveryTxHashes.push(rcpt.hash);
    deliveredLegs.push({
      chainId,
      txHash: rcpt.hash,
      rwa1155: rwa,
      tokenIds,
      amounts,
    });
  }

  // 4) write entries to Oasis (idempotent on first call)
  let paymentTxHash = null;
  if (!hasAnyEntry) {
    const payTx = payTxHash && ethers.isHexString(payTxHash, 32) ? payTxHash : ethers.ZeroHash;
    log("[execute] recordPayment send", { payTx });
    const tx = await journal.recordPayment(batchId, payer, onchainHash, payChainId, payTx, paidAmount);
    await tx.wait(1);
    paymentTxHash = tx.hash;
    log("[execute] recordPayment mined", { txHash: paymentTxHash });
  }

  for (const leg of deliveredLegs) {
    for (let i = 0; i < leg.tokenIds.length; i++) {
      const tokenId = leg.tokenIds[i];
      const amount = leg.amounts[i];
      log("[execute] recordMovement send", { chainId: leg.chainId, txHash: leg.txHash, tokenId, amount });
      const tx = await journal.recordMovement(
        2,
        batchId,
        leg.chainId,
        leg.rwa1155,
        tokenId,
        ethers.ZeroAddress,
        to,
        amount,
        0,
        leg.txHash
      );
      await tx.wait(1);
      log("[execute] recordMovement mined", { txHash: tx.hash });
    }
  }

  // recordBatchSummary disabled: current Oasis contract does not support it

  const result = {
    batchId,
    payer,
    paidAmount: paidAmount.toString(),
    basketHash: onchainHash,
    payChainId,
    paymentTxHash,
    deliveries: deliveryChainIds.map((cid, i) => ({
      chainId: cid,
      txHash: deliveryTxHashes[i],
    })),
  };
  log("[execute] done", result);
  return result;
}

// --------- Express server ----------
const app = express();
app.use((req, res, next) => {
  applyCors(req, res);
  if (req.method === "OPTIONS") return res.sendStatus(204);
  return next();
});
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => res.json({ ok: true }));

// GET /assets
app.get("/assets", (_req, res) => {
  try {
    const data = loadAssets();
    if (!data) return res.status(500).json({ ok: false, error: "assets.json not found" });
    return res.json({ ok: true, ...data });
  } catch (e) {
    logErr("[assets] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /encryptBasket
// body: { basket: {...} }
// returns: { basketHash, encryptedBasket }
app.post("/encryptBasket", (req, res) => {
  try {
    const basket = req.body?.basket;
    if (!basket || typeof basket !== "object") return res.status(400).json({ error: "basket object required" });

    const h = basketHash(basket);
    const enc = encryptBasketToHex(basket);
    log("[encryptBasket]", { basketHash: h, bytes: enc.length });
    res.json({ basketHash: h, encryptedBasket: enc });
  } catch (e) {
    logErr("[encryptBasket] error", e?.message || e);
    res.status(500).json({ error: String(e?.message || e) });
  }
});

// POST /execute
// body: { payChainId: 11155111|80002, batchId: "0x..", payTxHash?: "0x.." }
app.post("/execute", async (req, res) => {
  try {
    const payChainId = Number(req.body?.payChainId);
    const batchId = req.body?.batchId;
    const payTxHash = req.body?.payTxHash;

    log("[execute] request", { payChainId, batchId, payTxHash });
    const out = await executeBatch({ payChainId, batchId, payTxHash });
    res.json({ ok: true, result: out });
  } catch (e) {
    logErr("[execute] error", e?.message || e);
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /recordTrade
// body: { chainId, rwa1155, tokenId, from, to, amount, priceUSDx, txHash, batchId? }
app.post("/recordTrade", async (req, res) => {
  try {
    const chainId = Number(req.body?.chainId);
    const rwa1155 = req.body?.rwa1155;
    const tokenId = Number(req.body?.tokenId);
    const from = req.body?.from;
    const to = req.body?.to;
    const amount = Number(req.body?.amount);
    const priceUSDx = Number(req.body?.priceUSDx);
    const txHash = req.body?.txHash;
    const batchId = req.body?.batchId ?? ethers.ZeroHash;

    if (!chainId) return res.status(400).json({ ok: false, error: "chainId required" });
    if (!ethers.isAddress(rwa1155)) return res.status(400).json({ ok: false, error: "invalid rwa1155" });
    if (!ethers.isAddress(from)) return res.status(400).json({ ok: false, error: "invalid from" });
    if (!ethers.isAddress(to)) return res.status(400).json({ ok: false, error: "invalid to" });
    if (!Number.isFinite(tokenId) || tokenId <= 0) return res.status(400).json({ ok: false, error: "invalid tokenId" });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok: false, error: "invalid amount" });
    if (!Number.isFinite(priceUSDx) || priceUSDx <= 0) return res.status(400).json({ ok: false, error: "invalid priceUSDx" });
    if (!ethers.isHexString(txHash, 32)) return res.status(400).json({ ok: false, error: "txHash must be bytes32" });
    if (batchId && !ethers.isHexString(batchId, 32)) {
      return res.status(400).json({ ok: false, error: "batchId must be bytes32" });
    }

    const tx = await journal.recordMovement(
      3,
      batchId,
      chainId,
      rwa1155,
      tokenId,
      from,
      to,
      amount,
      priceUSDx,
      txHash
    );
    await tx.wait(1);
    return res.json({ ok: true, txHash: tx.hash });
  } catch (e) {
    logErr("[recordTrade] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// POST /recordTransfer
// body: { chainId, rwa1155, tokenId, from, to, amount, txHash, batchId? }
app.post("/recordTransfer", async (req, res) => {
  try {
    const chainId = Number(req.body?.chainId);
    const rwa1155 = req.body?.rwa1155;
    const tokenId = Number(req.body?.tokenId);
    const from = req.body?.from;
    const to = req.body?.to;
    const amount = Number(req.body?.amount);
    const txHash = req.body?.txHash;
    const batchId = req.body?.batchId ?? ethers.ZeroHash;

    if (!chainId) return res.status(400).json({ ok: false, error: "chainId required" });
    if (!ethers.isAddress(rwa1155)) return res.status(400).json({ ok: false, error: "invalid rwa1155" });
    if (!ethers.isAddress(from)) return res.status(400).json({ ok: false, error: "invalid from" });
    if (!ethers.isAddress(to)) return res.status(400).json({ ok: false, error: "invalid to" });
    if (!Number.isFinite(tokenId) || tokenId <= 0) return res.status(400).json({ ok: false, error: "invalid tokenId" });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok: false, error: "invalid amount" });
    if (!ethers.isHexString(txHash, 32)) return res.status(400).json({ ok: false, error: "txHash must be bytes32" });
    if (batchId && !ethers.isHexString(batchId, 32)) {
      return res.status(400).json({ ok: false, error: "batchId must be bytes32" });
    }

    const tx = await journal.recordMovement(
      4,
      batchId,
      chainId,
      rwa1155,
      tokenId,
      from,
      to,
      amount,
      0,
      txHash
    );
    await tx.wait(1);
    return res.json({ ok: true, txHash: tx.hash });
  } catch (e) {
    logErr("[recordTransfer] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// --- Meta-tx marketplace relay ---
app.post("/market/list", async (req, res) => {
  try {
    log("[market/list] request", req.body);
    const chainId = Number(req.body?.chainId);
    const seller = req.body?.seller;
    const rwa1155 = req.body?.rwa1155;
    const tokenId = Number(req.body?.tokenId);
    const amount = Number(req.body?.amount);
    const pricePerUnit = Number(req.body?.pricePerUnit);
    const deadline = Number(req.body?.deadline);
    const signature = req.body?.signature;

    if (!chainId) return res.status(400).json({ ok: false, error: "chainId required" });
    if (!ethers.isAddress(seller)) return res.status(400).json({ ok: false, error: "invalid seller" });
    if (!ethers.isAddress(rwa1155)) return res.status(400).json({ ok: false, error: "invalid rwa1155" });
    if (!Number.isFinite(tokenId) || tokenId <= 0) return res.status(400).json({ ok: false, error: "invalid tokenId" });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok: false, error: "invalid amount" });
    if (!Number.isFinite(pricePerUnit) || pricePerUnit <= 0) return res.status(400).json({ ok: false, error: "invalid pricePerUnit" });
    if (!Number.isFinite(deadline) || deadline <= 0) return res.status(400).json({ ok: false, error: "invalid deadline" });
    if (!ethers.isHexString(signature)) return res.status(400).json({ ok: false, error: "invalid signature" });

    const info = getChainInfo(chainId);
    const tx = await info.router.createListingWithSig(
      seller,
      rwa1155,
      tokenId,
      amount,
      pricePerUnit,
      deadline,
      signature
    );
    await tx.wait(1);
    const recordTx = await journal.recordMovement(
      5,
      ethers.ZeroHash,
      chainId,
      rwa1155,
      tokenId,
      seller,
      info.router.target ?? info.router.address,
      amount,
      pricePerUnit,
      tx.hash
    );
    await recordTx.wait(1);
    return res.json({ ok: true, txHash: tx.hash, oasisTxHash: recordTx.hash });
  } catch (e) {
    logErr("[market/list] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/market/buy", async (req, res) => {
  try {
    log("[market/buy] request", req.body);
    const chainId = Number(req.body?.chainId);
    const buyer = req.body?.buyer;
    const listingId = Number(req.body?.listingId);
    const amount = Number(req.body?.amount);
    const deadline = Number(req.body?.deadline);
    const signature = req.body?.signature;

    if (!chainId) return res.status(400).json({ ok: false, error: "chainId required" });
    if (!ethers.isAddress(buyer)) return res.status(400).json({ ok: false, error: "invalid buyer" });
    if (!Number.isFinite(listingId) || listingId <= 0) return res.status(400).json({ ok: false, error: "invalid listingId" });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok: false, error: "invalid amount" });
    if (!Number.isFinite(deadline) || deadline <= 0) return res.status(400).json({ ok: false, error: "invalid deadline" });
    if (!ethers.isHexString(signature)) return res.status(400).json({ ok: false, error: "invalid signature" });

    const info = getChainInfo(chainId);
    const listing = await info.router.listings(listingId);
    const seller = listing[0];
    const rwa1155 = listing[1];
    const tokenId = Number(listing[2]);
    const pricePerUnit = Number(listing[4]);

    try {
      await info.router.buyListingWithSig.staticCall(buyer, listingId, amount, deadline, signature);
      log("[market/buy] staticCall ok");
    } catch (err) {
      logErr("[market/buy] staticCall error", {
        reason: err?.reason,
        shortMessage: err?.shortMessage,
        errorName: err?.errorName,
        errorArgs: err?.errorArgs,
        data: err?.data,
        message: err?.message,
      });
    }

    const tx = await info.router.buyListingWithSig(buyer, listingId, amount, deadline, signature);
    await tx.wait(1);
    const totalPrice = pricePerUnit * amount;
    const recordTx = await journal.recordMovement(
      3,
      ethers.ZeroHash,
      chainId,
      rwa1155,
      tokenId,
      seller,
      buyer,
      amount,
      totalPrice,
      tx.hash
    );
    await recordTx.wait(1);
    return res.json({ ok: true, txHash: tx.hash, oasisTxHash: recordTx.hash });
  } catch (e) {
    logErr("[market/buy] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/market/transfer", async (req, res) => {
  try {
    log("[market/transfer] request", req.body);
    const chainId = Number(req.body?.chainId);
    const from = req.body?.from;
    const to = req.body?.to;
    const rwa1155 = req.body?.rwa1155;
    const tokenId = Number(req.body?.tokenId);
    const amount = Number(req.body?.amount);
    const deadline = Number(req.body?.deadline);
    const signature = req.body?.signature;

    if (!chainId) return res.status(400).json({ ok: false, error: "chainId required" });
    if (!ethers.isAddress(from)) return res.status(400).json({ ok: false, error: "invalid from" });
    if (!ethers.isAddress(to)) return res.status(400).json({ ok: false, error: "invalid to" });
    if (!ethers.isAddress(rwa1155)) return res.status(400).json({ ok: false, error: "invalid rwa1155" });
    if (!Number.isFinite(tokenId) || tokenId <= 0) return res.status(400).json({ ok: false, error: "invalid tokenId" });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ ok: false, error: "invalid amount" });
    if (!Number.isFinite(deadline) || deadline <= 0) return res.status(400).json({ ok: false, error: "invalid deadline" });
    if (!ethers.isHexString(signature)) return res.status(400).json({ ok: false, error: "invalid signature" });

    const info = getChainInfo(chainId);
    const tx = await info.router.transferAssetWithSig(
      from,
      rwa1155,
      to,
      tokenId,
      amount,
      deadline,
      signature
    );
    await tx.wait(1);
    const recordTx = await journal.recordMovement(
      4,
      ethers.ZeroHash,
      chainId,
      rwa1155,
      tokenId,
      from,
      to,
      amount,
      0,
      tx.hash
    );
    await recordTx.wait(1);
    return res.json({ ok: true, txHash: tx.hash, oasisTxHash: recordTx.hash });
  } catch (e) {
    logErr("[market/transfer] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.post("/market/cancel", async (req, res) => {
  try {
    log("[market/cancel] request", req.body);
    const chainId = Number(req.body?.chainId);
    const seller = req.body?.seller;
    const listingId = Number(req.body?.listingId);
    const deadline = Number(req.body?.deadline);
    const signature = req.body?.signature;

    if (!chainId) return res.status(400).json({ ok: false, error: "chainId required" });
    if (!ethers.isAddress(seller)) return res.status(400).json({ ok: false, error: "invalid seller" });
    if (!Number.isFinite(listingId) || listingId <= 0) return res.status(400).json({ ok: false, error: "invalid listingId" });
    if (!Number.isFinite(deadline) || deadline <= 0) return res.status(400).json({ ok: false, error: "invalid deadline" });
    if (!ethers.isHexString(signature)) return res.status(400).json({ ok: false, error: "invalid signature" });

    const info = getChainInfo(chainId);
    const listing = await info.router.listings(listingId);
    const rwa1155 = listing[1];
    const tokenId = Number(listing[2]);
    const amount = Number(listing[3]);

    const tx = await info.router.cancelListingWithSig(seller, listingId, deadline, signature);
    await tx.wait(1);
    if (amount > 0) {
      const recordTx = await journal.recordMovement(
        6,
        ethers.ZeroHash,
        chainId,
        rwa1155,
        tokenId,
        info.router.target ?? info.router.address,
        seller,
        amount,
        0,
        tx.hash
      );
      await recordTx.wait(1);
      return res.json({ ok: true, txHash: tx.hash, oasisTxHash: recordTx.hash });
    }
    return res.json({ ok: true, txHash: tx.hash, oasisTxHash: null });
  } catch (e) {
    logErr("[market/cancel] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// GET /entries/batch/:batchId
app.get("/entries/batch/:batchId", async (req, res) => {
  try {
    const batchId = req.params?.batchId;
    if (!batchId || !ethers.isHexString(batchId, 32)) {
      return res.status(400).json({ ok: false, error: "batchId must be bytes32 hex (0x..32 bytes)" });
    }
    const ids = await journal.getEntryIdsByBatch(batchId, 0, 100);
    return res.json({ ok: true, entryIds: ids.map((v) => Number(v)) });
  } catch (e) {
    logErr("[entries/batch] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// GET /entry/:id
app.get("/entry/:id", async (req, res) => {
  try {
    const id = Number(req.params?.id);
    if (!id || id < 1) return res.status(400).json({ ok: false, error: "id must be positive integer" });
    const entry = await journal.getEntry(id);
    return res.json({ ok: true, entry });
  } catch (e) {
    logErr("[entry] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// GET /entries/user/:address
app.get("/entries/user/:address", async (req, res) => {
  try {
    const user = req.params?.address;
    if (!user || !ethers.isAddress(user)) {
      return res.status(400).json({ ok: false, error: "invalid address" });
    }
    const ids = await journal.getEntryIdsByUser(user, 0, 100);
    return res.json({ ok: true, entryIds: ids.map((v) => Number(v)) });
  } catch (e) {
    logErr("[entries/user] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// GET /entries/asset/:chainId/:rwa1155/:tokenId
app.get("/entries/asset/:chainId/:rwa1155/:tokenId", async (req, res) => {
  try {
    const chainId = Number(req.params?.chainId);
    const rwa1155 = req.params?.rwa1155;
    const tokenId = Number(req.params?.tokenId);
    if (!chainId) return res.status(400).json({ ok: false, error: "invalid chainId" });
    if (!ethers.isAddress(rwa1155)) return res.status(400).json({ ok: false, error: "invalid rwa1155" });
    if (!tokenId || tokenId < 1) return res.status(400).json({ ok: false, error: "invalid tokenId" });

    const ids = await journal.getEntryIdsByAsset(chainId, rwa1155, tokenId, 0, 200);
    const entries = [];
    for (const id of ids) {
      const entry = await journal.getEntry(id);
      entries.push({
        id: Number(id),
        kind: Number(entry.kind),
        price: Number(entry.price),
        amount: Number(entry.amount),
        from: entry.from,
        to: entry.to,
        recordedAt: Number(entry.recordedAt),
      });
    }
    return res.json({ ok: true, entries });
  } catch (e) {
    logErr("[entries/asset] error", e?.message || e);
    return res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

app.listen(Number(PORT), async () => {
  log(`Relayer listening on http://localhost:${PORT}`);
  try {
    const results = await checkRoles();
    for (const r of results) {
      log(`Role checks: ${r.msg}`);
    }
  } catch (err) {
    logErr("Role checks: FAIL", err?.message || err);
  }
  if (AUTO_EXECUTE.toLowerCase() === "true") {
    log("AUTO_EXECUTE=true ignored: watchers were removed. Use POST /execute from frontend.");
  }
});
