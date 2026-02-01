import "dotenv/config";
import express from "express";
import crypto from "crypto";
import { ethers } from "ethers";
import fs from "fs";
import path from "path";

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
const RouteAndDeliveryAbi = [
  "event Paid(bytes32 indexed batchId, address indexed payer, uint256 amount, bytes32 indexed basketHash, bytes encryptedBasket)",
  "function getOrder(bytes32 batchId) view returns (address payer,uint256 paidAmount,bytes32 basketHash,bytes encryptedBasket,uint64 createdAt)",
  "function isDeliveredHere(bytes32 batchId) view returns (bool)",
  "function deliver(bytes32 batchId,address to,address rwa1155,uint256[] tokenIds,uint256[] amounts) external",
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function RELAYER_ROLE() view returns (bytes32)",
];

const TradeJournalAbi = [
  "function hasReceipt(bytes32 batchId) view returns (bool)",
  "function getReceipt(bytes32 batchId) view returns (address payer,bytes32 basketHash,uint256 payChainId,bytes32 payTxHash,uint256[] deliveryChainIds,bytes32[] deliveryTxHashes,uint64 recordedAt)",
  "function recordReceipt(bytes32 batchId,address payer,bytes32 basketHash,uint256 payChainId,bytes32 payTxHash,uint256[] deliveryChainIds,bytes32[] deliveryTxHashes) external",
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function RELAYER_ROLE() view returns (bytes32)",
];

const AccessControlAbi = [
  "function hasRole(bytes32 role, address account) view returns (bool)",
  "function RELAYER_ROLE() view returns (bytes32)",
  "function MINTER_ROLE() view returns (bytes32)",
];

// Contracts
const routerSepolia = new ethers.Contract(ROUTER_SEPOLIA, RouteAndDeliveryAbi, walletSepolia);
const routerAmoy = new ethers.Contract(ROUTER_AMOY, RouteAndDeliveryAbi, walletAmoy);
const journal = new ethers.Contract(JOURNAL_OASIS, TradeJournalAbi, walletOasis);

function log(...args) {
  console.log(new Date().toISOString(), "-", ...args);
}

function logErr(...args) {
  console.error(new Date().toISOString(), "-", ...args);
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

function loadFormatAssets() {
  const file = path.join(process.cwd(), "format_assets.json");
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

  // RouteAndDelivery RELAYER_ROLE (Sepolia/Amoy)
  const routerRelayerRoleSepolia = await routerSepolia.RELAYER_ROLE();
  const routerRelayerRoleAmoy = await routerAmoy.RELAYER_ROLE();

  const hasRelayerSepolia = await routerSepolia.hasRole(routerRelayerRoleSepolia, relayerSepolia);
  const hasRelayerAmoy = await routerAmoy.hasRole(routerRelayerRoleAmoy, relayerAmoy);

  results.push({
    ok: hasRelayerSepolia,
    msg: hasRelayerSepolia
      ? `OK RELAYER_ROLE on Sepolia RouteAndDelivery for ${relayerSepolia}`
      : `MISSING RELAYER_ROLE on Sepolia RouteAndDelivery for ${relayerSepolia}`,
  });
  results.push({
    ok: hasRelayerAmoy,
    msg: hasRelayerAmoy
      ? `OK RELAYER_ROLE on Amoy RouteAndDelivery for ${relayerAmoy}`
      : `MISSING RELAYER_ROLE on Amoy RouteAndDelivery for ${relayerAmoy}`,
  });

  // TradeJournal RELAYER_ROLE (Oasis)
  const journalRole = await journal.RELAYER_ROLE();
  const hasJournalRelayer = await journal.hasRole(journalRole, relayerOasis);
  results.push({
    ok: hasJournalRelayer,
    msg: hasJournalRelayer
      ? `OK RELAYER_ROLE on Oasis TradeJournal for ${relayerOasis}`
      : `MISSING RELAYER_ROLE on Oasis TradeJournal for ${relayerOasis}`,
  });

  // RWA MINTER_ROLE for RouteAndDelivery (from format_assets.json if present)
  const fmt = loadFormatAssets();
  const networks = fmt?.networks || {};
  const rwaByChain = new Map();
  for (const [chainId, info] of Object.entries(networks)) {
    if (info?.rwa1155) rwaByChain.set(Number(chainId), info.rwa1155);
  }

  for (const [chainId, rwaAddr] of rwaByChain.entries()) {
    const info = CHAINS[chainId];
    if (!info) continue;
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

  // receipt presence (used for idempotency decisions)
  const hasReceipt = await journal.hasReceipt(batchId);
  log("[execute] journal.hasReceipt", { hasReceipt });

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
      // Уже доставлено в этой сети — если квитанции нет, не пишем неполную.
      if (!hasReceipt) {
        throw new Error(`already delivered in chain ${chainId}, but receipt missing; refusing to write partial receipt`);
      }
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
  }

  // 4) write receipt to Oasis (idempotent)
  let receiptTxHash = null;
  if (!hasReceipt) {
    // payTxHash: если фронт не передал, можешь оставить 0x00..00 для MVP
    const payTx = payTxHash && ethers.isHexString(payTxHash, 32)
      ? payTxHash
      : ethers.ZeroHash;

    log("[execute] recordReceipt send", { payTx });
    const tx = await journal.recordReceipt(
      batchId,
      payer,
      onchainHash,
      payChainId,
      payTx,
      deliveryChainIds,
      deliveryTxHashes
    );
    await tx.wait(1);
    receiptTxHash = tx.hash;
    log("[execute] recordReceipt mined", { txHash: receiptTxHash });
  }

  const result = {
    batchId,
    payer,
    paidAmount: paidAmount.toString(),
    basketHash: onchainHash,
    payChainId,
    receiptTxHash,
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
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => res.json({ ok: true }));

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

// GET /receipt/:batchId
app.get("/receipt/:batchId", async (req, res) => {
  try {
    const batchId = req.params?.batchId;
    if (!batchId || !ethers.isHexString(batchId, 32)) {
      return res.status(400).json({ ok: false, error: "batchId must be bytes32 hex (0x..32 bytes)" });
    }
    const has = await journal.hasReceipt(batchId);
    if (!has) return res.status(404).json({ ok: false, error: "receipt not found" });
    const receipt = await journal.getReceipt(batchId);
    return res.json({
      ok: true,
      receipt: {
        payer: receipt[0],
        basketHash: receipt[1],
        payChainId: Number(receipt[2]),
        payTxHash: receipt[3],
        deliveryChainIds: receipt[4].map((v) => Number(v)),
        deliveryTxHashes: receipt[5],
        recordedAt: Number(receipt[6]),
      },
    });
  } catch (e) {
    logErr("[receipt] error", e?.message || e);
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
