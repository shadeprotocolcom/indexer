import express from "express";
import cors from "cors";
import { buildPoseidon } from "circomlibjs";
import { ethers } from "ethers";
import dotenv from "dotenv";
import { ShadeDatabase } from "./database.js";
import { MerkleTree } from "./merkle.js";
import { EventScanner } from "./scanner.js";

dotenv.config();

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT ?? "4000", 10);
const RPC_URL = process.env.RPC_URL ?? "https://rpc.citreascan.com";
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS ?? "";
const DEPLOYMENT_BLOCK = parseInt(process.env.DEPLOYMENT_BLOCK ?? "0", 10);
const DB_PATH = process.env.DB_PATH ?? undefined;
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL ?? "2000", 10);

/**
 * BN254 SNARK scalar field prime.
 */
const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * ZERO_VALUE = keccak256("Shade") % SNARK_FIELD
 * Used as the empty leaf value in the Merkle tree.
 */
const ZERO_VALUE =
  BigInt(ethers.keccak256(ethers.toUtf8Bytes("Shade"))) % SNARK_FIELD;

/**
 * Merkle tree depth. 2^16 = 65,536 leaf capacity.
 */
const TREE_DEPTH = 16;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

let db: ShadeDatabase;
let merkleTree: MerkleTree;
let scanner: EventScanner;

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  process.stdout.write("[indexer] Starting Shade Protocol Indexer...\n");

  if (!CONTRACT_ADDRESS) {
    process.stderr.write(
      "[indexer] WARNING: CONTRACT_ADDRESS not set. Scanner will not start.\n",
    );
  }

  // Initialize Poseidon (async, one-time).
  process.stdout.write("[indexer] Initializing Poseidon hash function...\n");
  const poseidon = await buildPoseidon();

  // Initialize the database.
  db = new ShadeDatabase(DB_PATH);
  process.stdout.write("[indexer] Database initialized.\n");

  // Initialize the Merkle tree.
  merkleTree = new MerkleTree(TREE_DEPTH, ZERO_VALUE, poseidon);
  process.stdout.write(
    `[indexer] Merkle tree initialized (depth=${TREE_DEPTH}, zeroValue=${ZERO_VALUE})\n`,
  );

  // Initialize and start the event scanner (only if contract address is set).
  if (CONTRACT_ADDRESS) {
    scanner = new EventScanner({
      rpcUrl: RPC_URL,
      contractAddress: CONTRACT_ADDRESS,
      db,
      merkleTree,
      poseidon,
      pollInterval: POLL_INTERVAL,
    });
    await scanner.start(DEPLOYMENT_BLOCK);
    process.stdout.write("[indexer] Event scanner started.\n");
  }

  // Start the Express server.
  const app = createServer();
  app.listen(PORT, () => {
    process.stdout.write(`[indexer] REST API listening on port ${PORT}\n`);
  });

  // Graceful shutdown.
  const shutdown = () => {
    process.stdout.write("[indexer] Shutting down...\n");
    if (scanner) scanner.stop();
    if (db) db.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ---------------------------------------------------------------------------
// Express server
// ---------------------------------------------------------------------------

function createServer(): express.Application {
  const app = express();

  app.use(cors());
  app.use(express.json());

  // -------------------------------------------------------------------------
  // Key registry
  // -------------------------------------------------------------------------

  /**
   * POST /keys/register
   * Body: { ethAddress: string, shadePublicKey: string }
   * Stores the mapping of 0x address → Shade public key.
   */
  app.post("/keys/register", (req, res) => {
    try {
      const { ethAddress, shadePublicKey } = req.body;

      if (!ethAddress || typeof ethAddress !== "string") {
        res.status(400).json({ error: "Missing or invalid ethAddress" });
        return;
      }
      if (!shadePublicKey || typeof shadePublicKey !== "string") {
        res.status(400).json({ error: "Missing or invalid shadePublicKey" });
        return;
      }
      if (!ethers.isAddress(ethAddress)) {
        res.status(400).json({ error: "Invalid Ethereum address format" });
        return;
      }

      db.registerKey(ethAddress, shadePublicKey);

      res.json({
        status: "ok",
        ethAddress: ethAddress.toLowerCase(),
        shadePublicKey,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  /**
   * GET /keys/:address
   * Returns the Shade public key for a given 0x address.
   */
  app.get("/keys/:address", (req, res) => {
    try {
      const { address } = req.params;

      if (!ethers.isAddress(address)) {
        res.status(400).json({ error: "Invalid Ethereum address format" });
        return;
      }

      const shadePublicKey = db.getKey(address);
      if (!shadePublicKey) {
        res.status(404).json({ error: "Address not registered" });
        return;
      }

      res.json({
        ethAddress: address.toLowerCase(),
        shadePublicKey,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  /**
   * GET /events?from=blockNumber
   * Returns all Shield/Transact/Nullified events since the given block number.
   */
  app.get("/events", (req, res) => {
    try {
      const from = parseInt(req.query.from as string, 10);
      if (isNaN(from) || from < 0) {
        res.status(400).json({ error: "Invalid or missing 'from' query parameter" });
        return;
      }

      const events = db.getEventsSince(from);

      const parsed = events.map((e) => ({
        id: e.id,
        blockNumber: e.blockNumber,
        txHash: e.txHash,
        eventType: e.eventType,
        data: JSON.parse(e.data),
      }));

      res.json({ events: parsed });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  // -------------------------------------------------------------------------
  // Merkle tree
  // -------------------------------------------------------------------------

  /**
   * GET /merkle/root
   * Returns the current Merkle root, leaf count, and tree number.
   */
  app.get("/merkle/root", (_req, res) => {
    try {
      const root = merkleTree.getRoot();
      const leafCount = merkleTree.getLeafCount();

      res.json({
        root: root.toString(),
        leafCount,
        treeNumber: 0,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  /**
   * GET /merkle/path/:leafIndex
   * Returns the Merkle authentication path for a given leaf index.
   */
  app.get("/merkle/path/:leafIndex", (req, res) => {
    try {
      const leafIndex = parseInt(req.params.leafIndex, 10);
      if (isNaN(leafIndex) || leafIndex < 0) {
        res.status(400).json({ error: "Invalid leaf index" });
        return;
      }

      if (leafIndex >= merkleTree.getLeafCount()) {
        res.status(404).json({
          error: `Leaf index ${leafIndex} not found (tree has ${merkleTree.getLeafCount()} leaves)`,
        });
        return;
      }

      const { pathElements, indices } = merkleTree.getPath(leafIndex);

      res.json({
        leafIndex,
        pathElements: pathElements.map((e) => e.toString()),
        indices,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: message });
    }
  });

  // -------------------------------------------------------------------------
  // Health
  // -------------------------------------------------------------------------

  /**
   * GET /health
   * Returns server health status.
   */
  app.get("/health", async (_req, res) => {
    try {
      const lastBlock = db.getLastScannedBlock();
      const leafCount = merkleTree.getLeafCount();

      res.json({
        status: "ok",
        lastBlock,
        leafCount,
        treeDepth: TREE_DEPTH,
        treeCapacity: 2 ** TREE_DEPTH,
        contractAddress: CONTRACT_ADDRESS || null,
        rpcUrl: RPC_URL,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(500).json({ status: "error", error: message });
    }
  });

  return app;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

main().catch((err) => {
  process.stderr.write(`[indexer] Fatal error: ${err}\n`);
  process.exit(1);
});
