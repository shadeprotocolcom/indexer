import { ethers } from "ethers";
import { buildPoseidon } from "circomlibjs";
import type { ShadeDatabase, EventType } from "./database.js";
import type { MerkleTree } from "./merkle.js";

type PoseidonFn = Awaited<ReturnType<typeof buildPoseidon>>;

/**
 * BN254 SNARK scalar field prime.
 */
const SNARK_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * ABI fragments for ShadePool events.
 *
 * Event signatures (RAILGUN-compatible):
 * - Shield(uint256 treeNumber, uint256 startPosition, tuple[] commitments, tuple[] shieldCiphertext, uint256[] fees)
 * - Transact(uint256 treeNumber, uint256 startPosition, bytes32[] hash, tuple[] ciphertext)
 * - Nullified(uint16 treeNumber, bytes32[] nullifier)
 */
const SHADE_POOL_ABI = [
  `event Shield(
    uint256 treeNumber,
    uint256 startPosition,
    tuple(
      bytes32 npk,
      tuple(uint8 tokenType, address tokenAddress, uint256 tokenSubID) token,
      uint120 value
    )[] commitments,
    tuple(
      bytes32[3] encryptedBundle,
      bytes32 shieldKey
    )[] shieldCiphertext,
    uint256[] fees
  )`,
  `event Transact(
    uint256 treeNumber,
    uint256 startPosition,
    bytes32[] hash,
    tuple(
      bytes32[4] ciphertext,
      bytes32 blindedSenderViewingKey,
      bytes32 blindedReceiverViewingKey,
      bytes annotationData,
      bytes memo
    )[] ciphertext
  )`,
  `event Nullified(
    uint16 treeNumber,
    bytes32[] nullifier
  )`,
];

/**
 * Decoded event with optional commitment values for tree insertion.
 */
interface DecodedEvent {
  blockNumber: number;
  txHash: string;
  logIndex: number;
  eventType: EventType;
  data: Record<string, unknown>;
  commitments?: bigint[];
}

/**
 * Event scanner that polls the Citrea mainnet for ShadePool contract events.
 */
export class EventScanner {
  private provider: ethers.JsonRpcProvider;
  private contract: ethers.Contract;
  private db: ShadeDatabase;
  private merkleTree: MerkleTree;
  private poseidon: PoseidonFn;
  private pollInterval: number;
  private running: boolean;
  private pollTimer: ReturnType<typeof setTimeout> | null;

  constructor(config: {
    rpcUrl: string;
    contractAddress: string;
    db: ShadeDatabase;
    merkleTree: MerkleTree;
    poseidon: PoseidonFn;
    pollInterval?: number;
  }) {
    this.provider = new ethers.JsonRpcProvider(config.rpcUrl);
    this.contract = new ethers.Contract(
      config.contractAddress,
      SHADE_POOL_ABI,
      this.provider,
    );
    this.db = config.db;
    this.merkleTree = config.merkleTree;
    this.poseidon = config.poseidon;
    this.pollInterval = config.pollInterval ?? 2000;
    this.running = false;
    this.pollTimer = null;
  }

  /**
   * Start the event scanning loop.
   */
  async start(deploymentBlock?: number): Promise<void> {
    this.running = true;

    // Determine the starting block.
    let lastBlock = this.db.getLastScannedBlock();
    if (lastBlock === 0 && deploymentBlock && deploymentBlock > 0) {
      lastBlock = deploymentBlock - 1;
      this.db.setLastScannedBlock(lastBlock);
    }

    // Rebuild the Merkle tree from stored commitments on startup.
    this.rebuildMerkleTree();

    process.stdout.write(
      `[scanner] Starting from block ${lastBlock + 1}, ` +
        `tree has ${this.merkleTree.getLeafCount()} leaves\n`,
    );

    this.poll();
  }

  /**
   * Stop the event scanning loop.
   */
  stop(): void {
    this.running = false;
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /**
   * Get the last block number from the chain.
   */
  async getLatestBlock(): Promise<number> {
    return await this.provider.getBlockNumber();
  }

  /**
   * Rebuild the in-memory Merkle tree from all stored commitments.
   */
  private rebuildMerkleTree(): void {
    const commitments = this.db.getAllCommitments();
    if (commitments.length > 0) {
      const leaves = commitments.map((c) => BigInt(c.commitment));
      this.merkleTree.insertBatch(leaves);
    }
  }

  /**
   * The main polling loop.
   */
  private async poll(): Promise<void> {
    if (!this.running) return;

    try {
      const latestBlock = await this.provider.getBlockNumber();
      const fromBlock = this.db.getLastScannedBlock() + 1;

      if (fromBlock <= latestBlock) {
        const chunkSize = 2000;
        let currentFrom = fromBlock;

        while (currentFrom <= latestBlock && this.running) {
          const currentTo = Math.min(currentFrom + chunkSize - 1, latestBlock);
          await this.scanRange(currentFrom, currentTo);
          this.db.setLastScannedBlock(currentTo);
          currentFrom = currentTo + 1;
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[scanner] Poll error: ${message}\n`);
    }

    if (this.running) {
      this.pollTimer = setTimeout(() => this.poll(), this.pollInterval);
    }
  }

  /**
   * Scan a specific block range for events, store them, and update the Merkle tree.
   */
  private async scanRange(fromBlock: number, toBlock: number): Promise<void> {
    const events = await this.fetchEvents(fromBlock, toBlock);

    for (const event of events) {
      this.db.insertEvent({
        blockNumber: event.blockNumber,
        txHash: event.txHash,
        eventType: event.eventType,
        data: JSON.stringify(event.data),
      });

      if (event.commitments && event.commitments.length > 0) {
        for (const commitment of event.commitments) {
          const leafIndex = this.merkleTree.insert(commitment);
          this.db.insertCommitment(leafIndex, commitment.toString());
        }
      }
    }

    if (events.length > 0) {
      process.stdout.write(
        `[scanner] Blocks ${fromBlock}-${toBlock}: ${events.length} events, ` +
          `tree now has ${this.merkleTree.getLeafCount()} leaves\n`,
      );
    }
  }

  /**
   * Fetch and decode all ShadePool events in a block range.
   */
  private async fetchEvents(
    fromBlock: number,
    toBlock: number,
  ): Promise<DecodedEvent[]> {
    const decoded: DecodedEvent[] = [];

    // Fetch all three event types in parallel.
    const [shieldLogs, transactLogs, nullifiedLogs] = await Promise.all([
      this.fetchShieldEvents(fromBlock, toBlock),
      this.fetchTransactEvents(fromBlock, toBlock),
      this.fetchNullifiedEvents(fromBlock, toBlock),
    ]);

    decoded.push(...shieldLogs, ...transactLogs, ...nullifiedLogs);

    // Sort by block number and log index for deterministic ordering.
    decoded.sort((a, b) =>
      a.blockNumber !== b.blockNumber
        ? a.blockNumber - b.blockNumber
        : a.logIndex - b.logIndex,
    );

    return decoded;
  }

  /**
   * Fetch and decode Shield events.
   */
  private async fetchShieldEvents(
    fromBlock: number,
    toBlock: number,
  ): Promise<DecodedEvent[]> {
    const decoded: DecodedEvent[] = [];

    try {
      const filter = this.contract.filters.Shield();
      const logs = await this.contract.queryFilter(filter, fromBlock, toBlock);

      for (const log of logs) {
        const eventLog = log as ethers.EventLog;
        const parsed = this.contract.interface.parseLog({
          topics: eventLog.topics as string[],
          data: eventLog.data,
        });
        if (!parsed) continue;

        const treeNumber = Number(parsed.args[0]);
        const startPosition = Number(parsed.args[1]);
        const commitmentPreimages = parsed.args[2];
        const shieldCiphertexts = parsed.args[3];
        const fees = parsed.args[4];

        const commitments: bigint[] = [];
        const preimageData: Array<Record<string, unknown>> = [];

        for (let i = 0; i < commitmentPreimages.length; i++) {
          const preimage = commitmentPreimages[i];
          const npk = BigInt(preimage.npk);
          const tokenType = Number(preimage.token.tokenType);
          const tokenAddress: string = preimage.token.tokenAddress;
          const tokenSubID = BigInt(preimage.token.tokenSubID);
          const value = BigInt(preimage.value);

          // Compute token hash: keccak256(abi.encodePacked(tokenType, tokenAddress, tokenSubID)) % SNARK_FIELD
          const tokenHash = computeTokenHash(tokenType, tokenAddress, tokenSubID);

          // Compute commitment = Poseidon(npk, tokenHash, value)
          const commitmentRaw = this.poseidon([npk, tokenHash, value]);
          const commitment = BigInt(this.poseidon.F.toString(commitmentRaw));
          commitments.push(commitment);

          const ciphertext =
            i < shieldCiphertexts.length
              ? {
                  encryptedBundle: Array.from(shieldCiphertexts[i].encryptedBundle),
                  shieldKey: shieldCiphertexts[i].shieldKey,
                }
              : null;

          preimageData.push({
            npk: npk.toString(),
            tokenType,
            tokenAddress,
            tokenSubID: tokenSubID.toString(),
            value: value.toString(),
            commitment: commitment.toString(),
            ciphertext,
          });
        }

        decoded.push({
          blockNumber: eventLog.blockNumber,
          txHash: eventLog.transactionHash,
          logIndex: eventLog.index,
          eventType: "Shield",
          data: {
            treeNumber,
            startPosition,
            preimages: preimageData,
            fees: fees.map((f: bigint) => f.toString()),
          },
          commitments,
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[scanner] Error fetching Shield events: ${message}\n`);
    }

    return decoded;
  }

  /**
   * Fetch and decode Transact events.
   * The Transact event directly emits commitment hashes in the `hash` array.
   */
  private async fetchTransactEvents(
    fromBlock: number,
    toBlock: number,
  ): Promise<DecodedEvent[]> {
    const decoded: DecodedEvent[] = [];

    try {
      const filter = this.contract.filters.Transact();
      const logs = await this.contract.queryFilter(filter, fromBlock, toBlock);

      for (const log of logs) {
        const eventLog = log as ethers.EventLog;
        const parsed = this.contract.interface.parseLog({
          topics: eventLog.topics as string[],
          data: eventLog.data,
        });
        if (!parsed) continue;

        const treeNumber = Number(parsed.args[0]);
        const startPosition = Number(parsed.args[1]);
        const hashes: string[] = parsed.args[2].map((h: string) => h);
        const ciphertexts = parsed.args[3];

        const commitments = hashes.map((h) => BigInt(h));

        const ciphertextData = ciphertexts.map(
          (ct: {
            ciphertext: string[];
            blindedSenderViewingKey: string;
            blindedReceiverViewingKey: string;
            annotationData: string;
            memo: string;
          }) => ({
            ciphertext: ct.ciphertext.map((c: string) => c),
            blindedSenderViewingKey: ct.blindedSenderViewingKey,
            blindedReceiverViewingKey: ct.blindedReceiverViewingKey,
            annotationData: ct.annotationData,
            memo: ct.memo,
          }),
        );

        decoded.push({
          blockNumber: eventLog.blockNumber,
          txHash: eventLog.transactionHash,
          logIndex: eventLog.index,
          eventType: "Transact",
          data: {
            treeNumber,
            startPosition,
            hashes,
            ciphertexts: ciphertextData,
          },
          commitments,
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[scanner] Error fetching Transact events: ${message}\n`);
    }

    return decoded;
  }

  /**
   * Fetch and decode Nullified events.
   * Nullified events do not produce new commitments.
   */
  private async fetchNullifiedEvents(
    fromBlock: number,
    toBlock: number,
  ): Promise<DecodedEvent[]> {
    const decoded: DecodedEvent[] = [];

    try {
      const filter = this.contract.filters.Nullified();
      const logs = await this.contract.queryFilter(filter, fromBlock, toBlock);

      for (const log of logs) {
        const eventLog = log as ethers.EventLog;
        const parsed = this.contract.interface.parseLog({
          topics: eventLog.topics as string[],
          data: eventLog.data,
        });
        if (!parsed) continue;

        const treeNumber = Number(parsed.args[0]);
        const nullifiers: string[] = parsed.args[1].map((n: string) => n);

        decoded.push({
          blockNumber: eventLog.blockNumber,
          txHash: eventLog.transactionHash,
          logIndex: eventLog.index,
          eventType: "Nullified",
          data: {
            treeNumber,
            nullifiers,
          },
          commitments: undefined,
        });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[scanner] Error fetching Nullified events: ${message}\n`);
    }

    return decoded;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Compute the token hash matching the on-chain computation:
 * keccak256(abi.encodePacked(tokenType, tokenAddress, tokenSubID)) % SNARK_FIELD
 */
function computeTokenHash(
  tokenType: number,
  tokenAddress: string,
  tokenSubID: bigint,
): bigint {
  const packed = ethers.solidityPacked(
    ["uint8", "address", "uint256"],
    [tokenType, tokenAddress, tokenSubID],
  );
  const hash = ethers.keccak256(packed);
  return BigInt(hash) % SNARK_FIELD;
}
