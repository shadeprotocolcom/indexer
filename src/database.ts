import Database from "better-sqlite3";
import path from "node:path";

/**
 * Event types emitted by the ShadePool contract.
 */
export type EventType = "Shield" | "Transact" | "Nullified";

/**
 * An on-chain event stored in the database.
 */
export interface StoredEvent {
  id: number;
  blockNumber: number;
  txHash: string;
  eventType: EventType;
  data: string;
}

/**
 * A commitment (Merkle leaf) stored in the database.
 */
export interface StoredCommitment {
  leafIndex: number;
  commitment: string;
}

/**
 * A registered key mapping.
 */
export interface StoredKey {
  ethAddress: string;
  shadePublicKey: string;
  registeredAt: string;
}

/**
 * SQLite database wrapper for the Shade indexer.
 */
export class ShadeDatabase {
  private db: Database.Database;

  constructor(dbPath?: string) {
    const resolvedPath = dbPath ?? path.join(process.cwd(), "shade-indexer.db");
    this.db = new Database(resolvedPath);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.init();
  }

  /**
   * Create tables if they do not exist.
   */
  private init(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blockNumber INTEGER NOT NULL,
        txHash TEXT NOT NULL,
        eventType TEXT NOT NULL CHECK(eventType IN ('Shield', 'Transact', 'Nullified')),
        data TEXT NOT NULL
      );

      CREATE INDEX IF NOT EXISTS idx_events_block ON events(blockNumber);
      CREATE INDEX IF NOT EXISTS idx_events_type ON events(eventType);

      CREATE TABLE IF NOT EXISTS merkle_tree (
        leafIndex INTEGER PRIMARY KEY,
        commitment TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS keys (
        ethAddress TEXT PRIMARY KEY COLLATE NOCASE,
        shadePublicKey TEXT NOT NULL,
        registeredAt TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
    `);

    // Seed last_scanned_block if not present.
    const existing = this.db
      .prepare("SELECT value FROM meta WHERE key = 'last_scanned_block'")
      .get() as { value: string } | undefined;
    if (!existing) {
      this.db
        .prepare("INSERT INTO meta (key, value) VALUES ('last_scanned_block', '0')")
        .run();
    }
  }

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  /**
   * Insert a contract event into the database.
   */
  insertEvent(event: {
    blockNumber: number;
    txHash: string;
    eventType: EventType;
    data: string;
  }): void {
    this.db
      .prepare(
        "INSERT INTO events (blockNumber, txHash, eventType, data) VALUES (?, ?, ?, ?)",
      )
      .run(event.blockNumber, event.txHash, event.eventType, event.data);
  }

  /**
   * Get all events since (and including) a given block number.
   */
  getEventsSince(blockNumber: number): StoredEvent[] {
    return this.db
      .prepare("SELECT * FROM events WHERE blockNumber >= ? ORDER BY blockNumber ASC, id ASC")
      .all(blockNumber) as StoredEvent[];
  }

  /**
   * Get events filtered by type since a given block number.
   */
  getEventsByTypeSince(eventType: EventType, blockNumber: number): StoredEvent[] {
    return this.db
      .prepare(
        "SELECT * FROM events WHERE eventType = ? AND blockNumber >= ? ORDER BY blockNumber ASC, id ASC",
      )
      .all(eventType, blockNumber) as StoredEvent[];
  }

  // ---------------------------------------------------------------------------
  // Merkle tree
  // ---------------------------------------------------------------------------

  /**
   * Insert a commitment (Merkle leaf) into the database.
   */
  insertCommitment(leafIndex: number, commitment: string): void {
    this.db
      .prepare("INSERT OR REPLACE INTO merkle_tree (leafIndex, commitment) VALUES (?, ?)")
      .run(leafIndex, commitment);
  }

  /**
   * Get all commitments ordered by leaf index.
   */
  getAllCommitments(): StoredCommitment[] {
    return this.db
      .prepare("SELECT leafIndex, commitment FROM merkle_tree ORDER BY leafIndex ASC")
      .all() as StoredCommitment[];
  }

  /**
   * Get the total number of commitments.
   */
  getCommitmentCount(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) as count FROM merkle_tree")
      .get() as { count: number };
    return row.count;
  }

  // ---------------------------------------------------------------------------
  // Key registry
  // ---------------------------------------------------------------------------

  /**
   * Register or update an Ethereum address → Shade public key mapping.
   */
  registerKey(ethAddress: string, shadePublicKey: string): void {
    this.db
      .prepare(
        `INSERT INTO keys (ethAddress, shadePublicKey) VALUES (?, ?)
         ON CONFLICT(ethAddress) DO UPDATE SET shadePublicKey = excluded.shadePublicKey, registeredAt = datetime('now')`,
      )
      .run(ethAddress.toLowerCase(), shadePublicKey);
  }

  /**
   * Look up the Shade public key for a given Ethereum address.
   * Returns null if not registered.
   */
  getKey(ethAddress: string): string | null {
    const row = this.db
      .prepare("SELECT shadePublicKey FROM keys WHERE ethAddress = ?")
      .get(ethAddress.toLowerCase()) as { shadePublicKey: string } | undefined;
    return row?.shadePublicKey ?? null;
  }

  // ---------------------------------------------------------------------------
  // Scan progress
  // ---------------------------------------------------------------------------

  /**
   * Get the last block number that was fully scanned.
   */
  getLastScannedBlock(): number {
    const row = this.db
      .prepare("SELECT value FROM meta WHERE key = 'last_scanned_block'")
      .get() as { value: string };
    return parseInt(row.value, 10);
  }

  /**
   * Update the last scanned block number.
   */
  setLastScannedBlock(block: number): void {
    this.db
      .prepare("UPDATE meta SET value = ? WHERE key = 'last_scanned_block'")
      .run(block.toString());
  }

  /**
   * Close the database connection.
   */
  close(): void {
    this.db.close();
  }
}
