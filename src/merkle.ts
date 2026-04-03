import { buildPoseidon } from "circomlibjs";

type PoseidonFn = Awaited<ReturnType<typeof buildPoseidon>>;

/**
 * Binary Poseidon Merkle tree with incremental insertion.
 * Matches the on-chain Commitments.sol tree exactly.
 *
 * Depth 16 → capacity 2^16 = 65,536 leaves.
 */
export class MerkleTree {
  readonly depth: number;
  readonly capacity: number;
  readonly zeroValue: bigint;

  private poseidon: PoseidonFn;
  private leafCount: number;
  private filledSubtrees: bigint[];
  private zeroHashes: bigint[];
  private root: bigint;
  private leaves: bigint[];

  constructor(depth: number, zeroValue: bigint, poseidon: PoseidonFn) {
    this.depth = depth;
    this.capacity = 2 ** depth;
    this.zeroValue = zeroValue;
    this.poseidon = poseidon;
    this.leafCount = 0;
    this.leaves = [];

    // Precompute zero hashes for each level.
    // zeroHashes[0] = zeroValue (empty leaf)
    // zeroHashes[i] = Poseidon(zeroHashes[i-1], zeroHashes[i-1])
    this.zeroHashes = new Array(depth + 1);
    this.zeroHashes[0] = zeroValue;
    for (let i = 1; i <= depth; i++) {
      this.zeroHashes[i] = this.hash(this.zeroHashes[i - 1], this.zeroHashes[i - 1]);
    }

    // Initialize filled subtrees with zero hashes.
    // filledSubtrees[i] holds the latest finalized node at level i on the left side.
    this.filledSubtrees = new Array(depth);
    for (let i = 0; i < depth; i++) {
      this.filledSubtrees[i] = this.zeroHashes[i];
    }

    this.root = this.zeroHashes[depth];
  }

  /**
   * Poseidon hash of two field elements (matching PoseidonT3 on-chain).
   */
  private hash(left: bigint, right: bigint): bigint {
    const raw = this.poseidon([left, right]);
    return BigInt(this.poseidon.F.toString(raw));
  }

  /**
   * Insert a single leaf commitment into the tree.
   * Returns the leaf index where it was inserted.
   */
  insert(leaf: bigint): number {
    if (this.leafCount >= this.capacity) {
      throw new Error(`Merkle tree full (capacity ${this.capacity})`);
    }

    const index = this.leafCount;
    this.leaves.push(leaf);

    let currentIndex = index;
    let currentHash = leaf;

    for (let level = 0; level < this.depth; level++) {
      if (currentIndex % 2 === 0) {
        // Left child: pair with zero hash on the right.
        // Update the filled subtree at this level.
        this.filledSubtrees[level] = currentHash;
        currentHash = this.hash(currentHash, this.zeroHashes[level]);
      } else {
        // Right child: pair with the filled subtree on the left.
        currentHash = this.hash(this.filledSubtrees[level], currentHash);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.root = currentHash;
    this.leafCount++;

    return index;
  }

  /**
   * Insert a batch of leaves. Returns the starting leaf index.
   */
  insertBatch(leaves: bigint[]): number {
    if (leaves.length === 0) {
      return this.leafCount;
    }
    const startIndex = this.leafCount;
    for (const leaf of leaves) {
      this.insert(leaf);
    }
    return startIndex;
  }

  /**
   * Get the current Merkle root.
   */
  getRoot(): bigint {
    return this.root;
  }

  /**
   * Get the number of inserted leaves.
   */
  getLeafCount(): number {
    return this.leafCount;
  }

  /**
   * Compute the Merkle proof (authentication path) for a given leaf index.
   *
   * Returns:
   * - pathElements: sibling hashes from leaf to root
   * - indices: 0 or 1 indicating whether the node is a left (0) or right (1) child
   */
  getPath(leafIndex: number): { pathElements: bigint[]; indices: number[] } {
    if (leafIndex < 0 || leafIndex >= this.leafCount) {
      throw new Error(
        `Leaf index ${leafIndex} out of range [0, ${this.leafCount - 1}]`,
      );
    }

    // Rebuild the path by recomputing hashes from all leaves.
    // This is O(n) but correct. For production, a persistent storage
    // approach (storing all intermediate nodes) would be O(log n).
    const pathElements: bigint[] = [];
    const indices: number[] = [];

    // Build level 0: all leaf values, padded with zero values.
    let currentLevel: bigint[] = new Array(this.capacity);
    for (let i = 0; i < this.capacity; i++) {
      currentLevel[i] = i < this.leafCount ? this.leaves[i] : this.zeroValue;
    }

    let idx = leafIndex;
    for (let level = 0; level < this.depth; level++) {
      // Determine sibling
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;

      pathElements.push(currentLevel[siblingIdx]);
      indices.push(isRight ? 1 : 0);

      // Compute next level
      const nextLevelSize = currentLevel.length / 2;
      const nextLevel: bigint[] = new Array(nextLevelSize);
      for (let i = 0; i < nextLevelSize; i++) {
        nextLevel[i] = this.hash(currentLevel[2 * i], currentLevel[2 * i + 1]);
      }
      currentLevel = nextLevel;
      idx = Math.floor(idx / 2);
    }

    return { pathElements, indices };
  }
}

/**
 * Create and initialize a MerkleTree instance.
 * Must be async because circomlibjs Poseidon initialization is async.
 */
export async function createMerkleTree(
  depth: number,
  zeroValue: bigint,
): Promise<MerkleTree> {
  const poseidon = await buildPoseidon();
  return new MerkleTree(depth, zeroValue, poseidon);
}
