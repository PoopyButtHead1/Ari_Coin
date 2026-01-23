import hashlib
#gives SHA-256 hashing which means it creates a 32 byte fingerprint of the input data with a 256 bit output 
#used for creating unique identifiers for blocks in the blockchain 
#A hash function takes an input (or 'message') and returns a fixed-size string of bytes.
import json
import binascii
from dataclasses import dataclass, asdict
from operator import index
from time import time
from typing import List, Any, Optional

from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError


SYSTEM_SENDER = "SYSTEM"


# ----------------------------
# Data structures
# ----------------------------

@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    fee: int = 0 #add fee
    signature: Optional[bytes] = None
#defines a transaction structure with sender, recipient, amount, and an optional signature

@dataclass(frozen=True)
class Block:
    index: int
    timestamp: float
    transactions: List[Any]
    previous_hash: str
    nonce: int 
    hash: str
#creates a data container class 
#frozen=True makes the instances of the class immutable, meaning once an instance is created, its fields cannot be modified.
#nonce is included for future proofing for mining implementation


# ----------------------------
# Crypto helpers
# ----------------------------

class Wallet:
    def __init__(self):
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def address(self) -> str:
        # address = hex-encoded public key bytes (simple for learning)
        return binascii.hexlify(self.public_key.to_string()).decode()
#creates a wallet with a public/private key pair; can sign messages with the private key; can derive an address from the public key


def transaction_bytes(tx: Transaction) -> bytes:
    # Deterministic encoding (simple version)
    return f"{tx.sender}|{tx.recipient}|{tx.amount}|{tx.fee}".encode()
#makes a transaction signable by converting its data to bytes
#if fee isnt signed someone could raise it without sellers consent 

def sign_transaction(tx: Transaction, wallet: Wallet) -> None:
    tx.signature = wallet.sign(transaction_bytes(tx))
#signs a transaction using the wallet's private key


def verify_transaction(tx: Transaction) -> bool:
    # Allow system minting transactions (genesis funding / mining rewards later)
    if tx.sender == SYSTEM_SENDER:
        return True

    if tx.signature is None:
        return False

    try:
        public_key_bytes = binascii.unhexlify(tx.sender)
        vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        vk.verify(tx.signature, transaction_bytes(tx))
        return True
    except (BadSignatureError, binascii.Error, ValueError):
        return False
#verifies a transaction's signature using the sender's public key; returns True if valid, False otherwise

def txid(tx: Transaction) -> str:
    # tx identity should include signature so that changing signature changes identity
    sig = tx.signature.hex() if tx.signature else ""
    s = f"{tx.sender}|{tx.recipient}|{tx.amount}|{tx.fee}|{sig}"
    return hashlib.sha256(s.encode()).hexdigest()

def tx_size_bytes(tx: Transaction) -> int:
    # toy estimate: size is length of the signable payload + signature bytes
    base = len(transaction_bytes(tx))
    sig_len = len(tx.signature) if tx.signature else 0
    return base + sig_len

def fee_rate(tx: Transaction) -> float:
    sz = tx_size_bytes(tx)
    return tx.fee / sz if sz > 0 else 0.0



# ----------------------------
# Hashing / blockchain core
# ----------------------------

# a function to compute the SHA-256 hash of a block
def compute_hash(index: int, timestamp: float, transactions: List[Any], previous_hash: str, nonce: int) -> str:
    # Convert Transaction objects to JSON-safe dicts for hashing
    txs_normalized = []
    for t in transactions:
        if isinstance(t, Transaction):
            txs_normalized.append({
                "sender": t.sender,
                "recipient": t.recipient,
                "amount": t.amount,
                "fee": t.fee, #prevents someone from changing fee without changing block hash 
                # signature is bytes -> hex for stable hashing
                "signature": t.signature.hex() if t.signature else None
            })
        else:
            txs_normalized.append(t)

    block_data = {
        "index": index,
        "timestamp": timestamp,
        "transactions": txs_normalized,
        "previous_hash": previous_hash,
        "nonce": nonce,
    }
    #builds the data we want in the fingerprint

    block_string = json.dumps(block_data, sort_keys=True, separators=(",", ":")).encode()
    #ensures consistent ordering of keys for hashing
    return hashlib.sha256(block_string).hexdigest()
    #returns the SHA-256 hash of the block data
    #by including nonce we prepare for future mining implementation 
    #nonce is a number that miners change to find a hash that meets certain criteria (like a number of leading zeros)
    #this makes it computationally expensive to create blocks while easy to verify them
    #nonce must affect the hash, otherwise “mining” wouldn’t do anything.


class Blockchain:
    def __init__(self, difficulty: int = 4, mining_reward: int = 50) -> None:
            self.chain: List[Block] = []
            self.difficulty = difficulty
            self.mining_reward = mining_reward
            self.create_genesis_block()
    # this defines the difficulty to mine blocks
    #Difficulty 4 means “hash starts with 4 zeros” — fast enough to test.
    # a block chain is a list of blocks
    #genisis block is the first block in the chain
    #creates the genesis block and appends it to the chain

    def create_genesis_block(self) -> None:
        index = 0
        timestamp = 0.0 #fixed timestamp for genesis block so that the hash stays the same making it possible for the nodes to attach blocks 
        transactions = ["GENESIS"]
        previous_hash = "0" * 64
        nonce = 0 #nonce for genesis block
        block_hash = compute_hash(index, timestamp, transactions, previous_hash, nonce)

        genesis = Block(
            index=index,
            timestamp=timestamp,
            transactions=transactions,
            previous_hash=previous_hash,
            nonce=nonce, #Added p3
            hash=block_hash,
        )
        self.chain.append(genesis)

    def last_block(self) -> Block:
        return self.chain[-1]

    def get_balance(self, address: str) -> int:
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if isinstance(tx, Transaction):
                    if tx.sender == address:
                        balance -= (tx.amount + tx.fee) #fee comes out of sellers balance
                    if tx.recipient == address:
                        balance += tx.amount
        return balance
    #calculates the balance for a given address by iterating through all transactions in the blockchain; adds amounts for received transactions and subtracts for sent transactions

    def is_proof_valid(self, block_hash: str) -> bool:
        return block_hash.startswith("0" * self.difficulty)

    def mine_block(self, transactions: List[Any], miner_address: str) -> Block:
    #compute total fees
        total_fees = 0
        for tx in transactions:
            if isinstance(tx, Transaction):
                total_fees += tx.fee

    # Add coinbase reward to miner
        reward_tx = Transaction(
            sender=SYSTEM_SENDER,
            recipient=miner_address,
            amount=self.mining_reward + total_fees,
            fee=0,
            signature=None,
        )

        #Coinbase first
        full_txs = [reward_tx] + transactions

    # Validate transactions (except SYSTEM minting)
    # Validate transactions using a temp balance view (prevents intra-block overspend)
        temp_bal: dict[str, int] = {}

        def bal(addr: str) -> int:
            if addr not in temp_bal:
                temp_bal[addr] = self.get_balance(addr)
            return temp_bal[addr]

        for tx in full_txs:
            if not isinstance(tx, Transaction):
                continue

            if not verify_transaction(tx):
                raise ValueError("Invalid transaction signature")

            # Skip balance accounting for SYSTEM minting tx (coinbase)
            if tx.sender == SYSTEM_SENDER:
                continue

            cost = tx.amount + tx.fee
            if bal(tx.sender) < cost:
                raise ValueError("Insufficient balance")

            # apply tx to temp balances
            temp_bal[tx.sender] = bal(tx.sender) - cost
            temp_bal[tx.recipient] = bal(tx.recipient) + tx.amount


        last = self.last_block()
        index = last.index + 1
        timestamp = time()
        previous_hash = last.hash

        # Proof of Work loop
        nonce = 0
        while True:
            block_hash = compute_hash(index, timestamp, full_txs, previous_hash, nonce)
            if self.is_proof_valid(block_hash):
                break
            nonce += 1
        new_block = Block(
            index=index,
            timestamp=timestamp,
            transactions=full_txs,
            previous_hash=previous_hash,
            nonce=nonce,
            hash=block_hash,
        )
        self.chain.append(new_block)
        return new_block
    #Miner always gets a reward transaction first
    #Then we repeatedly try nonces until hash meets target
    #When it matches, we append that block

    #Rejects fake signatures: Rejects fake signatures; Rejects overspending; Enforces ownership
    #Grab the last block; New block index = last index + 1; Previous hash = last block’s hash; Compute hash from this block’s data; Append it; Return it (useful for printing/debugging).
    #validates the integrity of the blockchain
    #add block is no longer necessarey anymore because mining now adds blocks with proof of work and reward transactions

    def chain_work(self) -> int:
    # Simple version: work = number of blocks (difficulty fixed)
        return len(self.chain)
#compares the current chain with another chain and replaces it if the other chain is longer and valid; returns True if the chain was replaced, otherwise False


    def replace_chain_if_better(self, other_chain: list[Block]) -> bool:
        if len(other_chain) <= len(self.chain):
            return False

    # Temporarily swap and validate
        original_chain = self.chain
        self.chain = other_chain

        if self.is_valid():
            return True
        else:
            self.chain = original_chain
            return False
#validates the integrity of the blockchain


    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Rule 1: the block must correctly point to the previous block
            if current.previous_hash != previous.hash:
                return False

            # Rule 2: the stored hash must match a fresh recomputation
            expected_hash = compute_hash(
                current.index,
                current.timestamp,
                current.transactions,
                current.previous_hash,
                current.nonce,
            )
            if current.hash != expected_hash:
                return False

            # NEW: proof-of-work target must be met for non-genesis blocks
            if i != 0 and not self.is_proof_valid(current.hash):
                return False

        return True



    def validate_block(self, block: Block) -> bool:

        temp_bal: dict[str, int] = {}

        def bal(addr: str) -> int:
            if addr not in temp_bal:
                temp_bal[addr] = self.get_balance(addr)
            return temp_bal[addr]



        # 1) prev hash must match our tip (for "normal extension" case)
        if block.previous_hash != self.last_block().hash:
            return False

        # 2) recompute hash must match stored hash
        expected_hash = compute_hash(
            block.index,
            block.timestamp,
            block.transactions,
            block.previous_hash,
            block.nonce,
        )
        if block.hash != expected_hash:
            return False

        # 3) PoW must be valid
        if not self.is_proof_valid(block.hash):
            return False

        # 4) transaction rules + coinbase correctness
        # coinbase must be first tx and must be SYSTEM_SENDER
        if not block.transactions or not isinstance(block.transactions[0], Transaction):
            return False
        coinbase = block.transactions[0]
        if coinbase.sender != SYSTEM_SENDER:
            return False

        # verify all signatures + no overspend
        # we simulate balances by replaying chain + this block (toy approach).
        # For speed/realism you'd use a UTXO set, but your code is account-style.
        total_fees = 0

        for tx in block.transactions[1:]:
            if not isinstance(tx, Transaction):
                return False
            if not verify_transaction(tx):
                return False

            cost = tx.amount + tx.fee
            if bal(tx.sender) < cost:
                return False

            #apply tx to temp balances so later txs see updated balances 
            temp_bal[tx.sender] = bal(tx.sender) - cost
            temp_bal[tx.recipient] = bal(tx.recipient) +tx.amount

            total_fees += tx.fee

        # coinbase payout must equal subsidy + total fees
        expected_reward = self.mining_reward + total_fees
        if coinbase.amount != expected_reward:
            return False

        return True
#iterates through the chain starting from the second block; checks if each block's previous_hash matches the hash of the previous block; recomputes the hash of each block and compares it to the stored hash; returns True if all blocks are valid, otherwise False.




#---------------
# Networking / Nodes
#---------------

#each node has its own blockchain and can connect to other nodes as peers
MAX_BLOCK_BYTES =1200
MIN_FEE_RATE = 0.0

class Node:   
    def __init__(self, name: str, difficulty: int = 4):
        self.name = name
        self.blockchain = Blockchain(difficulty=difficulty)
        self.peers: list["Node"] = []
        self.mempool: list[Transaction] = []
        self.mempool_ids: set[str] =set()
        self.orphans: dict[str, Block] = {}
        #orphan block is just a valid block without a parent yet 
#initializes a node with a name, its own blockchain, and an empty list of peers
    
    def connect_peer(self, peer: "Node") -> None:
        self.peers.append(peer)
#method to connect another node as a peer

    def try_attach_orphans(self) -> None:
        attached = True

        while attached:
            attached = False
            last_hash = self.blockchain.last_block().hash

            for orphan_hash, orphan in list(self.orphans.items()):
                if orphan.previous_hash == last_hash:
                    self.blockchain.chain.append(orphan)
                    del self.orphans[orphan_hash]
                    print(f"{self.name} attached orphan block {orphan.index}")
                    attached = True
                    break
#tries attatching orphan blocks to the chain if their previous hash matches the last block's hash; continues until no more orphans can be attached

    def receive_transaction(self, tx: Transaction) -> None:

        # 1) Signature check
        if not verify_transaction(tx):
            print(f"{self.name} rejected invalid transaction")
            return

        # 2) Funds check (mempool policy) — Phase 7 includes fees
        if tx.sender != SYSTEM_SENDER:
            cost = tx.amount + tx.fee
            if self.blockchain.get_balance(tx.sender) < cost:
                print(f"{self.name} rejected: insufficient funds (mempool policy)")
                return

        # 3) Dedup by txid (NOT object identity)
        tid = txid(tx)
        if tid in self.mempool_ids:
            return

        # 4) Accept + gossip
        self.mempool.append(tx)
        self.mempool_ids.add(tid)
        print(f"{self.name} accepted transaction")
        self.broadcast_transaction(tx)
#method to receive and validate transactions; if valid, adds to mempool and broadcasts to peers

    def broadcast_transaction(self, tx: Transaction) -> None:
        tid = txid(tx)
        for peer in self.peers:
            if tid not in peer.mempool_ids:
                peer.receive_transaction(tx)
#method to broadcast a transaction to all connected peers
#now models gossip style propagation by checking if the peer already has the transaction in its mempool before sending it

    def select_txs_for_block(self, mempool: list[Transaction]) -> list[Transaction]:
        """
        Miner policy: choose highest fee-rate txs that fit in MAX_BLOCK_BYTES.
        """
        # sort by fee rate descending
        candidates = sorted(mempool, key=lambda t: fee_rate(t), reverse=True)

        selected: list[Transaction] = []
        used = 0

        for tx in candidates:
            fr = fee_rate(tx)
            if fr < MIN_FEE_RATE:
                break  # since sorted, everything after is worse

            sz = tx_size_bytes(tx)
            if used + sz > MAX_BLOCK_BYTES:
                continue  # maybe smaller txs still fit later

            selected.append(tx)
            used += sz

        return selected
#--------------------

    def mine(self, miner_address: str) -> None:
        if not self.mempool:
            print(f"{self.name}: no transactions to mine")
            return

        selected = self.select_txs_for_block(self.mempool)
        if not selected:
            print(f"{self.name}: nothing meets fee-rate / size policy")
            return

        block = self.blockchain.mine_block(selected, miner_address)

        # remove only the selected txs from mempool
        selected_ids = {txid(t) for t in selected}

        for tid in selected_ids:
            self.mempool_ids.discard(tid)

        self.mempool = [tx for tx in self.mempool if txid(tx) not in selected_ids]

        self.broadcast_block(block)
        print(f"{self.name} mined block {block.index} with {len(selected)} txs")


    def broadcast_block(self, block: Block) -> None:
        for peer in self.peers:
            peer.receive_block(block)
#method to broadcast a newly mined block to all connected peers

    def receive_block(self, block: Block) -> None:
        last = self.blockchain.last_block()

        # Case 1: normal extension
        if block.previous_hash == last.hash:
            # ✅ NEW: validate before accept
            if not self.blockchain.validate_block(block):
                print(f"{self.name} rejected invalid block {block.index}")
                return

            self.blockchain.chain.append(block)
            # ✅ remove confirmed txs from mempool AND mempool_ids
            block_ids = {txid(t) for t in block.transactions if isinstance(t, Transaction)}
            self.mempool = [tx for tx in self.mempool if txid(tx) not in block_ids]
            for tid in block_ids:
                self.mempool_ids.discard(tid)

            print(f"{self.name} accepted block {block.index}")

            self.try_attach_orphans()
            return

        # Case 2: parent missing → orphan
        known_hashes = {b.hash for b in self.blockchain.chain}
        if block.previous_hash not in known_hashes:
            self.orphans[block.hash] = block
            print(f"{self.name} stored orphan block {block.index}")
            return
        
        # Case 3: parent exists but not the tip → fork
        print(f"{self.name} detected fork, syncing")
        self.sync_with_peers()
#method to receive a new block; if it extends the current chain, appends it and removes included transactions from the mempool; if it creates a fork, initiates synchronization with peers

    def sync_with_peers(self) -> None:
        for peer in self.peers:
            replaced = self.blockchain.replace_chain_if_better(peer.blockchain.chain)
            if replaced:
                self.orphans.clear()
                print(f"{self.name} adopted {peer.name}'s chain")
#peer synchronization method to adopt the longest valid chain from connected peers




# ----------------------------
# Utility functions
# ----------------------------

#prints full blockchain with proper transaction formatting
def print_chain(bc: Blockchain) -> None:
    for block in bc.chain:
        printable = {
            "index": block.index,
            "timestamp": block.timestamp,
            "previous_hash": block.previous_hash,
            "nonce": block.nonce,
            "hash": block.hash,
            "transactions": []
        }

        for tx in block.transactions:
            if isinstance(tx, Transaction):
                printable["transactions"].append({
                    "txid": txid(tx),
                    "sender": tx.sender,
                    "recipient": tx.recipient,
                    "amount": tx.amount,
                    "fee": tx.fee,
                    "fee_rate": fee_rate(tx),
                    "signature": tx.signature.hex() if tx.signature else None
                })
            else:
                printable["transactions"].append(tx)

        print(json.dumps(printable, indent=2))



# ----------------------------
# Demo
#function to demonstrate wallets and signed transactions
# ----------------------------


# ----------------------------
# DEMO: Phase 8 end-to-end
# Paste this at the bottom of your file
# ----------------------------

def describe_block(block: Block) -> None:
    print("\n=== BLOCK ===")
    print(f"index={block.index} hash={block.hash[:12]}.. prev={block.previous_hash[:12]}.. nonce={block.nonce}")
    fees = 0
    for i, tx in enumerate(block.transactions):
        if isinstance(tx, Transaction):
            fees += tx.fee
            print(f"  tx[{i}] sender={tx.sender[:10]}.. -> {tx.recipient[:10]}.. "
                  f"amt={tx.amount} fee={tx.fee} feerate={fee_rate(tx):.3f} txid={txid(tx)[:12]}..")
        else:
            print(f"  tx[{i}] {tx}")
    print(f"  (sum fees in block txs) = {fees}")
    print("=============\n")


def run_phase8_demo():
    print("\n\n==============================")
    print("PHASE 8 DEMO START")
    print("==============================\n")

    # Make mining fast for a demo
    # (Difficulty 3 is usually quick; adjust if needed.)
    A = Node("A", difficulty=3)
    B = Node("B", difficulty=3)
    C = Node("C", difficulty=3)

    # Connect peers (simple mesh)
    A.connect_peer(B)
    A.connect_peer(C)
    B.connect_peer(A)
    B.connect_peer(C)
    C.connect_peer(A)
    C.connect_peer(B)

    # Wallets
    minerA = Wallet()
    minerB = Wallet()
    alice = Wallet()
    bob = Wallet()
    carol = Wallet()

    addr_minerA = minerA.address()
    addr_minerB = minerB.address()
    addr_alice = alice.address()
    addr_bob = bob.address()
    addr_carol = carol.address()

    print("Addresses:")
    print(" minerA:", addr_minerA[:16], "...")
    print(" minerB:", addr_minerB[:16], "...")
    print(" alice :", addr_alice[:16], "...")
    print(" bob   :", addr_bob[:16], "...")
    print(" carol :", addr_carol[:16], "...\n")

    # ---------------------------------------------------------
    # 1) FUNDING via SYSTEM tx (no signature required)
    # ---------------------------------------------------------
    print("1) Funding Alice and Bob (realistic): mine rewards to minerA, then signed payments...")

    # Give minerA funds by mining a few empty reward blocks directly
    # (Node.mine() requires mempool txs, so we call blockchain.mine_block)
    for _ in range(5):
        blk = A.blockchain.mine_block([], addr_minerA)
        A.broadcast_block(blk)

    print("MinerA balance after reward blocks:", A.blockchain.get_balance(addr_minerA))

    # minerA pays Alice and Bob using NORMAL signed transactions
    pay_alice = Transaction(sender=addr_minerA, recipient=addr_alice, amount=120, fee=5)
    sign_transaction(pay_alice, minerA)

    pay_bob = Transaction(sender=addr_minerA, recipient=addr_bob, amount=80, fee=3)
    sign_transaction(pay_bob, minerA)

    A.receive_transaction(pay_alice)
    A.receive_transaction(pay_bob)

    # Mine them into a block
    A.mine(addr_minerA)

    print("Balances after funding:")
    print("  MinerA:", A.blockchain.get_balance(addr_minerA))
    print("  Alice :", A.blockchain.get_balance(addr_alice))
    print("  Bob   :", A.blockchain.get_balance(addr_bob))
    print()


    # ---------------------------------------------------------
    # 2) Signatures: valid tx accepted, invalid signature rejected
    # ---------------------------------------------------------
    print("2) Signature enforcement: create one valid signed tx and one invalid unsigned tx...")

    tx_valid = Transaction(sender=addr_alice, recipient=addr_bob, amount=10, fee=2)
    sign_transaction(tx_valid, alice)  # ✅ signed

    tx_invalid = Transaction(sender=addr_alice, recipient=addr_bob, amount=1, fee=1)
    # ❌ NOT signing tx_invalid

    B.receive_transaction(tx_valid)     # should be accepted + gossiped
    B.receive_transaction(tx_invalid)   # should be rejected

    print("\nCurrent mempool sizes (should include tx_valid, not tx_invalid):")
    print("  A mempool:", len(A.mempool))
    print("  B mempool:", len(B.mempool))
    print("  C mempool:", len(C.mempool))
    print()

    # ---------------------------------------------------------
    # 3) Mempool txid dedup: send same tx again
    # ---------------------------------------------------------
    print("3) Mempool txid dedup: rebroadcast the SAME tx_valid again (should not duplicate)...")
    B.receive_transaction(tx_valid)

    print("Mempool sizes after duplicate rebroadcast (should be unchanged):")
    print("  A mempool:", len(A.mempool))
    print("  B mempool:", len(B.mempool))
    print("  C mempool:", len(C.mempool))
    print()

    # ---------------------------------------------------------
    # 4) Fee market + selection under MAX_BLOCK_BYTES
    #    Create multiple signed txs with different fees and let miner choose
    # ---------------------------------------------------------
    print("4) Fee market: create multiple txs with different fees; miner picks by fee-rate under block bytes...")

    # Make the block tight so not everything fits
    global MAX_BLOCK_BYTES, MIN_FEE_RATE
    MAX_BLOCK_BYTES = 550     # tight
    MIN_FEE_RATE = 0.0        # allow all, selection decides

    tx1 = Transaction(sender=addr_alice, recipient=addr_carol, amount=5, fee=1)
    sign_transaction(tx1, alice)

    tx2 = Transaction(sender=addr_alice, recipient=addr_carol, amount=6, fee=15)  # high fee
    sign_transaction(tx2, alice)

    tx3 = Transaction(sender=addr_bob, recipient=addr_carol, amount=3, fee=4)
    sign_transaction(tx3, bob)

    # Broadcast txs into network via C
    C.receive_transaction(tx1)
    C.receive_transaction(tx2)
    C.receive_transaction(tx3)

    print("\nFee rates (sat/byte-ish):")
    for t in [tx1, tx2, tx3]:
        print(f"  {txid(t)[:10]}.. fee={t.fee} size={tx_size_bytes(t)} feerate={fee_rate(t):.3f}")

    print("\nNow B mines a block (minerB). It should include the highest fee-rate txs that fit.")
    B.mine(addr_minerB)

    # Show the latest block from B’s chain
    describe_block(B.blockchain.last_block())

    print("Balances after minerB block:")
    print("  Alice :", B.blockchain.get_balance(addr_alice))
    print("  Bob   :", B.blockchain.get_balance(addr_bob))
    print("  Carol :", B.blockchain.get_balance(addr_carol))
    print("  MinerB:", B.blockchain.get_balance(addr_minerB))
    print("\n(Notice minerB increased by subsidy + sum(fees) in that block.)\n")

    # ---------------------------------------------------------
    # 5) Validation: demonstrate that tampering breaks acceptance
    #    (Change a block after mining -> hash mismatch -> reject)
    # ---------------------------------------------------------
    print("5) Block validation: craft an INVALID extension of B's tip and show rejection...")

    # We will send to B a block that CLAIMS to extend B's current tip,
    # but has an incorrect hash (does not match its contents).
    tip = B.blockchain.last_block()

    # Build a "fake" next block
    fake_index = tip.index + 1
    fake_ts = time()

    # include one tx from mempool if available, otherwise empty list
    fake_txs = []
    if B.mempool:
        fake_txs = [B.mempool[0]]

    # coinbase must be first (otherwise validate_block fails earlier)
    coinbase = Transaction(sender=SYSTEM_SENDER, recipient=addr_minerB, amount=50, fee=0, signature=None)
    full_txs = [coinbase] + fake_txs

    # Choose a nonce and compute a VALID PoW hash...
    nonce = 0
    while True:
        good_hash = compute_hash(fake_index, fake_ts, full_txs, tip.hash, nonce)
        if good_hash.startswith("0" * B.blockchain.difficulty):
            break
        nonce += 1

    # ...then tamper by storing the WRONG hash (guaranteed invalid)
    tampered_hash = "f" * 64  # definitely won't match recomputation and also fails PoW

    evil = Block(
    index=fake_index,
    timestamp=fake_ts,
    transactions=full_txs,
    previous_hash=tip.hash,   # IMPORTANT: extends B's TIP
    nonce=nonce,
    hash=tampered_hash,       # WRONG on purpose
)

    # Now B will hit Case 1 (normal extension) and reject as invalid
    B.receive_block(evil)

    print("\nIf you saw 'rejected invalid block', validation is working.\n")



    # ---------------------------------------------------------
    # 6) Orphan blocks: send child before parent, then parent, observe attachment
    # ---------------------------------------------------------
    print("6) Orphan handling demo: send a block whose parent is unknown, store as orphan, then send parent...")

    # We'll craft a fake "parent" block that properly extends C's tip,
    # and a "child" block that references that parent.
    # Note: your orphan attachment code appends orphans without validating them (learning simplification).
    tip = C.blockchain.last_block()

    # Create a parent block that extends C's tip by actually mining it using C's blockchain:
    parent = C.blockchain.mine_block([], addr_minerA)  # mines on C, extends its chain

    # Create a child block referencing parent (we will send child to A BEFORE parent)
    child_index = parent.index + 1
    child_prev = parent.hash
    child_ts = time()
    child_txs = ["ORPHAN_CHILD_DEMO"]  # doesn't matter; orphan storage doesn't validate
    child_nonce = 0

    # Mine a PoW-valid hash for the child to make it look real
    while True:
        h = compute_hash(child_index, child_ts, child_txs, child_prev, child_nonce)
        if h.startswith("0" * A.blockchain.difficulty):
            break
        child_nonce += 1

    child = Block(
        index=child_index,
        timestamp=child_ts,
        transactions=child_txs,
        previous_hash=child_prev,
        nonce=child_nonce,
        hash=h
    )

    # Send child to A first -> A should store orphan
    A.receive_block(child)

    # Now send parent to A -> A should accept, then attach orphan
    A.receive_block(parent)

    print("\nIf you saw 'stored orphan block' then later 'attached orphan block', orphan handling works.\n")

    print("==============================")
    print("PHASE 8 DEMO END")
    print("==============================\n")


# Run the demo
if __name__ == "__main__":
    run_phase8_demo()
