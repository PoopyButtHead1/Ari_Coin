#---------
#Big Ideas
#---------

#phase 1: blocks and hashing
# Big Idea: Blockchains create security through the fact that each block references the hash of the previous block, forming an immutable chain. If one block is altered, its hash changes, breaking the chain and signaling tampering.
# This ensures data integrity and trustworthiness in decentralized systems.
# applications: cryptocurrencies, supply chain management, secure voting systems, digital identity verification, and decentralized finance (DeFi).
# people can change the chain but it will be obvious to everyone else that it has been changed

#phase 2: Transactions, wallets, and digital signatures
#in phase 1 anyone can add any transaction to the blockchain and be accepted as valid. Sooo... 
#phase 2 will make owners cryptographically sign their transactions to prove authenticity.
    #wallet: a pair of public and private keys and an adress derived from the public key
    #transactions: will include digital signatures created with the private key and verified with the public key if any part changes the signature will no longer be valid
    #rule enforcement: you can only spend what you have, and you must sign transactions with your private key
#install ecdsa
#ecdsa is a library for elliptic curve cryptography, used here for creating and verifying digital signatures.

#phase 3: Add mining making it expensive to create blocks through trial and error hashing while cheap to varify
#a nonce is added to the block data and miners repeatedly try different nonce values until they find a hash that meets a certain difficulty target (e.g., starts with a certain number of zeros).
#This proof-of-work mechanism secures the blockchain by making it computationally expensive to alter past blocks, as changing any block would require re-mining all subsequent blocks.
#witiout mining anyone could quickly create blocks and add them to the chain, undermining its security and trustworthiness.

#phase 4: multiple nodes, networking, consensus, forks, and attacks
#What happens when multiple copies of the blockchain exist across many computers (nodes) that communicate over a network?
#in a decentralized system, blocks will conflict 
#nodes: computers that maintain a independent copy of the blockchain and validate new blocks and transactions (its own miner, own wallet, own copy of the chain)
#consensus: nodes agree on the state of the blockchain using consensus algorithms (e.g., Proof of Work, Proof of Stake) The longest valid chain is accepted as the true chain!
#forks: occur when there are conflicting versions of the blockchain, leading to temporary splits until consensus is reached

#Phase 5: Networking, mempool, transaction propagation, and block propagation
#blocks dont just appear magically on every node they are built from transactions that users create and broadcast to the network
#transaction braodcasting: when a user creates a transaction, it is broadcasted to all nodes in the network
#mempool: each node maintains a mempool (memory pool) of unconfirmed transactions waiting
#block propagation: when a miner successfully mines a new block, it is broadcasted to all nodes for validation and addition to their local blockchain copy
#orphan handling: nodes may receive blocks that reference unknown previous blocks (orphans); these are stored temporarily until the missing blocks are received
#right now, if it doesnt attatch -> sync with peers to get the longest chain this isnt propper but it works for learning
#rebroadcasting/gossip: after accepting the transaction or block, nodes rebroadcast it to their peers to ensure network-wide propagation
#networking: nodes communicate over a peer-to-peer network to share blockchain data and updates

#Phase 6: Orphan Blocks and "try again later"
#when a node receives a block that references a previous block it doesn't have yet, it stores the orphan block temporarily
#once the missing previous block is received, the node can then validate and add the orphan block to its blockchain
#this ensures that blocks are not lost and the blockchain remains consistent across all nodes
#nodes may request missing blocks from their peers to complete their blockchain
#once the missing blocks are obtained, the node can validate and add the orphan blocks to its chain
#this mechanism helps maintain the integrity and continuity of the blockchain across the network
#before if a block arrived and it didnt attach we detected a fork and synced with peers

#important to know:
#Transaction broadcast
    #are signed by wallets
    #broadcast to peers
    #independently verified
    #stored in mempools
#Block broadcast
    #are mined locally
    #broadcast to peers
    #verified (hash + PoW + transactions)
    #appended or rejected


#---------
#to be discussed later:
# security considerations
#attacks: various threats to blockchain security, such as 51% attacks, double spending, and Sybil attacks
#---------

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
    return f"{tx.sender}|{tx.recipient}|{tx.amount}".encode()
#makes a transaction signable by converting its data to bytes


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
                        balance -= tx.amount
                    if tx.recipient == address:
                        balance += tx.amount
        return balance
    #calculates the balance for a given address by iterating through all transactions in the blockchain; adds amounts for received transactions and subtracts for sent transactions

    def is_proof_valid(self, block_hash: str) -> bool:
        return block_hash.startswith("0" * self.difficulty)

    def mine_block(self, transactions: List[Any], miner_address: str) -> Block:
    # Add coinbase reward to miner
        reward_tx = Transaction(
            sender=SYSTEM_SENDER,
            recipient=miner_address,
            amount=self.mining_reward
        )
        full_txs = [reward_tx] + transactions
    # Validate transactions (except SYSTEM minting)
        for tx in full_txs:
            if isinstance(tx, Transaction):
                if not verify_transaction(tx):
                    raise ValueError("Invalid transaction signature")
                if tx.sender != SYSTEM_SENDER and self.get_balance(tx.sender) < tx.amount:
                    raise ValueError("Insufficient balance")
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
    
#iterates through the chain starting from the second block; checks if each block's previous_hash matches the hash of the previous block; recomputes the hash of each block and compares it to the stored hash; returns True if all blocks are valid, otherwise False.



#each node has its own blockchain and can connect to other nodes as peers
class Node:
    def __init__(self, name: str, difficulty: int = 4):
        self.name = name
        self.blockchain = Blockchain(difficulty=difficulty)
        self.peers: list["Node"] = []
        self.mempool: list[Transaction] = []
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
        if verify_transaction(tx):
            self.mempool.append(tx)
            self.broadcast_transaction(tx)
            print(f"{self.name} accepted transaction")
        else:
            print(f"{self.name} rejected invalid transaction")
        if tx.sender != SYSTEM_SENDER and self.blockchain.get_balance(tx.sender) < tx.amount:
            print(f"{self.name} rejected: insufficient funds (mempool policy)")
        return

#method to receive and validate transactions; if valid, adds to mempool and broadcasts to peers

    def broadcast_transaction(self, tx: Transaction) -> None:
        for peer in self.peers:
            if tx not in peer.mempool:
                peer.receive_transaction(tx)
#method to broadcast a transaction to all connected peers
#now models gossip style propagation by checking if the peer already has the transaction in its mempool before sending it

    def mine(self, miner_address: str) -> None:
        if not self.mempool:
            print(f"{self.name}: no transactions to mine")
            return

        block = self.blockchain.mine_block(self.mempool, miner_address)
        self.mempool.clear()
        self.broadcast_block(block)
        print(f"{self.name} mined block {block.index}")
#method to mine a new block using transactions from the mempool; clears the mempool after mining and broadcasts the new block to peers

    def broadcast_block(self, block: Block) -> None:
        for peer in self.peers:
            peer.receive_block(block)
#method to broadcast a newly mined block to all connected peers

    def receive_block(self, block: Block) -> None:
        last = self.blockchain.last_block()

        # Case 1: normal extension
        if block.previous_hash == last.hash:
            self.blockchain.chain.append(block)
            self.mempool = [
                tx for tx in self.mempool if tx not in block.transactions
            ]
            print(f"{self.name} accepted block {block.index}")

            # After attaching, try to attach any waiting orphans
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




#prints the blockchain in a readable format
def print_chain(bc: Blockchain) -> None:
    for block in bc.chain:
        # Make blocks JSON-readable (Transaction objects handled in compute_hash, but not here)
        printable = asdict(block)
        cleaned = []
        for t in printable["transactions"]:
            if isinstance(t, dict):
                cleaned.append(t)
            else:
                cleaned.append(t)
        printable["transactions"] = cleaned
        print(json.dumps(printable, indent=2))

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
                    "sender": tx.sender,
                    "recipient": tx.recipient,
                    "amount": tx.amount,
                    "signature": tx.signature.hex() if tx.signature else None
                })
            else:
                printable["transactions"].append(tx)

        print(json.dumps(printable, indent=2))


# ----------------------------
# Demo
#function to demonstrate wallets and signed transactions
# ----------------------------

if __name__ == "__main__":
    # -------------------------
    # SETUP
    # -------------------------
    node_a = Node("Node A", difficulty=3)
    node_b = Node("Node B", difficulty=3)

    # Connect peers so transactions gossip
    node_a.connect_peer(node_b)
    node_b.connect_peer(node_a)

    miner_a = Wallet()
    miner_b = Wallet()
    alice = Wallet()
    bob = Wallet()

    print("\n=== STEP 1: Initial sync (Phase 4 behavior) ===")
    node_b.sync_with_peers()  # optional: makes sure both start aligned

    # -------------------------
    # STEP 2: Give Miner A funds by mining on A
    # -------------------------
    print("\n=== STEP 2: Node A mines a reward block (miner gets coins) ===")
    block1_a = node_a.blockchain.mine_block([], miner_a.address())
    print("Node A mined:", block1_a.index, "hash:", block1_a.hash[:12])

    # IMPORTANT: Don't auto-broadcast blocks yet; we will deliver them manually.
    # To prevent automatic block broadcast from other methods, we just won't call node_a.mine() here.

    # Manually deliver block1 to B (normal in-order delivery)
    node_b.receive_block(block1_a)

    # -------------------------
    # STEP 3: Transaction gossip (mempool)
    # -------------------------
    print("\n=== STEP 3: Transaction gossip (Miner A -> Alice 20) ===")
    tx1 = Transaction(sender=miner_a.address(), recipient=alice.address(), amount=20)
    sign_transaction(tx1, miner_a)

    # Send tx to Node A; it should gossip to Node B
    node_a.receive_transaction(tx1)

    print("Node A mempool size:", len(node_a.mempool))
    print("Node B mempool size:", len(node_b.mempool))

    # -------------------------
    # STEP 4: Mine a block on A that includes tx1
    # (We mine directly using Blockchain.mine_block to avoid auto-broadcast.)
    # -------------------------
    print("\n=== STEP 4: Node A mines a block including the mempool tx ===")
    block2_a = node_a.blockchain.mine_block(node_a.mempool, miner_a.address())
    node_a.mempool.clear()
    print("Node A mined:", block2_a.index, "hash:", block2_a.hash[:12])

    # -------------------------
    # STEP 5: ORPHAN DEMO (deliver out of order)
    # Deliver block2 BEFORE block1's successor is known on Node B.
    # We'll simulate this by resetting Node B to only genesis for a moment.
    # -------------------------
    print("\n=== STEP 5: Orphan block demo (deliver child before parent) ===")

    # Create a fresh Node C to show orphan behavior clearly (only genesis block)
    node_c = Node("Node C", difficulty=3)

    # Deliver block2 first (Node C doesn't have its parent hash)
    node_c.receive_block(block2_a)

    # Now deliver block1 (parent); Node C should accept it and then attach orphan
    node_c.receive_block(block1_a)

    print("Node C chain length:", len(node_c.blockchain.chain))
    print("Node C orphans stored:", len(getattr(node_c, "orphans", {})))

    # -------------------------
    # STEP 6: FORK DEMO (two nodes mine different blocks at same height)
    # Make Node B mine its own competing block at the same height as Node A's block2.
    # -------------------------
    print("\n=== STEP 6: Fork demo (Node B mines a competing block) ===")

    # At this moment, Node B has block1_a. It also has tx1 in mempool.
    # We'll let Node B mine a different block (maybe empty or with tx) to create a fork.
    # Mine directly to avoid auto-broadcast.
    block2_b = node_b.blockchain.mine_block(node_b.mempool, miner_b.address())
    node_b.mempool.clear()
    print("Node B mined competing:", block2_b.index, "hash:", block2_b.hash[:12])

    # Now Node B receives Node A's block2 (which conflicts with its own block2)
    node_b.receive_block(block2_a)

    # With your current logic, Node B may say "detected fork, syncing" here.
    # That’s okay—this demonstrates fork detection and recovery.

    # -------------------------
    # STEP 7: CONVERGENCE DEMO (Node A extends its chain, making it "stronger")
    # -------------------------
    print("\n=== STEP 7: Convergence demo (Node A mines one more block, then B syncs) ===")
    block3_a = node_a.blockchain.mine_block([], miner_a.address())
    print("Node A mined:", block3_a.index, "hash:", block3_a.hash[:12])

    # Deliver the new tip block to B
    node_b.receive_block(block3_a)

    # Force sync to show adoption of best chain if needed
    node_b.sync_with_peers()

    # -------------------------
    # FINAL STATE
    # -------------------------
    print("\n=== FINAL BALANCES (Node A view) ===")
    print("Miner A:", node_a.blockchain.get_balance(miner_a.address()))
    print("Miner B:", node_a.blockchain.get_balance(miner_b.address()))
    print("Alice:", node_a.blockchain.get_balance(alice.address()))
    print("Bob:", node_a.blockchain.get_balance(bob.address()))
    print("Blockchain valid (A)?", node_a.blockchain.is_valid())

    print("\n=== FINAL CHAIN LENGTHS ===")
    print("Node A chain length:", len(node_a.blockchain.chain))
    print("Node B chain length:", len(node_b.blockchain.chain))
    print("Node C chain length:", len(node_c.blockchain.chain))


"""
=== STEP 1: Initial sync (Phase 4 behavior) ===

=== STEP 2: Node A mines a reward block (miner gets coins) ===
Node A mined: 1 hash: 0005a3d20255
Node B accepted block 1

Node A mined the first PoW block (block 1).
Node B had the same genesis, so the parent hash matched its tip → it appended the block normally.

=== STEP 3: Transaction gossip (Miner A -> Alice 20) ===
Node B accepted transaction
Node A accepted transaction
Node A mempool size: 1
Node B mempool size: 1

=== STEP 4: Node A mines a block including the mempool tx ===
Node A mined: 2 hash: 000004f974f5

=== STEP 5: Orphan block demo (deliver child before parent) ===
Node C stored orphan block 2
Node C accepted block 1
Node C attached orphan block 2
Node C chain length: 3
Node C orphans stored: 0

=== STEP 6: Fork demo (Node B mines a competing block) ===
Node B mined competing: 2 hash: 0000efef134c
Node B detected fork, syncing

=== STEP 7: Convergence demo (Node A mines one more block, then B syncs) ===
Node A mined: 3 hash: 000e6f9c929e
Node B stored orphan block 3
Node B adopted Node A's chain

=== FINAL BALANCES (Node A view) ===
Miner A: 130
Miner B: 0
Alice: 20
Bob: 0
Blockchain valid (A)? True

=== FINAL CHAIN LENGTHS ===
Node A chain length: 4
Node B chain length: 4
Node C chain length: 3
"""