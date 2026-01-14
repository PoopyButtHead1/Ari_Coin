#---------
#Big Ideas
#---------
#phase 1 : blocks and hashing
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

#-------------
#imports
#-------------

import hashlib
#gives SHA-256 hashing which means it creates a 32 byte fingerprint of the input data with a 256 bit output 
#used for creating unique identifiers for blocks in the blockchain 
#A hash function takes an input (or 'message') and returns a fixed-size string of bytes.
import json
from dataclasses import dataclass, asdict
from operator import index
from time import time 
from typing import List, Any
from ecdsa import SigningKey, SECP256k1
import binascii
from ecdsa import VerifyingKey, BadSignatureError

SYSTEM_SENDER = "SYSTEM"


#-------------
#Data structures
#-------------

@dataclass
class Transaction:
    sender: str
    recipient: str
    amount: int
    signature: bytes | None = None
#defines a transaction structure with sender, recipient, amount, and an optional signature

@dataclass(frozen=True)
#creates a data container class 
#frozen=True makes the instances of the class immutable, meaning once an instance is created, its fields cannot be modified.
class Block:
    index: int # block numbers (0,1,2,...)
    timestamp: float #when the block was created
    transactions: List[Any] #list of transactions included in the block
    previous_hash: str #the hash of the previous block in the chain
    hash: str #the computed hash of the blocks content


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
        return binascii.hexlify(self.public_key.to_string()).decode()
#creates a wallet with a public/private key pair; can sign messages with the private key; can derive an address from the public key


def transaction_bytes(tx: Transaction) -> bytes:
    data = f"{tx.sender}{tx.recipient}{tx.amount}"
    return data.encode()
#makes a transaction signable by converting its data to bytes

def sign_transaction(tx: Transaction, wallet: Wallet) -> None:
    message = transaction_bytes(tx)
    tx.signature = wallet.sign(message)
#signs a transaction using the wallet's private key


def verify_transaction(tx: Transaction) -> bool:
    if tx.signature is None:
        return False

    try:
        public_key_bytes = binascii.unhexlify(tx.sender)
        vk = VerifyingKey.from_string(public_key_bytes, curve=SECP256k1)
        vk.verify(tx.signature, transaction_bytes(tx))
        return True
    except BadSignatureError:
        return False
#verifies a transaction's signature using the sender's public key; returns True if valid, False otherwise


#-----------
#Hashing and Blockchain core
#-----------

# a function to compute the SHA-256 hash of a block
def compute_hash(index: int, timestamp: float, transactions: List[Any], previous_hash: str) -> str:
    block_data = {
        'index': index,
        'timestamp': timestamp,
        'transactions': transactions,
        'previous_hash': previous_hash,
    }
    #builds the data we want in the fingerprint
    block_string = json.dumps(block_data, sort_keys=True, separators=(',', ':')).encode()
    #ensures consistent ordering of keys for hashing
    return hashlib.sha256(block_string).hexdigest()
    #returns the SHA-256 hash of the block data


class Blockchain:
    def __init__(self) -> None:
        self.chain: List[Block] = []
        self.create_genesis_block()
    # a block chain is a list of blocks
    #genisis block is the first block in the chain
    #creates the genesis block and appends it to the chain

    def create_genesis_block(self) -> None:
        index = 0
        timestamp = time()
        transactions = ["GENESIS"]
        previous_hash = "0" * 64
        block_hash = compute_hash(index, timestamp, transactions, previous_hash)

        genesis = Block(
            index=index,
            timestamp=timestamp,
            transactions=transactions,
            previous_hash=previous_hash,
            hash=block_hash,
        )
        self.chain.append(genesis)
    # helper to get the last block in the chain

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


    #new version Rejects fake signatures: Rejects fake signatures; Rejects overspending; Enforces ownership
    def add_block(self, transactions: List[Any]) -> Block:
        for tx in transactions:
            if isinstance(tx, Transaction):
                if not verify_transaction(tx):
                    raise ValueError("Invalid transaction signature")

            if self.get_balance(tx.sender) < tx.amount:
                raise ValueError("Insufficient balance")

        last = self.last_block()
        index = last.index + 1
        timestamp = time()
        previous_hash = last.hash
        block_hash = compute_hash(index, timestamp, transactions, previous_hash)

        new_block = Block(
        index=index,
        timestamp=timestamp,
        transactions=transactions,
        previous_hash=previous_hash,
        hash=block_hash,
    )
        self.chain.append(new_block)
        return new_block

    #Grab the last block; New block index = last index + 1; Previous hash = last block’s hash; Compute hash from this block’s data; Append it; Return it (useful for printing/debugging).
    # #validates the integrity of the blockchain
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
            )
            if current.hash != expected_hash:
                return False

        return True
#iterates through the chain starting from the second block; checks if each block's previous_hash matches the hash of the previous block; recomputes the hash of each block and compares it to the stored hash; returns True if all blocks are valid, otherwise False.

#prints the blockchain in a readable format
def print_chain(bc: Blockchain) -> None:
    for block in bc.chain:
        print(json.dumps(asdict(block), indent=2))

#new main function to demonstrate wallets and signed transactions
if __name__ == "__main__":
    bc = Blockchain()

    alice = Wallet()
    bob = Wallet()

    # Give Alice some starting funds (temporary hack)
    bc.add_block([
        Transaction(
            sender="SYSTEM",
            recipient=alice.address(),
            amount=100
        )
    ])

    tx1 = Transaction(
        sender=alice.address(),
        recipient=bob.address(),
        amount=30
    )
    sign_transaction(tx1, alice)

    bc.add_block([tx1])

    print("Alice balance:", bc.get_balance(alice.address()))
    print("Bob balance:", bc.get_balance(bob.address()))
    print("Blockchain valid?", bc.is_valid())
#creates wallets for Alice and Bob; gives Alice some initial funds; creates and signs a transaction from Alice to Bob; adds the transaction to the blockchain; prints the balances and validity of the blockchain.