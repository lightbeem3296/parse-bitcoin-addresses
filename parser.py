import json
from hashlib import sha256
from typing import Any

import base58
import psycopg2
from bech32 import bech32_encode, convertbits
from Crypto.Hash import RIPEMD160
from loguru import logger
from pymongo import MongoClient
from pymongo.errors import BulkWriteError
from pymongo.results import InsertManyResult  # noqa: TC002

# Consts
BATCH_SIZE = 100

# MongoDB setup
MONGO_CLIENT: MongoClient[dict[str, Any]] = MongoClient("mongodb://localhost:27017/")
MONGO_DB = MONGO_CLIENT["bitcoin_db"]
MONGO_COLLECTION = MONGO_DB["unique_addresses"]

# PostgreSQL setup
PG_CONN = psycopg2.connect(
    dbname="blocks_demo",
    user="postgres",  # replace with your PostgreSQL username
    password="postgres",  # replace with your PostgreSQL password  # noqa: S106
    host="localhost",  # replace with your PostgreSQL host if different
    port="5433",  # replace with your PostgreSQL port if different
)

PG_CURSOR = PG_CONN.cursor()


# Address extraction functions in Python


def encode_segwit(hrp: str, witprog: bytes) -> str:
    # Convert the witness program into the required 5-bit groups
    converted = convertbits(witprog, 8, 5, pad=False)
    if not converted:
        msg = "Invalid witness program"
        raise ValueError(msg)
    # Encode into Bech32
    return bech32_encode(hrp, converted)


def digest(data: bytes | None, hash_type: str) -> bytes:
    if not data:
        return b""
    if hash_type == "sha256":
        return sha256(data).digest()
    if hash_type == "ripemd160":
        h = RIPEMD160.new()  # Correct usage of pycryptodome's RIPEMD160
        h.update(data)
        return h.digest()
    return b""


def encode_p2wpkh(pubkey: bytes) -> str:
    # Encode P2WPKH address using bech32
    return encode_segwit("bc", digest(pubkey, "ripemd160"))


def encode_p2wsh(sha256_hash: bytes) -> str:
    # Encode P2WSH address using bech32
    return encode_segwit("bc", sha256_hash)


def extract_address_from_scriptpubkey(scriptpubkey: bytes) -> str | None:  # noqa: PLR0911
    if scriptpubkey[:3] == b"\x76\xa9\x14":  # P2PKH (Pay-to-PubKey-Hash)
        return base58.b58encode_check(b"\x00" + scriptpubkey[3:23]).decode(
            "utf-8"
        )  # Add prefix for Mainnet address (0x00)
    if scriptpubkey[:2] == b"\xa9\x14":  # P2SH (Pay-to-Script-Hash)
        return base58.b58encode_check(b"\x05" + scriptpubkey[2:22]).decode("utf-8")  # Add prefix for P2SH (0x05)
    if scriptpubkey[:2] == b"\x00\x14":  # P2WPKH (Pay-to-Witness-PubKey-Hash)
        # Bech32 encoding for P2WPKH address
        hrp = "bc"  # Human-readable prefix for Bitcoin mainnet (bc)
        witness_program = scriptpubkey[2:22]
        return encode_segwit(hrp, witness_program)  # Bech32 encoding
    if scriptpubkey[:2] == b"\x00\x20":  # P2WSH (Pay-to-Witness-Script-Hash)
        # Bech32 encoding for P2WSH address
        hrp = "bc"  # Human-readable prefix for Bitcoin mainnet (bc)
        witness_program = scriptpubkey[2:34]
        return encode_segwit(hrp, witness_program)  # Bech32 encoding
    if scriptpubkey[:1] == b"\x41":  # P2PK (Pay-to-PubKey) - Length byte + public key
        # P2PK directly pays to a public key (not often used in addresses)
        # Not commonly seen in plain text Bitcoin addresses
        return None
    if scriptpubkey[:1] == b"\x51":  # P2TR (Taproot)
        # Bech32m encoding for Taproot addresses (bc1p)
        hrp = "bc"  # Human-readable prefix for Bitcoin mainnet (bc)
        witness_program = scriptpubkey[1:33]
        return encode_segwit(hrp, witness_program)  # Bech32m encoding
    return None


def extract_address_from_scriptsig_and_witness(scriptsig: bytes, witness: bytes) -> str | None:
    if not scriptsig:  # Native SegWit: P2WSH or P2WPKH
        wits = parse_witness(witness)
        pub = wits[-1] if wits else None
        if pub:
            sha = digest(pub, "sha256")
            if len(wits) == 2 and len(pub) == 33:  # Likely a P2WPKH  # noqa: PLR2004
                return encode_p2wpkh(pub)
            # Likely a P2WSH
            return encode_p2wsh(sha)
    else:
        # Handle non-SegWit cases (P2PKH, P2SH, etc.)
        length = ord(scriptsig[0:1])
        if length == len(scriptsig) - 1:  # Likely a P2SH (or P2SH-P2W*)
            return base58.b58encode(digest(digest(scriptsig[1:], "sha256"), "ripemd160")).decode()
        pos = 0
        while pos < len(scriptsig) - 1:
            op = ord(scriptsig[pos : pos + 1])
            if op > 0 and op < 76:  # Length-prefixed data  # noqa: PLR2004
                length = op
                pos += 1
            elif op == 76:  # OP_PUSHDATA1  # noqa: PLR2004
                length = ord(scriptsig[pos + 1 : pos + 2])
                pos += 2
            elif op == 77:  # OP_PUSHDATA2  # noqa: PLR2004
                length = ord(scriptsig[pos + 1 : pos + 2]) + ord(scriptsig[pos + 2 : pos + 3]) * 256
                pos += 3
            else:
                pos += 1
            pub = scriptsig[pos + 1 : pos + length + 1]
            pos += length
        return base58.b58encode(digest(digest(pub, "sha256"), "ripemd160")).decode()

    return None


def parse_witness(witness: bytes) -> list[bytes]:
    # Parse witness data (assuming witness is a list of byte sequences)
    # Adjust based on actual data structure
    return [witness]


# Function to fetch addresses
def get_addresses(offset: int, batch_size: int) -> tuple[list[str], bool]:
    # Fetch addresses from txouts (scriptpubkey)
    PG_CURSOR.execute(f"""
        SELECT scriptpubkey
        FROM public.txouts
        WHERE scriptpubkey IS NOT NULL
        LIMIT {batch_size}
        OFFSET {offset};
    """)  # noqa: S608
    txout_addresses = [[row[0].tobytes()] for row in PG_CURSOR.fetchall()]

    # Fetch addresses from txins (scriptsig, witness)
    PG_CURSOR.execute(f"""
        SELECT scriptsig, witness
        FROM public.txins
        WHERE scriptsig IS NOT NULL AND witness IS NOT NULL
        LIMIT {batch_size}
        OFFSET {offset}
    """)  # noqa: S608
    txin_addresses = [[row[0].tobytes(), row[1].tobytes()] for row in PG_CURSOR.fetchall()]

    all_addresses: list[str] = []

    # Process txouts (scriptpubkey)
    for row in txout_addresses:
        scriptpubkey = row[0]
        address = extract_address_from_scriptpubkey(scriptpubkey)
        if address:
            all_addresses.append(address)

    # Process txins (scriptsig, witness)
    for row in txin_addresses:
        scriptsig, witness = row
        address = extract_address_from_scriptsig_and_witness(scriptsig, witness)
        if address:
            all_addresses.append(address)

    return all_addresses, len(txout_addresses) == batch_size or len(txin_addresses) == batch_size


# Function to write to MongoDB
def write_addresses_to_mongo(addresses: list[str]) -> None:
    try:
        if addresses:
            res: InsertManyResult = MONGO_COLLECTION.insert_many(
                [{"address": address} for address in addresses],
                ordered=False,
            )
            logger.info(f"{len(res.inserted_ids)} addresses written to MongoDB.")
        else:
            logger.info("No addresses written to MongoDB.")
    except BulkWriteError as e:
        logger.error(f"Failed to write addresses to MongoDB: {json.dumps(e.details, indent=2, default=str)}")


def process_address(offset: int, batch_size: int) -> bool:
    ret = False

    addresses, ret = get_addresses(offset=offset, batch_size=batch_size)
    write_addresses_to_mongo(addresses)
    logger.info(f"{len(addresses)} unique addresses written to MongoDB.")

    return ret


def main() -> None:
    # Set up Index & Unique
    MONGO_COLLECTION.create_index([("address", 1)], unique=True)

    # Process Address
    offset = 0
    batch_size = BATCH_SIZE
    while True:
        logger.info(f"offset: {offset}, batch_size: {batch_size}")
        if not process_address(offset=offset, batch_size=batch_size):
            break
        offset += batch_size

    # Close connections
    PG_CURSOR.close()
    PG_CONN.close()
    MONGO_CLIENT.close()


if __name__ == "__main__":
    main()
