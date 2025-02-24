import concurrent.futures
import json
from contextlib import contextmanager
from hashlib import sha256

import base58
import psycopg2
from bech32 import bech32_encode, convertbits
from Crypto.Hash import RIPEMD160
from loguru import logger
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.errors import BulkWriteError
from pymongo.results import InsertManyResult  # noqa: TC002

# Consts
PAGE_SIZE = 1000
MAX_THREADS = 10

# MongoDB setup
MONGO_URL = "mongodb://localhost:27017/"
MONGO_DB_NAME = "bitcoin_db"
MONGO_COLLECTION_NAME = "unique_addresses"

# PostgreSQL setup
PG_HOST = "localhost"
PG_PORT = "5433"
PG_USER = "postgres"
PG_PASS = "postgres"  # noqa: S105
PG_DB = "blocks_demo"


@contextmanager
def get_mongo_collection():  # noqa: ANN201
    mongo_client = MongoClient(MONGO_URL)
    mongo_db = mongo_client[MONGO_DB_NAME]
    mongo_collection = mongo_db[MONGO_COLLECTION_NAME]

    # Create the index when entering the context
    mongo_collection.create_index([("address", 1)], unique=True)

    try:
        yield mongo_collection  # Yield the collection for usage in the context block
    finally:
        mongo_client.close()  # Ensure the MongoDB client is closed


@contextmanager
def get_pg_connection():  # noqa: ANN201
    pg_conn = psycopg2.connect(
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASS,
        host=PG_HOST,
        port=PG_PORT,
    )
    pg_cursor = pg_conn.cursor()
    try:
        yield pg_cursor  # Yield the cursor for usage in the context block
    finally:
        pg_cursor.close()  # Ensure cursor is closed
        pg_conn.close()  # Ensure connection is closed


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
def get_addresses_from_postgre(task_id: int, pg_cursor, offest: int, limit: int) -> list[str]:  # noqa: ANN001
    logger.info(f"task: {task_id}, offest: {offest}, limit: {limit}")

    # Fetch addresses from txouts (scriptpubkey)
    pg_cursor.execute(f"""
        SELECT scriptpubkey
        FROM public.txouts
        WHERE scriptpubkey IS NOT NULL
        LIMIT {limit}
        OFFSET {offest};
    """)  # noqa: S608
    txout_addresses = [[row[0].tobytes()] for row in pg_cursor.fetchall()]

    # Fetch addresses from txins (scriptsig, witness)
    pg_cursor.execute(f"""
        SELECT scriptsig, witness
        FROM public.txins
        WHERE scriptsig IS NOT NULL AND witness IS NOT NULL
        LIMIT {limit}
        OFFSET {offest * limit}
    """)  # noqa: S608
    txin_addresses = [[row[0].tobytes(), row[1].tobytes()] for row in pg_cursor.fetchall()]

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

    return all_addresses


# Function to write to MongoDB
def write_addresses_to_mongo(task_id: int, mongo_collection: Collection, addresses: list[str]) -> None:
    logger.info(f"task: {task_id}")

    try:
        if addresses:
            res: InsertManyResult = mongo_collection.insert_many(
                [{"address": address} for address in addresses],
                ordered=False,
            )
            logger.info(f"task: {task_id}, {len(res.inserted_ids)} addresses written to MongoDB.")
        else:
            logger.info(f"task: {task_id}, No addresses written to MongoDB.")
    except BulkWriteError as e:
        error_details = json.dumps(e.details, indent=2, default=str)
        logger.error(f"task: {task_id}, Failed to write addresses to MongoDB: {error_details}")


def process_address_task(task_id: int, offset: int, limit: int) -> None:
    logger.info(f"task: {task_id}, offset: {offset}, limit: {limit}")

    page_limit = (limit + PAGE_SIZE - 1) // PAGE_SIZE
    with get_pg_connection() as pg_cursor, get_mongo_collection() as mongo_collection:
        for page_number in range(page_limit):
            addresses = get_addresses_from_postgre(
                task_id=task_id,
                pg_cursor=pg_cursor,
                offest=offset + page_number * PAGE_SIZE,
                limit=PAGE_SIZE,
            )
            write_addresses_to_mongo(
                task_id=task_id,
                mongo_collection=mongo_collection,
                addresses=addresses,
            )


def main() -> None:
    # Set up Index & Unique
    with get_mongo_collection() as mongo_collection:
        mongo_collection.create_index([("address", 1)], unique=True)

    # Get Page Size
    with get_pg_connection() as pg_cursor:
        pg_cursor.execute("SELECT COUNT(*) FROM public.txouts")
        row_count_txouts = pg_cursor.fetchone()[0]

        pg_cursor.execute("SELECT COUNT(*) FROM public.txins")
        row_count_txins = pg_cursor.fetchone()[0]

        max_rows = max(row_count_txins, row_count_txouts)

    # Process Address Concurrently
    rows_per_thread = (max_rows + MAX_THREADS - 1) // MAX_THREADS
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        executor.map(
            process_address_task,
            list(range(MAX_THREADS)),
            [i * rows_per_thread for i in range(MAX_THREADS)],
            [rows_per_thread for _ in range(MAX_THREADS)],
        )


if __name__ == "__main__":
    main()
