import json
from typing import List, Dict, Tuple
from dataclasses import dataclass, asdict
import typer
from eth_utils import keccak
from eth_abi import encode, decode
from py_ecc.bls.g2_primitives import pubkey_to_G1
from pathlib import Path
from kzg_base import *
from web3 import Web3

from py_ecc.optimized_bls12_381.optimized_curve import normalize


app = typer.Typer()

BLOB_LENGTH = 4096
STORAGE_FILE = Path("blob_storage.json")

REVERSED_ROOTS_FILE = Path("bit_reversed_roots.json")


def dump_reversed_roots():
    reversed_roots = [int(x) for x in bit_reversal_permutation(ROOTS_OF_UNITY)]
    with open(REVERSED_ROOTS_FILE, "w") as f:
        json.dump(reversed_roots, f)
    print(f"✅ Bit-reversed roots dumped to {REVERSED_ROOTS_FILE}")


@app.command()
def dumproots():
    """Dump bit-reversed ROOTS_OF_UNITY to file."""
    dump_reversed_roots()


@dataclass
class G1Point:
    x: Tuple[int, int]  # (a, b)
    y: Tuple[int, int]  # (a, b)

    def to_dict(self):
        return {
            "X": {"a": self.x[0], "b": self.x[1]},
            "Y": {"a": self.y[0], "b": self.y[1]},
        }

    @staticmethod
    def from_dict(d):
        return G1Point(x=(d["X"]["a"], d["X"]["b"]), y=(d["Y"]["a"], d["Y"]["b"]))

    def encode(self) -> bytes:
        return (
            self.x[0].to_bytes(32, "big")
            + self.x[1].to_bytes(32, "big")
            + self.y[0].to_bytes(32, "big")
            + self.y[1].to_bytes(32, "big")
        )


@dataclass
class UserInfo:
    address: bytes  # bytes20 地址，和合约一致
    value: int  # uint256
    root_of_unity: int  # uint256
    lagrange_setup: G1Point  # 包含 4 个 uint256
    proof: bytes  # bytes

    def encode(self) -> bytes:
        return encode(
            [
                "address",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
                "uint256",
            ],
            [
                self.address,
                self.value,
                self.root_of_unity,
                self.lagrange_setup.x[0],  # X.a
                self.lagrange_setup.x[1],  # X.b
                self.lagrange_setup.y[0],  # Y.a
                self.lagrange_setup.y[1],  # Y.b
            ],
        )

    def hash(self) -> bytes:
        return hash_to_bls_field(self.encode()).to_bytes(32, "big")


@dataclass
class BlobState:
    blob: List[bytes]  # List[bytes32]，hash 结果
    user_index_map: Dict[str, int]  # key = 用户标识字符串（如 "user1"）
    user_info_list: List[UserInfo]
    current_index: int
    commitment: bytes = b""

    def to_json(self, commitment: bytes = b"") -> str:
        data = {
            "blob": [b.hex() for b in self.blob],
            "user_index_map": self.user_index_map,
            "user_info_list": [
                {
                    "address": u.address.hex(),
                    "value": u.value,
                    "root_of_unity": u.root_of_unity,
                    "lagrange_setup": u.lagrange_setup.to_dict(),
                    "proof": u.proof.hex(),
                }
                for u in self.user_info_list
            ],
            "current_index": self.current_index,
            "commitment": (commitment or self.commitment).hex(),
        }

        for i, u in enumerate(self.user_info_list):
            expected = u.hash()
            if self.blob[i] != expected:
                raise ValueError(
                    f"Hash mismatch at index {i}: expected {expected.hex()} vs actual {self.blob[i].hex()}"
                )

        return json.dumps(data, indent=2)

    @staticmethod
    def from_json(data: str) -> "BlobState":
        raw = json.loads(data)
        return BlobState(
            blob=[bytes.fromhex(b) for b in raw["blob"]],
            user_index_map=raw["user_index_map"],
            user_info_list=[
                UserInfo(
                    address=bytes.fromhex(u["address"]),
                    value=u["value"],
                    root_of_unity=u["root_of_unity"],
                    lagrange_setup=G1Point.from_dict(u["lagrange_setup"]),
                    proof=bytes.fromhex(u["proof"]),
                )
                for u in raw["user_info_list"]
            ],
            current_index=raw["current_index"],
            commitment=bytes.fromhex(raw["commitment"]),
        )


def load_state() -> BlobState:
    if not STORAGE_FILE.exists():
        raise FileNotFoundError("Storage file not found. Please initialize first.")
    return BlobState.from_json(STORAGE_FILE.read_text())


def save_state(state: BlobState):
    commitment = get_current_commitment(state.blob)
    STORAGE_FILE.write_text(state.to_json(commitment=commitment))


def fq_to_uint256_pair(fq) -> Tuple[int, int]:
    # 将 fq 元素（FQ(x)）转换为两个 uint256，高位在前
    x_bytes = int(fq.n).to_bytes(64, "big")
    hi = int.from_bytes(x_bytes[:32], "big")
    lo = int.from_bytes(x_bytes[32:], "big")
    return (hi, lo)


@app.command()
def init(user: List[str]):
    """初始化 blob 状态，只设置 address 和 value，proof 延迟生成。"""
    if STORAGE_FILE.exists():
        typer.echo(
            "Storage already exists. Remove manually if reinitialization needed."
        )
        raise typer.Exit(1)

    if len(user) > FIELD_ELEMENTS_PER_BLOB:
        typer.echo("Too many users, exceeds blob length.")
        raise typer.Exit(1)

    user_index_map = {}
    user_info_list = []
    blob = []

    reversed_roots = bit_reversal_permutation(ROOTS_OF_UNITY)
    reversed_lagranges = bit_reversal_permutation(KZG_SETUP_LAGRANGE)

    for i, u in enumerate(user):
        try:
            # user_str 格式: "user1:0xabc...:100"
            parts = u.split(":")
            if len(parts) != 3:
                raise ValueError("Expected format <id>:<address>:<value>")

            user_id, addr_hex, value_str = parts

            address = bytes.fromhex(
                addr_hex[2:] if addr_hex.startswith("0x") else addr_hex
            )
            value = int(value_str)

            root_of_unity = int(reversed_roots[i])

            # 解压 lagrange_setup
            compressed = reversed_lagranges[i]
            pt = pubkey_to_G1(compressed)

            if pt == Z1:
                x = (0, 0)
                y = (0, 0)
            else:
                x = fq_to_uint256_pair(pt[0])
                y = fq_to_uint256_pair(pt[1])

            info = UserInfo(
                address=address,
                value=value,
                proof=b"",
                root_of_unity=root_of_unity,
                lagrange_setup=G1Point(x=x, y=y),
            )
            h = info.hash()

            user_info_list.append(info)
            blob.append(h)
            user_index_map[user_id] = i

        except Exception as e:
            typer.echo(f"Invalid user format: {u}. Error: {e}")
            raise typer.Exit(1)

    while len(blob) < FIELD_ELEMENTS_PER_BLOB:
        blob.append(b"\x00" * 32)

    state = BlobState(
        blob=blob,
        user_index_map=user_index_map,
        user_info_list=user_info_list,
        current_index=len(user_info_list),
    )
    save_state(state)
    typer.echo(f"Initialized with {len(user_info_list)} users.")


@app.command()
def addusers(new_users: List[str]):
    """Add new users to the blob."""
    state = load_state()

    if state.current_index + len(new_users) > BLOB_LENGTH:
        typer.echo("Too many new users, exceeds blob length.")
        raise typer.Exit(1)

    parsed = []
    duplicates = []

    for i, u in enumerate(new_users):
        try:
            parts = u.split(":")
            if len(parts) != 3:
                raise ValueError("Expected format <id>:<address>:<value>")

            user_id, addr_hex, value_str = parts

            if user_id in state.user_index_map:
                duplicates.append(user_id)
                continue

            address = bytes.fromhex(
                addr_hex[2:] if addr_hex.startswith("0x") else addr_hex
            )
            value = int(value_str)

            idx = state.current_index + i

            root_of_unity = bit_reversal_permutation(ROOTS_OF_UNITY)[idx]

            lagrange_bytes = bit_reversal_permutation(KZG_SETUP_LAGRANGE)[idx]
            pt = pubkey_to_G1(lagrange_bytes)
            if pt == Z1:
                x = (0, 0)
                y = (0, 0)
            else:
                x = fq_to_uint256_pair(pt[0])
                y = fq_to_uint256_pair(pt[1])

            info = UserInfo(
                address=address,
                value=value,
                root_of_unity=root_of_unity,
                lagrange_setup=G1Point(x=x, y=y),
                proof=b"",
            )

            parsed.append((user_id, info))

        except Exception as e:
            typer.echo(f"Invalid user format: {u}. Error: {e}")
            raise typer.Exit(1)

    if not parsed:
        typer.echo("No valid new users to add.")
        raise typer.Exit(0)

    for user_id, info in parsed:
        idx = state.current_index
        h = info.hash()

        state.user_index_map[user_id] = idx
        state.user_info_list.append(info)
        state.blob[idx] = h
        state.current_index += 1

    save_state(state)
    typer.echo(f"Added {len(parsed)} new users.")

    if duplicates:
        typer.echo(
            f"These users already existed and were skipped: {', '.join(duplicates)}"
        )


@app.command()
def update(updates: List[str]):
    """
    Batch update user values and blob hashes.

    Example:
        python3 blob_manager.py update user1 5 user2 -3
    """
    if len(updates) % 2 != 0:
        typer.echo("Invalid input. Please provide user-delta pairs.")
        raise typer.Exit(1)

    state = load_state()

    commitment_delta = Z1

    for i in range(0, len(updates), 2):
        user = updates[i]
        try:
            delta = int(updates[i + 1])
        except ValueError:
            typer.echo(f"Invalid delta value: {updates[i + 1]}")
            raise typer.Exit(1)

        index = state.user_index_map.get(user)
        if index is None:
            typer.echo(f"User {user} not found.")
            raise typer.Exit(1)

        # ✅ 记录旧哈希，更新 user 的 value
        old_hash = state.user_info_list[index].hash()

        # ✅ 修改 user 的 value，并更新 blob 中的哈希
        state.user_info_list[index].value += delta
        new_hash = state.user_info_list[index].hash()
        state.blob[index] = new_hash

        typer.echo(f"Updated user {user} at index {index} by delta {delta}.")

        hash_diff = (
            int.from_bytes(new_hash, "big") - int.from_bytes(old_hash, "big")
        ) % BLS_MODULUS

        commitment_delta = add(
            commitment_delta,
            multiply(
                pubkey_to_G1(bit_reversal_permutation(KZG_SETUP_LAGRANGE)[index]),
                hash_diff,
            ),
        )

    pt = commitment_delta
    if pt == Z1:
        x = (0, 0)
        y = (0, 0)
    else:
        # normalize 很重要！否则合约会报错，其他函数未进行normalize是因为输出的G1点是直接从bytes转换的，未经过计算。
        pt = normalize(pt)
        x = fq_to_uint256_pair(pt[0])
        y = fq_to_uint256_pair(pt[1])

    typer.echo(f"Commitment Delta: {G1_to_pubkey(commitment_delta).hex()}")
    typer.echo(f"Commitment Delta x[0]: {x[0]}")
    typer.echo(f"Commitment Delta x[1]: {x[1]}")
    typer.echo(f"Commitment Delta y[0]: {y[0]}")
    typer.echo(f"Commitment Delta y[1]: {y[1]}")
    save_state(state)


@app.command()
def dump():
    """Print the current blob and user-index map."""
    state = load_state()
    typer.echo(state.to_json())


@app.command()
def getindex(user: str):
    """Get the index and value of a user in the blob."""
    state = load_state()
    index = state.user_index_map.get(user)
    if index is None:
        typer.echo("User not found.")
        raise typer.Exit(1)

    user_info = state.user_info_list[index]
    address_hex = "0x" + user_info.address.hex()
    value = user_info.value

    typer.echo(
        f"User {user} is at index {index}, address={address_hex}, value={value}."
    )


def int_to_bytes32(x: int) -> bytes:
    return x.to_bytes(32, "big")


def get_current_commitment(blob: List[bytes]) -> bytes:
    # 验证每个元素都是 bytes32
    if len(blob) != FIELD_ELEMENTS_PER_BLOB:
        raise ValueError("Invalid blob length")

    for i, b in enumerate(blob):
        if not isinstance(b, bytes) or len(b) != 32:
            raise TypeError(f"Blob element at index {i} is not bytes32: {b!r}")

    # 拼接所有 bytes32 得到 blob
    blob_bytes = b"".join(blob)

    return blob_to_kzg_commitment(blob_bytes)


@app.command()
def outputcommitment():
    """Output the current blob's commitment."""
    state = load_state()
    commitment = get_current_commitment(state.blob)
    hex_commitment = commitment.hex()

    pt = pubkey_to_G1(commitment)

    if pt == Z1:
        x = (0, 0)
        y = (0, 0)
    else:
        x = fq_to_uint256_pair(pt[0])
        y = fq_to_uint256_pair(pt[1])
    typer.echo(f"Current Commitment: {hex_commitment}")
    typer.echo(f"Commitment x[0]: {x[0]}")
    typer.echo(f"Commitment x[1]: {x[1]}")
    typer.echo(f"Commitment y[0]: {y[0]}")
    typer.echo(f"Commitment y[1]: {y[1]}")


@app.command()
def checkcommitment(expected_commitment_hex: str):
    """Check if the current blob's commitment matches the given hex commitment."""
    state = load_state()
    commitment = get_current_commitment(state.blob)
    hex_commitment = commitment.hex()
    if hex_commitment.lower() == expected_commitment_hex.lower():
        typer.echo("✅ Commitment matches.")
    else:
        typer.echo("❌ Commitment mismatch.")
        typer.echo(f"Computed : {hex_commitment}")
        typer.echo(f"Expected : {expected_commitment_hex}")


@app.command()
def reset():
    """Reset the entire blob and user mapping."""
    if not STORAGE_FILE.exists():
        typer.echo("Storage file not found. Nothing to reset.")
        raise typer.Exit(1)

    reset_state = BlobState(
        blob=[b"\x00" * 32] * BLOB_LENGTH,  # 正确初始化 bytes32
        user_index_map={},
        user_info_list=[],
        current_index=0,
        commitment=b"",
    )

    save_state(reset_state)
    typer.echo("✅ Blob state has been reset.")


@app.command()
def getproof(user: str):
    """
    Compute and verify the KZG proof for the given user at their evaluation point.
    Writes the proof into the corresponding UserInfo.
    """
    state = load_state()

    index = state.user_index_map.get(user)
    if index is None:
        typer.echo("User not found in mapping.")
        raise typer.Exit(1)

    user_info = state.user_info_list[index]

    z = user_info.root_of_unity  # ✅ 从用户属性中拿 evaluation point
    z_bytes = int_to_bytes32(z)

    blob_bytes = b"".join(state.blob)
    proof = compute_kzg_proof(blob_bytes, z_bytes)

    y_bytes = state.blob[index]
    assert isinstance(y_bytes, bytes) and len(y_bytes) == 32

    ok = verify_kzg_proof(state.commitment, z_bytes, y_bytes, proof)

    # 存到 user_info_list 里
    state.user_info_list[index].proof = proof
    save_state(state)

    pt = pubkey_to_G1(proof)

    if pt == Z1:
        x = (0, 0)
        y = (0, 0)
    else:
        x = fq_to_uint256_pair(pt[0])
        y = fq_to_uint256_pair(pt[1])

    # 输出
    typer.echo(f"User: {user}")
    typer.echo(f"Index: {index}")
    typer.echo(f"z (evaluation point): {z}")
    typer.echo(f"y (blob value): {y_bytes.hex()}")
    typer.echo(f"Proof: {proof.hex()}")
    typer.echo(f"Proof x[0]: {x[0]}")
    typer.echo(f"Proof x[1]: {x[1]}")
    typer.echo(f"Proof y[0]: {y[0]}")
    typer.echo(f"Proof y[1]: {y[1]}")
    typer.echo(f"Verification result: {'✅ success' if ok else '❌ failed'}")


@app.command()
def outputproof(user: str):
    state = load_state()

    index = state.user_index_map.get(user)
    if index is None:
        typer.echo("User not found in mapping.")
        raise typer.Exit(1)

    user_info = state.user_info_list[index]
    proof = user_info.proof

    pt = pubkey_to_G1(proof)

    if pt == Z1:
        x = (0, 0)
        y = (0, 0)
    else:
        x = fq_to_uint256_pair(pt[0])
        y = fq_to_uint256_pair(pt[1])

    typer.echo(f"Current proof: {proof.hex()}")
    typer.echo(f"proof x[0]: {x[0]}")
    typer.echo(f"proof x[1]: {x[1]}")
    typer.echo(f"proof y[0]: {y[0]}")
    typer.echo(f"proof y[1]: {y[1]}")


if __name__ == "__main__":
    app()
