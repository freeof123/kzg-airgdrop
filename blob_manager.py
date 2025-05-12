import json
from typing import List, Dict
from dataclasses import dataclass, asdict
import typer
from pathlib import Path
from kzg_base import *

app = typer.Typer()

BLOB_LENGTH = 4096
STORAGE_FILE = Path("blob_storage.json")


@dataclass
class BlobState:
    blob: List[int]
    user_index_map: Dict[str, int]
    current_index: int  # Add current_index to the state

    def to_json(self, commitment: str = ""):
        # Add commitment if provided
        data = asdict(self)
        if commitment:
            data["commitment"] = commitment
        return json.dumps(data, indent=2)

    @staticmethod
    def from_json(data: str):
        raw = json.loads(data)
        return BlobState(
            blob=raw["blob"],
            user_index_map=raw["user_index_map"],
            current_index=raw["current_index"],
        )


def load_state() -> BlobState:
    if not STORAGE_FILE.exists():
        raise FileNotFoundError("Storage file not found. Please initialize first.")
    return BlobState.from_json(STORAGE_FILE.read_text())


def save_state(state: BlobState):
    # Compute commitment before saving
    commitment = get_current_commitment(state.blob).hex()
    STORAGE_FILE.write_text(state.to_json(commitment=commitment))


@app.command()
def addusers(new_users: List[str]):
    """Add new users to the blob."""
    state = load_state()

    # Ensure new users do not exceed BLOB_LENGTH
    if state.current_index + len(new_users) > BLOB_LENGTH:
        typer.echo("Too many new users, exceeds blob length.")
        raise typer.Exit(1)

    # Check for duplicates and filter out already existing users
    existing_users = [user for user in new_users if user in state.user_index_map]
    if existing_users:
        typer.echo(f"These users are already added: {', '.join(existing_users)}.")
        new_users = [user for user in new_users if user not in state.user_index_map]

    if not new_users:
        typer.echo("No new users to add.")
        raise typer.Exit(0)

    # Update user_index_map and blob
    user_index_map = state.user_index_map
    new_user_index_map = {
        user: i for i, user in enumerate(new_users, start=state.current_index)
    }

    # Merge the old and new user index maps
    user_index_map.update(new_user_index_map)

    # Update the current_index
    state.current_index += len(new_users)

    state.user_index_map = user_index_map
    save_state(state)

    typer.echo(f"Added {len(new_users)} new users.")


@app.command()
def init(users: List[str]):
    """Initialize blob with a list of user addresses."""
    if STORAGE_FILE.exists():
        typer.echo(
            "Storage already exists. Remove manually if reinitialization needed."
        )
        raise typer.Exit(1)
    if len(users) > BLOB_LENGTH:
        typer.echo("Too many users, exceeds blob length.")
        raise typer.Exit(1)

    # Initialize user index map and blob
    user_index_map = {user: i for i, user in enumerate(users)}
    blob = [0] * BLOB_LENGTH

    # Initialize current_index
    current_index = len(users)

    state = BlobState(
        blob=blob, user_index_map=user_index_map, current_index=current_index
    )
    save_state(state)
    typer.echo(f"Initialized with {len(users)} users.")


@app.command()
def update(updates: List[str]):
    """
    Batch update blob values for users.

    Example:
        python3 blob_manager.py update user1 5 user2 -3
    """
    if len(updates) % 2 != 0:
        typer.echo("Invalid input. Please provide user-delta pairs.")
        raise typer.Exit(1)

    state = load_state()

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

        state.blob[index] += delta
        typer.echo(f"Updated user {user} at index {index} by delta {delta}.")

    save_state(state)


@app.command()
def dump():
    """Print the current blob and user-index map."""
    state = load_state()
    typer.echo(state.to_json())


@app.command()
def getindex(user: str):
    """Get the index of a user in the blob."""
    state = load_state()
    index = state.user_index_map.get(user)
    if index is None:
        typer.echo("User not found.")
        raise typer.Exit(1)
    typer.echo(f"User {user} is at index {index} with value {state.blob[index]}.")


def int_to_bytes32(x: int) -> bytes:
    return x.to_bytes(32, "big")


def get_current_commitment(blob: List[int]) -> bytes:
    # 将 List[int] 转换为符合底层库要求的 Blob (bytes 类型)
    if len(blob) != FIELD_ELEMENTS_PER_BLOB:
        raise ValueError("Invalid blob length")

    blob_bytes = b"".join(int_to_bytes32(x) for x in blob)
    return blob_to_kzg_commitment(blob_bytes)


@app.command()
def outputcommitment():
    """Output the current blob's commitment."""
    state = load_state()
    commitment = get_current_commitment(state.blob)
    hex_commitment = commitment.hex()
    typer.echo(f"Current Commitment: {hex_commitment}")


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

    # Reset the blob state
    reset_state = BlobState(
        blob=[0] * BLOB_LENGTH,
        user_index_map={},
        current_index=0,
    )

    save_state(reset_state)
    typer.echo("✅ Blob state has been reset.")


if __name__ == "__main__":
    app()
