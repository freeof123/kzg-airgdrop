import hashlib, json
from pathlib import Path
from py_ecc.bls.g2_primitives import (
    pubkey_to_G1,
    G1_to_pubkey,
    G2_to_signature,
    signature_to_G2,
)
from typing import Iterator, Sequence, TypeVar, Final, NewType
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.optimized_bls12_381.optimized_curve import (
    G1,
    Z1,
    multiply,
    add,
    G2,
    Z2,
    neg,
    FQ12,
)
from py_ecc.optimized_bls12_381.optimized_pairing import pairing

# 导入 compress_G1 方法
from hashlib import sha256

T = TypeVar("T")

# --- Constants ---
BLS_MODULUS: Final[int] = (
    52435875175126190479447740508185965837690552500527637822603658699938581184513
)
BYTES_PER_FIELD_ELEMENT: Final[int] = 32
FIELD_ELEMENTS_PER_BLOB: Final[int] = 4096
KZG_SETUP_G2_LENGTH: Final[int] = 65

G1_POINT_AT_INFINITY: Final[bytes] = bytes([0xC0]) + bytes(47)
PRIMITIVE_ROOT_OF_UNITY = 7
ENDIANNESS: Final[str] = "big"
FIAT_SHAMIR_PROTOCOL_DOMAIN = b"FSBLOBVERIFY_V1_"  # Fiat-Shamir 协议域，用于 blob 验证
RANDOM_CHALLENGE_KZG_BATCH_DOMAIN = b"RCKZGBATCH___V1_"  # 用于 KZG 批量验证的随机挑战域
TRUSTED_SETUP_PATH: Final[str] = "./trusted_setup_4096.json"


Bytes32 = NewType("Bytes32", bytes)
Bytes48 = NewType("Bytes48", bytes)
Bytes96 = NewType("Bytes96", bytes)

G1Point = NewType("G1Point", Bytes48)
G2Point = NewType("G2Point", Bytes96)

KZGCommitment = NewType("KZGCommitment", Bytes48)
KZGProof = NewType("KZGProof", Bytes48)
uint64 = int
Blob = bytes

# Patch missing function for compatibility with official spec
if not hasattr(bls, "bytes48_to_G1"):
    setattr(bls, "bytes48_to_G1", pubkey_to_G1)

if not hasattr(bls, "G1_to_bytes48"):
    setattr(bls, "G1_to_bytes48", G1_to_pubkey)

if not hasattr(bls, "bytes96_to_G2"):
    setattr(bls, "bytes96_to_G2", signature_to_G2)

if not hasattr(bls, "G2_to_bytes96"):
    setattr(bls, "G2_to_bytes96", G2_to_signature)


# --- Types based on SSZ Spec ---
# BLSFieldElement: uint256 with validation x < BLS_MODULUS
class BLSFieldElement(int):
    def __new__(cls, value: int):
        if not (0 <= value < BLS_MODULUS):
            raise ValueError("Value out of range for BLS field element")
        return super().__new__(cls, value)

    def __repr__(self):
        return f"BLSFieldElement({int(self)})"


class KZGCommitment(bytes):
    def __new__(cls, data: bytes):
        if len(data) != 48:
            raise ValueError("KZGCommitment must be 48 bytes")
        return super().__new__(cls, data)


class KZGProof(bytes):
    def __new__(cls, data: bytes):
        if len(data) != 48:
            raise ValueError("KZGProof must be 48 bytes")
        return super().__new__(cls, data)


class Polynomial(Sequence[BLSFieldElement]):
    def __init__(self):
        self._data = [BLSFieldElement(0) for _ in range(FIELD_ELEMENTS_PER_BLOB)]

    def __getitem__(self, index: int) -> BLSFieldElement:
        return self._data[index]

    def __setitem__(self, index: int, value: BLSFieldElement) -> None:
        self._data[index] = value

    def __len__(self) -> int:
        return FIELD_ELEMENTS_PER_BLOB

    def __iter__(self) -> Iterator[BLSFieldElement]:
        return iter(self._data)

    def __repr__(self):
        return f"Polynomial({self._data})"


def compute_powers(x: BLSFieldElement, n: uint64) -> Sequence[BLSFieldElement]:
    """
    Return ``x`` to power of [0, n-1], if n > 0. When n==0, an empty array is returned.
    """
    current_power = BLSFieldElement(1)
    powers = []
    for _ in range(n):
        powers.append(current_power)
        current_power = current_power * x % BLS_MODULUS
    return powers


def compute_roots_of_unity(order: uint64) -> Sequence[BLSFieldElement]:
    """
    Return roots of unity of ``order``.
    """
    assert (BLS_MODULUS - 1) % int(order) == 0
    root_of_unity = BLSFieldElement(
        pow(PRIMITIVE_ROOT_OF_UNITY, (BLS_MODULUS - 1) // int(order), BLS_MODULUS)
    )
    return compute_powers(root_of_unity, order)


ROOTS_OF_UNITY = compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)


def load_trusted_setup(
    path: str = TRUSTED_SETUP_PATH,
) -> tuple[Sequence[G2Point], Sequence[G1Point]]:
    with open(Path(path), "r") as f:
        setup_data = json.load(f)

    g2_monomial_raw = setup_data["g2_monomial"]
    g1_lagrange_raw = setup_data["g1_lagrange"]

    assert len(g2_monomial_raw) == KZG_SETUP_G2_LENGTH, "Invalid g2_monomial length"
    assert len(g1_lagrange_raw) == FIELD_ELEMENTS_PER_BLOB, "Invalid g1_lagrange length"

    g2 = tuple(bytes.fromhex(s[2:]) for s in g2_monomial_raw)
    g1 = tuple(bytes.fromhex(s[2:]) for s in g1_lagrange_raw)

    return g2, g1


KZG_SETUP_G2, KZG_SETUP_LAGRANGE = load_trusted_setup()


def is_power_of_two(value: int) -> bool:
    """
    Check if ``value`` is a power of two integer.
    """
    return (value > 0) and (value & (value - 1) == 0)


def reverse_bits(n: int, order: int) -> int:
    """
    Reverse the bit order of an integer ``n``.
    """
    assert is_power_of_two(order)
    # Convert n to binary with the same number of bits as "order" - 1, then reverse its bit order
    return int(("{:0" + str(order.bit_length() - 1) + "b}").format(n)[::-1], 2)


def bit_reversal_permutation(sequence: Sequence[T]) -> Sequence[T]:
    """
    Return a copy with bit-reversed permutation. The permutation is an involution (inverts itself).

    The input and output are a sequence of generic type ``T`` objects.
    """
    return [sequence[reverse_bits(i, len(sequence))] for i in range(len(sequence))]


def hash_to_bls_field(data: bytes) -> BLSFieldElement:
    """
    Hash ``data`` and convert the output to a BLS scalar field element.
    The output is not uniform over the BLS field.
    """
    hashed_data = hashlib.sha256(data).digest()
    return BLSFieldElement(int.from_bytes(hashed_data, ENDIANNESS) % BLS_MODULUS)


def bytes_to_bls_field(b: Bytes32) -> BLSFieldElement:
    """
    Convert untrusted bytes to a trusted and validated BLS scalar field element.
    This function does not accept inputs greater than the BLS modulus.
    """
    field_element = int.from_bytes(b, ENDIANNESS)
    assert field_element < BLS_MODULUS
    return BLSFieldElement(field_element)


def validate_kzg_g1(b: Bytes48) -> None:
    """
    Perform BLS validation required by the types `KZGProof` and `KZGCommitment`.
    """
    if b == G1_POINT_AT_INFINITY:
        return

    assert bls.KeyValidate(b)


def bytes_to_kzg_commitment(b: Bytes48) -> KZGCommitment:
    """
    Convert untrusted bytes into a trusted and validated KZGCommitment.
    """
    validate_kzg_g1(b)
    return KZGCommitment(b)


def bytes_to_kzg_proof(b: Bytes48) -> KZGProof:
    """
    Convert untrusted bytes into a trusted and validated KZGProof.
    """
    validate_kzg_g1(b)
    return KZGProof(b)


def blob_to_polynomial(blob: Blob) -> Polynomial:
    """
    Convert a blob to list of BLS field scalars.
    """
    polynomial = Polynomial()
    for i in range(FIELD_ELEMENTS_PER_BLOB):
        value = bytes_to_bls_field(
            blob[i * BYTES_PER_FIELD_ELEMENT : (i + 1) * BYTES_PER_FIELD_ELEMENT]
        )
        polynomial[i] = value
    return polynomial


def compute_challenge(blob: Blob, commitment: KZGCommitment) -> BLSFieldElement:
    """
    Return the Fiat-Shamir challenge required by the rest of the protocol.
    """

    # Append the degree of the polynomial as a domain separator
    degree_poly = int.to_bytes(FIELD_ELEMENTS_PER_BLOB, 16, ENDIANNESS)
    data = FIAT_SHAMIR_PROTOCOL_DOMAIN + degree_poly

    data += blob
    data += commitment

    # Transcript has been prepared: time to create the challenge
    return hash_to_bls_field(data)


def bls_modular_inverse(x: BLSFieldElement) -> BLSFieldElement:
    """
    Compute the modular inverse of x
    i.e. return y such that x * y % BLS_MODULUS == 1 and return 0 for x == 0
    """
    return BLSFieldElement(pow(x, -1, BLS_MODULUS)) if x != 0 else BLSFieldElement(0)


def div(x: BLSFieldElement, y: BLSFieldElement) -> BLSFieldElement:
    """
    Divide two field elements: ``x`` by `y``.
    """
    return BLSFieldElement((int(x) * int(bls_modular_inverse(y))) % BLS_MODULUS)


def g1_lincomb(
    points: Sequence[KZGCommitment], scalars: Sequence[BLSFieldElement]
) -> KZGCommitment:
    """
    BLS multiscalar multiplication. This function can be optimized using Pippenger's algorithm and variants.
    """
    assert len(points) == len(scalars)
    result = Z1
    for x, a in zip(points, scalars):
        result = add(result, multiply(bls.bytes48_to_G1(x), a))
    return KZGCommitment(bls.G1_to_bytes48(result))


def evaluate_polynomial_in_evaluation_form(
    polynomial: Polynomial, z: BLSFieldElement
) -> BLSFieldElement:
    """
    Evaluate a polynomial (in evaluation form) at an arbitrary point ``z`` that is not in the domain.
    Uses the barycentric formula:
       f(z) = (z**WIDTH - 1) / WIDTH  *  sum_(i=0)^WIDTH  (f(DOMAIN[i]) * DOMAIN[i]) / (z - DOMAIN[i])
    """
    width = len(polynomial)
    assert width == FIELD_ELEMENTS_PER_BLOB
    inverse_width = bls_modular_inverse(BLSFieldElement(width))

    roots_of_unity_brp = bit_reversal_permutation(ROOTS_OF_UNITY)

    # If we are asked to evaluate within the domain, we already know the answer
    if z in roots_of_unity_brp:
        eval_index = roots_of_unity_brp.index(z)
        return BLSFieldElement(polynomial[eval_index])

    result = 0
    for i in range(width):
        a = BLSFieldElement(
            int(polynomial[i]) * int(roots_of_unity_brp[i]) % BLS_MODULUS
        )
        b = BLSFieldElement(
            (int(BLS_MODULUS) + int(z) - int(roots_of_unity_brp[i])) % BLS_MODULUS
        )
        result += int(div(a, b) % BLS_MODULUS)
    result = (
        result * int(BLS_MODULUS + pow(z, width, BLS_MODULUS) - 1) * int(inverse_width)
    )
    return BLSFieldElement(result % BLS_MODULUS)


def blob_to_kzg_commitment(blob: Blob) -> KZGCommitment:
    """
    Public method.
    """
    return g1_lincomb(
        bit_reversal_permutation(KZG_SETUP_LAGRANGE), blob_to_polynomial(blob)
    )


def verify_kzg_proof(
    commitment_bytes: Bytes48, z: Bytes32, y: Bytes32, proof_bytes: Bytes48
) -> bool:
    """
    Verify KZG proof that ``p(z) == y`` where ``p(z)`` is the polynomial represented by ``polynomial_kzg``.
    Receives inputs as bytes.
    Public method.
    """
    return verify_kzg_proof_impl(
        bytes_to_kzg_commitment(commitment_bytes),
        bytes_to_bls_field(z),
        bytes_to_bls_field(y),
        bytes_to_kzg_proof(proof_bytes),
    )


def verify_kzg_proof_impl(
    commitment: KZGCommitment, z: BLSFieldElement, y: BLSFieldElement, proof: KZGProof
) -> bool:
    """
    Verify KZG proof that ``p(z) == y`` where ``p(z)`` is the polynomial represented by ``polynomial_kzg``.
    """
    # Verify: P - y = Q * (X - z)
    X_minus_z = add(
        bls.bytes96_to_G2(KZG_SETUP_G2[1]),
        multiply(G2, (BLS_MODULUS - z) % BLS_MODULUS),
    )
    P_minus_y = add(
        bls.bytes48_to_G1(commitment),
        multiply(G1, (BLS_MODULUS - y) % BLS_MODULUS),
    )
    return pairing_check([[P_minus_y, neg(G2)], [bls.bytes48_to_G1(proof), X_minus_z]])


def compute_kzg_proof(blob: Blob, z: Bytes32) -> KZGProof:
    """
    Compute KZG proof at point `z` for the polynomial represented by `blob`.
    Do this by computing the quotient polynomial in evaluation form: q(x) = (p(x) - p(z)) / (x - z).
    Public method.
    """
    polynomial = blob_to_polynomial(blob)
    return compute_kzg_proof_impl(polynomial, bytes_to_bls_field(z))


def compute_kzg_proof_impl(polynomial: Polynomial, z: BLSFieldElement) -> KZGProof:
    """
    Helper function for `compute_kzg_proof()` and `compute_blob_kzg_proof()`.
    """
    roots_of_unity_brp = bit_reversal_permutation(ROOTS_OF_UNITY)

    # For all x_i, compute p(x_i) - p(z)
    y = evaluate_polynomial_in_evaluation_form(polynomial, z)
    polynomial_shifted = [
        BLSFieldElement((int(p) - int(y)) % BLS_MODULUS) for p in polynomial
    ]

    # For all x_i, compute (x_i - z)
    denominator_poly = [
        BLSFieldElement((int(x) - int(z)) % BLS_MODULUS) for x in roots_of_unity_brp
    ]

    # Compute the quotient polynomial directly in evaluation form
    quotient_polynomial = [BLSFieldElement(0)] * FIELD_ELEMENTS_PER_BLOB
    for i, (a, b) in enumerate(zip(polynomial_shifted, denominator_poly)):
        if b == 0:
            # The denominator is zero hence `z` is a root of unity: we must handle it as a special case
            quotient_polynomial[i] = compute_quotient_eval_within_domain(
                roots_of_unity_brp[i], polynomial, y
            )
        else:
            # Compute: q(x_i) = (p(x_i) - p(z)) / (x_i - z).
            quotient_polynomial[i] = div(a, b)

    return KZGProof(
        g1_lincomb(bit_reversal_permutation(KZG_SETUP_LAGRANGE), quotient_polynomial)
    )


def compute_quotient_eval_within_domain(
    z: BLSFieldElement, polynomial: Polynomial, y: BLSFieldElement
) -> BLSFieldElement:
    """
    Given `y == p(z)` for a polynomial `p(x)`, compute `q(z)`: the KZG quotient polynomial evaluated at `z` for the
    special case where `z` is in `ROOTS_OF_UNITY`.

    For more details, read https://dankradfeist.de/ethereum/2021/06/18/pcs-multiproofs.html section "Dividing
    when one of the points is zero". The code below computes q(x_m) for the roots of unity special case.
    """
    roots_of_unity_brp = bit_reversal_permutation(ROOTS_OF_UNITY)
    result = 0
    for i, omega_i in enumerate(roots_of_unity_brp):
        if omega_i == z:  # skip the evaluation point in the sum
            continue

        f_i = int(BLS_MODULUS) + int(polynomial[i]) - int(y) % BLS_MODULUS
        numerator = f_i * int(omega_i) % BLS_MODULUS
        denominator = int(z) * (int(BLS_MODULUS) + int(z) - int(omega_i)) % BLS_MODULUS
        result += int(div(BLSFieldElement(numerator), BLSFieldElement(denominator)))

    return BLSFieldElement(result % BLS_MODULUS)


def pairing_check(pairs: list[tuple]) -> bool:
    """
    Ethereum-style pairing product check:
    Return True if the product of all pairings equals 1 in FQ12.
    All pairings are final_exponentiated.
    """
    result = FQ12.one()
    for P, Q in pairs:
        result *= pairing(Q, P)  # 注意：py_ecc 接口是 pairing(Q, P)
    return result == FQ12.one()
