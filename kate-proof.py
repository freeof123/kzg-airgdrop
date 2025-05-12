import random, json
from py_ecc.bls12_381 import FQ, G1, curve_order, multiply, add, Z1

# 导入 compress_G1 方法
from hashlib import sha256

# BLS12-381 的阶数
BLS_MODULUS = curve_order
POW_2_381 = 2**381
POW_2_382 = 2**382
POW_2_383 = 2**383
POW_2_384 = 2**384
q = int(
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
)
# Curve is y**2 = x**3 + 4
b = FQ(4)


#
# G1
#
def compress_G1(pt):
    """
    A compressed point is a 384-bit integer with the bit order
    (c_flag, b_flag, a_flag, x), where the c_flag bit is always set to 1,
    the b_flag bit indicates infinity when set to 1,
    the a_flag bit helps determine the y-coordinate when decompressing,
    and the 381-bit integer x is the x-coordinate of the point.
    """
    x, y = pt[0], pt[1]
    # Record y's leftmost bit to the a_flag
    a_flag = (y.n * 2) // q
    # Set c_flag = 1 and b_flag = 0
    return (x.n + a_flag * POW_2_381 + POW_2_383).to_bytes(48, byteorder="big")


def decompress_G1(z):
    """
    Recovers x and y coordinates from the compressed point.
    """
    c_flag = bool((z >> 383) & 1)  # The most significant bit.
    a_flag = bool((z >> 381) & 1)  # The third-most significant bit.

    # c_flag == 1 indicates the compressed form
    # MSB should be 1
    if not c_flag:
        raise ValueError("c_flag should be 1")

    # Else, not point at infinity
    # 3 MSBs should be 100 or 101
    x = z % POW_2_381
    if x >= q:
        raise ValueError(f"Point value should be less than field modulus. Got {x}")

    # Try solving y coordinate from the equation Y^2 = X^3 + b
    # using quadratic residue
    y = pow((x**3 + b.n) % q, (q + 1) // 4, q)

    if pow(y, 2, q) != (x**3 + b.n) % q:
        raise ValueError("The given point is not on G1: y**2 = x**3 + b")
    # Choose the y whose leftmost bit is equal to the a_flag
    if (y * 2) // q != int(a_flag):
        y = q - y
    return (FQ(x), FQ(y))


# 生成随机私钥 s
def generate_random_private_key():
    return random.randint(1, BLS_MODULUS - 1)


# 生成 KZG trusted setup 数组 [s^i]_1
def generate_trusted_setup(s, num_elements):
    setup_array = []
    for i in range(num_elements):
        # 使用 multiply 方法计算 G1 元素的乘法
        setup_array.append(multiply(G1, s**i % BLS_MODULUS))
    return setup_array


# 计算 多项式f(x) = x^3 + 5 的 Commitment C = [s^3]_1 + [s^0]_1 * 5
def calculate_commitment(setup_array):
    # 计算 [s^3]_1
    commitment = setup_array[3]
    # 计算 [s^0]_1 * 5 (即 G1 的单位元素乘以常数 5)
    commitment = add(commitment, multiply(setup_array[0], 5))
    return commitment


# (x^3+5-13)/(x-2) = x^2+2x+4
# Q(x) = x^2 + 2x + 4, 计算 [Q(x)]_1 = [s^2]_1 + [s^1]_1 * 2 + [s^0]_1 * 4
def calculate_proof(setup_array):
    commitment = setup_array[2]
    commitment = add(commitment, multiply(setup_array[1], 2))
    commitment = add(commitment, multiply(setup_array[0], 4))
    return commitment


# 计算 b 的值
def compute_b(y, p):
    # 计算 (p - 1) / 2
    half_p_minus_1 = (p - 1) // 2
    # 如果 y > (p - 1) / 2，b=1，否则 b=0
    return 1 if y > half_p_minus_1 else 0


# 将整数转换为指定字节数的字节表示
def int_to_bytes(val, length):
    return val.to_bytes(length, byteorder="big")


# 读取 JSON 文件并获取 g1_monomial 数组
def load_trusted_setup(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)
        # 将十六进制字符串转换为整数，去掉前缀 '0x'
        return [int(hex_str, 16) for hex_str in data["g1_monomial"]]


# 从文件加载 trusted setup 数组
def generate_trusted_setup_from_file(file_path):
    g1_monomial_ints = load_trusted_setup(file_path)

    # 将每个整数反序列化为 G1 点
    setup_array = [decompress_G1(value) for value in g1_monomial_ints]
    return setup_array


def add_group_elements(elements):
    # 初始化累加器为无穷远点（单位元）
    accumulator = Z1
    for element in elements:
        accumulator = add(accumulator, element)
    return accumulator


def generate_roots_of_unity(width):
    modulus = curve_order
    n = width

    # 检查 n 是否整除 (curve_order - 1)
    assert (modulus - 1) % n == 0, f"{n} must divide curve_order - 1"

    # 计算 ω = 7^((modulus - 1) // n) mod modulus
    exponent = (modulus - 1) // n
    omega = pow(7, exponent, modulus)

    # 验证 ω 是 n 次单位原根
    assert pow(omega, n, modulus) == 1, "ω is not a n-th root of unity"
    assert pow(omega, n // 2, modulus) == modulus - 1, "ω is not a primitive root"

    return [pow(omega, i, modulus) for i in range(n)]


# def testing(setup_array):
#     roots_of_unity = generate_roots_of_unity(width)

#     result = add_group_elements(setup_array)
#     print(compress_G1(result).hex())
#     return


# 主程序

# 测试加载并反序列化
file_path = "trusted_setup_4096.json"  # 文件路径
setup_array = generate_trusted_setup_from_file(file_path)

# testing(setup_array)

# 计算 Commitment C = [s^3]_1 + [s^0]_1 * 5  f（x）=x^3+5
C = calculate_commitment(setup_array)

# 将 Commitment 转换为 bytes48 格式
C_bytes = compress_G1(C)

VERSIONED_HASH_VERSION_KZG = b"\x01"  # 示例版本号，实际应根据需求定义


# KZGCommitment 的版本化哈希计算
def kzg_to_versioned_hash(commitment: bytes) -> bytes:
    # 计算 commitment 的 sha256 哈希
    commitment_hash = sha256(commitment).digest()
    # 返回版本号 + 哈希值的后部分 (去掉 sha256 前几个字节)
    return VERSIONED_HASH_VERSION_KZG + commitment_hash[1:]


vh = kzg_to_versioned_hash(C_bytes)

# 取 z = 2, y = f(z) = 13,
z = 2
y = 13

# 将 z 和 y 转换为 32 字节的 bytes
z_bytes = z.to_bytes(32, byteorder="big")
y_bytes = y.to_bytes(32, byteorder="big")

pi = calculate_proof(setup_array)

# 将 Proof 转换为 bytes48 格式
pi_bytes = compress_G1(pi)

# 拼接成 192 字节的 bytes
final_bytes = vh + z_bytes + y_bytes + C_bytes + pi_bytes

# 展示拼接结果
print(f"Final 192 bytes: {final_bytes.hex()}")
