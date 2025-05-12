import json
from py_ecc.optimized_bls12_381 import curve_order
from py_ecc.bls12_381 import FQ, G1, curve_order, multiply, add, neg


# BLS12-381 的阶数
BLS_MODULUS = curve_order
POW_2_381 = 2**381
POW_2_382 = 2**382
POW_2_383 = 2**383
POW_2_384 = 2**384
q = int('0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab', 16)
# Curve is y**2 = x**3 + 4
b = FQ(4)

def bit_reverse_indices(n):
    """生成位反转索引（用于Cooley-Tukey算法）"""
    bits = n.bit_length() - 1
    return [int(format(i, f'0{bits}b')[::-1], 2) for i in range(n)]

def fft(values, roots_of_unity):
    """非递归FFT实现，保证数值稳定性"""
    n = len(values)
    assert n == len(roots_of_unity), "长度必须匹配"
    assert (n & (n - 1)) == 0, "n必须是2的幂"
    
    # 位反转排列输入
    reversed_idx = bit_reverse_indices(n)
    arr = [values[i] for i in reversed_idx]
    # print(reversed_idx)
    # 迭代FFT
    s = 1
    while s <= n // 2:
        for k in range(0, n, 2 * s):
            for j in range(s):
                twiddle = roots_of_unity[j * (n // (2 * s))]
                even = arr[k + j]
                odd = multiply(arr[k + j + s], twiddle)
                arr[k + j] = add(even, odd)
                arr[k + j + s] = add(even, neg(odd))
        s *= 2
    return arr

def ifft(values, roots_of_unity):
    """非递归IFFT实现"""
    n = len(values)
    inv_n = pow(n, curve_order - 2, curve_order)  # 1/n的模逆
    
    # 使用逆单位根
    inv_roots = [pow(root, curve_order - 2, curve_order) for root in roots_of_unity]
    result = fft(values, inv_roots)
    
    # 乘以1/n
    return [multiply(x, inv_n) for x in result]

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
    return (x.n + a_flag * POW_2_381 + POW_2_383).to_bytes(48, byteorder='big')

def decompress_G1(hex_str):
    z = int(hex_str, 16)
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

# --- 核心转换逻辑 ---
def lagrange_to_g1(lagrange_setup, roots_of_unity):
    """将 KZG_SETUP_LAGRANGE (G1 点列表) 转换为 KZG_SETUP_G1 (IFFT)"""
    return fft(lagrange_setup, roots_of_unity)

def g1_to_lagrange(g1_setup, roots_of_unity):
    """将 KZG_SETUP_G1 (G1 点列表) 转换为 KZG_SETUP_LAGRANGE (FFT)"""
    return ifft(g1_setup, roots_of_unity)

# --- 主程序 ---
if __name__ == "__main__":
    # 1. 加载可信设置文件
    file_path = "trusted_setup_4096.json"
    with open(file_path, "r") as f:
        trusted_setup = json.load(f)
    
    # 2. 解析 G1 Lagrange 点（假设已解压为 G1 点）
    g1_lagrange_hex = trusted_setup["g1_lagrange"]
    g1_lagrange = [decompress_G1(hex_str) for hex_str in g1_lagrange_hex]
    width = len(g1_lagrange)

    # 3. 生成单位根并验证
    roots_of_unity = generate_roots_of_unity(width)
    print(f"Generated {len(roots_of_unity)} roots of unity (ω^0 to ω^{width-1})")

    # 4. 转换 KZG_SETUP_LAGRANGE → KZG_SETUP_G1
    kzg_setup_g1 = lagrange_to_g1(g1_lagrange, roots_of_unity)
    print("First 3 KZG_SETUP_G1 points:")
    for pt in kzg_setup_g1[:3]:
        print(compress_G1(pt).hex())

    # 5. 反向转换验证 (KZG_SETUP_G1 → KZG_SETUP_LAGRANGE)
    kzg_setup_lagrange_roundtrip = g1_to_lagrange(kzg_setup_g1, roots_of_unity)
    print("\nFirst 3 roundtrip KZG_SETUP_LAGRANGE points:")
    for pt in kzg_setup_lagrange_roundtrip[:3]:
        print(compress_G1(pt).hex())

    # 6. 验证转换的正确性（可选）
    assert all(
        compress_G1(a) == compress_G1(b)
        for a, b in zip(g1_lagrange, kzg_setup_lagrange_roundtrip)
    ), "Roundtrip conversion failed!"
    print("\n✅ Roundtrip validation passed!")