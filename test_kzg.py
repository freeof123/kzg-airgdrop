import unittest, time
from kzg_base import *
from py_ecc.bls.typing import G1Uncompressed, G2Uncompressed
from py_ecc.bls.g2_primitives import signature_to_G2
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.optimized_bls12_381.optimized_curve import (
    b,
    b2,
    G1,
    G2,
    Z1,
    Z2,
    multiply,
    add,
)


class TestRootsOfUnity(unittest.TestCase):
    def test_roots_of_unity_length(self):
        roots = compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
        self.assertEqual(len(roots), FIELD_ELEMENTS_PER_BLOB)

    def test_roots_of_unity_first_element_is_one(self):
        roots = compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
        self.assertEqual(roots[0], BLSFieldElement(1))

    def test_all_roots_are_correct(self):
        roots = compute_roots_of_unity(FIELD_ELEMENTS_PER_BLOB)
        for i, root in enumerate(roots):
            expected = BLSFieldElement(1)
            self.assertEqual(pow(root, FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS), expected)


class TestTrustedSetupLoad(unittest.TestCase):
    def test_sample_g1_points_are_on_curve(self):
        _, g1_points = load_trusted_setup()

        # 抽查前两个 G1 点（Affine -> Jacobian 转换）
        for i in range(2):
            bls.KeyValidate(g1_points[i])

    def test_first_g2_point_equals_spec_constant(self):
        g2_bytes_points, _ = load_trusted_setup()
        g2_point_0: G2Uncompressed = signature_to_G2(g2_bytes_points[0])
        self.assertEqual(g2_point_0, G2)


class TestIsPowerOfTwo(unittest.TestCase):
    def test_power_of_two(self):
        self.assertTrue(is_power_of_two(1))  # 2^0
        self.assertTrue(is_power_of_two(2))  # 2^1
        self.assertTrue(is_power_of_two(4))  # 2^2
        self.assertTrue(is_power_of_two(1024))  # 2^10

    def test_not_power_of_two(self):
        self.assertFalse(is_power_of_two(0))  # 不是正数
        self.assertFalse(is_power_of_two(3))  # 介于 2^1 和 2^2 之间
        self.assertFalse(is_power_of_two(6))  # 2 * 3
        self.assertFalse(is_power_of_two(-8))  # 负数


class TestReverseBits(unittest.TestCase):
    def test_reverse_bits_order_8(self):
        self.assertEqual(reverse_bits(0, 8), 0)
        self.assertEqual(reverse_bits(1, 8), 4)  # 001 -> 100
        self.assertEqual(reverse_bits(2, 8), 2)  # 010 -> 010
        self.assertEqual(reverse_bits(3, 8), 6)  # 011 -> 110
        self.assertEqual(reverse_bits(4, 8), 1)  # 100 -> 001
        self.assertEqual(reverse_bits(5, 8), 5)  # 101 -> 101
        self.assertEqual(reverse_bits(6, 8), 3)  # 110 -> 011
        self.assertEqual(reverse_bits(7, 8), 7)  # 111 -> 111

    def test_reverse_bits_order_16(self):
        self.assertEqual(reverse_bits(1, 16), 8)  # 0001 -> 1000
        self.assertEqual(reverse_bits(15, 16), 15)  # 1111 -> 1111

    def test_non_power_of_two_order_raises(self):
        with self.assertRaises(AssertionError):
            reverse_bits(3, 10)  # 10 is not power of two


class TestBitReversalPermutation(unittest.TestCase):
    def test_bit_reversal_order_8(self):
        input_sequence = list(range(8))
        output_sequence = bit_reversal_permutation(input_sequence)
        expected_sequence = [0, 4, 2, 6, 1, 5, 3, 7]
        self.assertEqual(output_sequence, expected_sequence)

    def test_bit_reversal_order_4(self):
        input_sequence = ["a", "b", "c", "d"]  # indices 0-3
        output_sequence = bit_reversal_permutation(input_sequence)
        # reverse_bits(0,4)=0, (1)=2, (2)=1, (3)=3
        expected_sequence = ["a", "c", "b", "d"]
        self.assertEqual(output_sequence, expected_sequence)

    def test_empty_sequence(self):
        self.assertEqual(bit_reversal_permutation([]), [])

    def test_single_element(self):
        self.assertEqual(bit_reversal_permutation([42]), [42])


class TestHashToBLSField(unittest.TestCase):
    def test_same_input_produces_same_output(self):
        data = b"hello world"
        h1 = hash_to_bls_field(data)
        h2 = hash_to_bls_field(data)
        self.assertEqual(h1, h2)

    def test_different_inputs_produce_different_outputs(self):
        h1 = hash_to_bls_field(b"data1")
        h2 = hash_to_bls_field(b"data2")
        self.assertNotEqual(h1, h2)

    def test_output_within_field(self):
        data = b"arbitrary"
        result = hash_to_bls_field(data)
        self.assertTrue(0 <= int(result) < BLS_MODULUS)

    def test_empty_data(self):
        result = hash_to_bls_field(b"")
        self.assertTrue(0 <= int(result) < BLS_MODULUS)


class TestBytesToBlsField(unittest.TestCase):
    def test_bytes_to_bls_field_valid(self):
        # 构造一个合法的字节序列（小于 BLS_MODULUS）
        valid_bytes = (BLS_MODULUS - 1).to_bytes(32, "big")  # 32字节，取BLS_MODULUS减1
        result = bytes_to_bls_field(valid_bytes)
        self.assertEqual(result, BLSFieldElement(BLS_MODULUS - 1))

    def test_bytes_to_bls_field_invalid(self):
        # 构造一个非法的字节序列（大于或等于 BLS_MODULUS）
        invalid_bytes = BLS_MODULUS.to_bytes(32, "big")  # 32字节，等于BLS_MODULUS
        with self.assertRaises(AssertionError):
            bytes_to_bls_field(invalid_bytes)


class TestValidateKzgG1(unittest.TestCase):
    def test_valid_g1(self):
        # 生成一个有效的私钥（32字节随机数）
        private_key = (
            12345678901234567890123456789012  # 示例私钥，实际上应该是随机生成的
        )

        # 通过 SkToPk 方法生成公钥字节数据
        public_key_bytes = bls.SkToPk(private_key)

        # 调用 validate_kzg_g1 函数验证公钥
        try:
            validate_kzg_g1(public_key_bytes)
        except AssertionError:
            self.fail(
                "validate_kzg_g1 raised AssertionError unexpectedly for valid G1 point!"
            )

    def test_infinity_g1(self):
        # 使用无穷大的 G1 点
        try:
            validate_kzg_g1(G1_POINT_AT_INFINITY)
        except AssertionError:
            self.fail(
                "validate_kzg_g1 raised AssertionError unexpectedly for infinity point!"
            )

    def test_invalid_g1(self):
        # 传入无效的 G1 点，应该触发异常
        invalid_g1_bytes = (
            b"\xff" * 48
        )  # 无效的 G1 点（这里只是示例，可以使用无效数据）
        with self.assertRaises(AssertionError):
            validate_kzg_g1(invalid_g1_bytes)


class TestBytesToKZGCommitment(unittest.TestCase):
    def test_bytes_to_kzg_commitment_valid(self):
        _, g1_points = load_trusted_setup()
        valid_bytes = g1_points[10]
        try:
            commitment = bytes_to_kzg_commitment(valid_bytes)
            self.assertIsInstance(commitment, bytes)
            self.assertEqual(len(commitment), 48)
        except AssertionError:
            self.fail("bytes_to_kzg_commitment raised AssertionError unexpectedly!")

    def test_bytes_to_kzg_commitment_invalid(self):
        # Create invalid bytes (this will raise an assertion error in validate_kzg_g1)
        invalid_bytes = bytes.fromhex("f0" * 47)  # 47 bytes instead of 48
        with self.assertRaises(AssertionError):
            bytes_to_kzg_commitment(invalid_bytes)


class TestBlobToPolynomial(unittest.TestCase):
    def test_blob_to_polynomial_length_and_type(self):
        # 构造一个全为 0 的 blob
        blob = Blob(bytes(FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT))
        poly = blob_to_polynomial(blob)

        # 验证多项式长度
        self.assertEqual(len(poly), FIELD_ELEMENTS_PER_BLOB)

        # 验证每个元素是 BLSFieldElement（即 int 且 < BLS_MODULUS）
        for i in range(FIELD_ELEMENTS_PER_BLOB):
            self.assertIsInstance(poly[i], BLSFieldElement)
            self.assertGreaterEqual(poly[i], 0)
            self.assertLess(poly[i], BLS_MODULUS)

    def test_blob_to_polynomial_with_known_values(self):
        # 前 4 个字段放 0, 1, 2, 3，其余填 0
        blob_bytes = bytearray()
        for i in range(4):
            blob_bytes += i.to_bytes(BYTES_PER_FIELD_ELEMENT, ENDIANNESS)
        for _ in range(FIELD_ELEMENTS_PER_BLOB - 4):
            blob_bytes += (0).to_bytes(BYTES_PER_FIELD_ELEMENT, ENDIANNESS)

        blob = Blob(blob_bytes)
        poly = blob_to_polynomial(blob)

        # 校验前四个值
        for i in range(4):
            self.assertEqual(poly[i], BLSFieldElement(i))

        # 剩下应该全是 0
        for i in range(4, FIELD_ELEMENTS_PER_BLOB):
            self.assertEqual(poly[i], BLSFieldElement(0))


class TestComputeChallenge(unittest.TestCase):
    def setUp(self):
        # 构造一个长度为 BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB 的全 0 blob
        self.zero_blob = Blob(bytes(BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB))
        # 随便从 trusted setup 拿一个合法 commitment
        _, g1_points = load_trusted_setup()
        self.commitment = KZGCommitment(g1_points[0])  # bytes48 合法的

    def test_output_type_is_bls_field_element(self):
        challenge = compute_challenge(self.zero_blob, self.commitment)
        self.assertIsInstance(challenge, BLSFieldElement)

    def test_different_inputs_give_different_challenges(self):
        # 构造另一个不一样的 blob
        one_blob = Blob(b"\x01" * BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB)
        challenge1 = compute_challenge(self.zero_blob, self.commitment)
        challenge2 = compute_challenge(one_blob, self.commitment)
        self.assertNotEqual(challenge1, challenge2)

    def test_same_inputs_give_same_challenge(self):
        challenge1 = compute_challenge(self.zero_blob, self.commitment)
        challenge2 = compute_challenge(self.zero_blob, self.commitment)
        self.assertEqual(challenge1, challenge2)

    def test_challenge_differs_with_commitment(self):
        _, g1_points = load_trusted_setup()
        another_commitment = KZGCommitment(g1_points[1])
        challenge1 = compute_challenge(self.zero_blob, self.commitment)
        challenge2 = compute_challenge(self.zero_blob, another_commitment)
        self.assertNotEqual(challenge1, challenge2)


class TestBLSModularInverse(unittest.TestCase):
    def test_modular_inverse_nonzero(self):
        # 选择一个非零的 BLSFieldElement（假设 BLS_MODULUS 较大且为素数）
        x = BLSFieldElement(2)
        expected_inverse = BLSFieldElement(
            pow(x, -1, BLS_MODULUS)
        )  # 使用 pow 函数直接计算预期逆元素
        self.assertEqual(bls_modular_inverse(x), expected_inverse)

    def test_modular_inverse_zero(self):
        # 测试 x 为 0 时的情况
        x = BLSFieldElement(0)
        self.assertEqual(bls_modular_inverse(x), BLSFieldElement(0))

    def test_modular_inverse_with_modulus(self):
        # 测试 BLS_MODULUS - 1 的情况
        x = BLSFieldElement(BLS_MODULUS - 1)
        expected_inverse = BLSFieldElement(
            BLS_MODULUS - 1
        )  # BLS_MODULUS - 1 和其自身互为逆
        self.assertEqual(bls_modular_inverse(x), expected_inverse)


class TestDivFunction(unittest.TestCase):
    def test_div_normal(self):
        # 正常情况下的除法
        x = BLSFieldElement(10)
        y = BLSFieldElement(3)

        expected_result = BLSFieldElement(
            (int(x) * int(bls_modular_inverse(y))) % BLS_MODULUS
        )
        result = div(x, y)

        self.assertEqual(result, expected_result)

    def test_div_by_one(self):
        # 除以 1 的情况
        x = BLSFieldElement(15)
        y = BLSFieldElement(1)

        expected_result = x  # 因为除以 1 应该返回 x 本身
        result = div(x, y)

        self.assertEqual(result, expected_result)

    def test_div_zero_dividend(self):
        # 被除数为 0 的情况
        x = BLSFieldElement(0)
        y = BLSFieldElement(5)

        expected_result = BLSFieldElement(0)  # 0 除以任何数都是 0
        result = div(x, y)

        self.assertEqual(result, expected_result)

    def test_div_zero_divisor(self):
        # 除数为 0 的情况 (这里我们假设 div(x, 0) 返回 0，或者抛出异常，根据设计)
        x = BLSFieldElement(5)
        y = BLSFieldElement(0)

        # 如果遇到除数为零，应该有一个定义的行为（如返回零或者抛出异常），这里假设返回零
        expected_result = BLSFieldElement(0)  # 或者可能抛出一个异常
        result = div(x, y)

        self.assertEqual(
            result, expected_result
        )  # 根据设计，可以根据需求进行异常处理测试

    def test_div_large_numbers(self):
        # 除法中使用接近 BLS_MODULUS 的值
        x = BLSFieldElement(BLS_MODULUS - 1)
        y = BLSFieldElement(BLS_MODULUS - 2)

        # 计算 modular inverse 和进行除法操作
        expected_result = BLSFieldElement(
            (int(x) * int(bls_modular_inverse(y))) % BLS_MODULUS
        )
        result = div(x, y)

        self.assertEqual(result, expected_result)


class TestG1Lincomb(unittest.TestCase):
    def test_single_term(self):
        # 单个点 × 标量
        point = bls.G1_to_bytes48(G1)
        scalar = BLSFieldElement(3)
        result = g1_lincomb([point], [scalar])
        expected = bls.G1_to_bytes48(multiply(G1, int(scalar)))
        self.assertEqual(result, expected)

    def test_zero_scalars(self):
        # 所有标量为 0，结果应为 Z1()
        point1 = bls.G1_to_bytes48(G1)
        point2 = bls.G1_to_bytes48(multiply(G1, 5))
        result = g1_lincomb([point1, point2], [BLSFieldElement(0), BLSFieldElement(0)])
        expected = bls.G1_to_bytes48(Z1)
        self.assertEqual(result, expected)

    def test_multiple_terms(self):
        # 多项混合，检查总和是否正确
        p1 = G1
        p2 = multiply(G1, 2)
        s1 = BLSFieldElement(2)
        s2 = BLSFieldElement(3)
        expected_g1 = add(multiply(p1, int(s1)), multiply(p2, int(s2)))

        point_bytes = [bls.G1_to_bytes48(p1), bls.G1_to_bytes48(p2)]
        scalars = [s1, s2]

        result = g1_lincomb(point_bytes, scalars)
        self.assertEqual(result, bls.G1_to_bytes48(expected_g1))

    def test_empty_inputs(self):
        # 空输入应返回 G1 零元
        result = g1_lincomb([], [])
        self.assertEqual(result, bls.G1_to_bytes48(Z1))

    def test_length_mismatch_assertion(self):
        # 不匹配的输入长度应该断言失败
        point = bls.G1_to_bytes48(G1)
        with self.assertRaises(AssertionError):
            g1_lincomb([point], [BLSFieldElement(1), BLSFieldElement(2)])


class TestEvaluatePolynomialInEvaluationForm(unittest.TestCase):
    def setUp(self):
        self.domain = ROOTS_OF_UNITY
        self.width = FIELD_ELEMENTS_PER_BLOB

    def test_evaluation_on_root_of_unity(self):
        # poly[i] 表示在 domain[i] 上的值，因此 index 也要 BRP 排列
        normal_values = [BLSFieldElement(i + 1) for i in range(self.width)]
        poly = bit_reversal_permutation(normal_values)

        z = self.domain[10]
        result = evaluate_polynomial_in_evaluation_form(poly, z)
        self.assertEqual(result, normal_values[10])

    def test_zero_polynomial(self):
        poly = [BLSFieldElement(0) for _ in range(self.width)]
        z = BLSFieldElement(123456789)
        result = evaluate_polynomial_in_evaluation_form(poly, z)
        self.assertEqual(result, BLSFieldElement(0))

    def test_constant_polynomial(self):
        value = BLSFieldElement(7)
        normal_values = [value for _ in range(self.width)]
        poly = bit_reversal_permutation(normal_values)

        z = BLSFieldElement(67890)
        result = evaluate_polynomial_in_evaluation_form(poly, z)
        self.assertEqual(result, value)

    def test_linear_polynomial_f_x_eq_x_plus_1(self):
        # 构造 f(x) = x + 1 的 evaluation form
        normal_values = [
            BLSFieldElement((int(x) + 1) % BLS_MODULUS) for x in self.domain
        ]
        poly = bit_reversal_permutation(normal_values)

        z = BLSFieldElement(42)
        expected = BLSFieldElement(int(z) + 1)
        result = evaluate_polynomial_in_evaluation_form(poly, z)
        self.assertEqual(result, expected)

    def test_z_approaching_domain(self):
        normal_values = [
            BLSFieldElement((i * 3 + 2) % BLS_MODULUS) for i in range(self.width)
        ]
        poly = bit_reversal_permutation(normal_values)

        # z 接近 ROOTS_OF_UNITY[0] + 1
        z = BLSFieldElement((int(self.domain[0]) + 1) % BLS_MODULUS)
        result = evaluate_polynomial_in_evaluation_form(poly, z)
        self.assertIsInstance(result, BLSFieldElement)

    def test_invalid_polynomial_length(self):
        poly = [BLSFieldElement(1) for _ in range(self.width - 1)]
        z = BLSFieldElement(100)
        with self.assertRaises(AssertionError):
            evaluate_polynomial_in_evaluation_form(poly, z)


class TestBlobToKZGCommitment(unittest.TestCase):
    def setUp(self):
        # 常量
        self.bytes_per_element = BYTES_PER_FIELD_ELEMENT  # 通常是 32
        self.num_elements = FIELD_ELEMENTS_PER_BLOB  # 通常是 4096
        self.expected_blob_len = self.bytes_per_element * self.num_elements

        # 构造一个合法 Blob，元素递增，每个 field element 是 32 字节
        self.blob = Blob(
            b"".join(
                (i.to_bytes(self.bytes_per_element, "big"))
                for i in range(self.num_elements)
            )
        )

    def test_blob_to_kzg_commitment_correctness(self):
        # 执行被测函数
        commitment = blob_to_kzg_commitment(self.blob)

        # 类型检查
        self.assertIsInstance(commitment, KZGCommitment)
        self.assertEqual(len(commitment), 48)  # Bytes48 检查

        # 手动计算 expected commitment
        poly = blob_to_polynomial(self.blob)
        lagrange_brp = bit_reversal_permutation(KZG_SETUP_LAGRANGE)
        expected_commitment = g1_lincomb(lagrange_brp, poly)

        # 断言一致性（字节层面）
        self.assertEqual(commitment, expected_commitment)

    def test_all_zero_blob(self):
        blob = Blob(bytes([0] * self.expected_blob_len))
        commitment = blob_to_kzg_commitment(blob)

        expected_commitment = KZGCommitment(G1_to_pubkey(Z1))
        self.assertEqual(commitment, expected_commitment)

    def test_first_one_rest_zero_blob(self):
        # 构造第一个元素为 1，其余为 0 的 blob（big endian 编码）
        blob_bytes = (
            b"\x00" * 31
            + b"\x01"
            + b"\x00" * (self.expected_blob_len - self.bytes_per_element)
        )
        blob = Blob(blob_bytes)
        commitment = blob_to_kzg_commitment(blob)

        # poly = [1, 0, ..., 0] -> commitment = KZG_SETUP_LAGRANGE[0] after bit reversal
        expected_commitment = KZGCommitment(
            bit_reversal_permutation(KZG_SETUP_LAGRANGE)[0]
        )
        self.assertEqual(commitment, expected_commitment)


class TestComputeQuotientEvalWithinDomain(unittest.TestCase):
    def setUp(self):
        self.domain = bit_reversal_permutation(ROOTS_OF_UNITY)
        self.num_elements = len(self.domain)

    def test_quotient_eval_identity(self):
        poly = [(omega + 1) % BLS_MODULUS for omega in self.domain]  # f(ωᵢ) = ωᵢ + 1
        z = self.domain[10]
        y = (z + 1) % BLS_MODULUS
        q_z = compute_quotient_eval_within_domain(z, poly, y)
        self.assertEqual(q_z, BLSFieldElement(1))

    def test_quotient_eval_quadratic(self):
        poly = [
            (pow(omega, 2, BLS_MODULUS) + 1) % BLS_MODULUS for omega in self.domain
        ]  # f(ωᵢ) = ωᵢ² + 1
        z = self.domain[17]
        y = (z * z + 1) % BLS_MODULUS
        q_z = compute_quotient_eval_within_domain(z, poly, y)
        expected = (2 * z) % BLS_MODULUS
        self.assertEqual(q_z, BLSFieldElement(expected))

    def test_quotient_eval_constant(self):
        poly = [BLSFieldElement(5) for _ in self.domain]  # f(x) = 5
        z = self.domain[3]
        y = 5
        q_z = compute_quotient_eval_within_domain(z, poly, y)
        self.assertEqual(q_z, BLSFieldElement(0))


class TestComputeKZGProof(unittest.TestCase):
    def setUp(self):
        self.domain = bit_reversal_permutation(ROOTS_OF_UNITY)

    def test_kzg_proof_linear_polynomial(self):
        # 构造 p(x) = x + 1 -> f(ωᵢ) = ωᵢ + 1
        evaluations = [(omega + 1) % BLS_MODULUS for omega in self.domain]
        blob = b"".join(e.to_bytes(32, "big") for e in evaluations)
        self.assertEqual(len(blob), BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB)

        # 选择一个非 root 的点 z
        z = BLSFieldElement(12345678901234567890)
        z_bytes = int(z).to_bytes(32, "big")

        # 计算 proof
        proof = compute_kzg_proof(blob, z_bytes)

        # 构造 expected proof: quotient polynomial 恒为 1
        one_poly = [BLSFieldElement(1)] * FIELD_ELEMENTS_PER_BLOB
        expected_commitment = g1_lincomb(
            bit_reversal_permutation(KZG_SETUP_LAGRANGE), one_poly
        )

        self.assertEqual(proof, KZGProof(expected_commitment))


class TestKZGProofVerification(unittest.TestCase):
    def test_proof_verification_linear_poly(self):
        # 构造 blob 对应 f(x) = x + 1 in evaluation form
        domain = bit_reversal_permutation(ROOTS_OF_UNITY)
        poly = [(omega + 1) % BLS_MODULUS for omega in domain]
        blob = b"".join(x.to_bytes(32, "big") for x in poly)
        self.assertEqual(len(blob), 131072)

        # 选取验证点 z
        z = domain[123]
        y = (z + 1) % BLS_MODULUS

        # for i, x in enumerate(ROOTS_OF_UNITY[:5]):
        #     print(f"ROOTS_OF_UNITY[{i}] = {x}, type = {type(x)}")

        # print("z =", z)
        # print("int(z) =", int(z))
        # print("bit_length =", int(z).bit_length())
        # print("bit length of z:", z.bit_length())
        # 使用公开 API 生成 commitment
        commitment = blob_to_kzg_commitment(blob)
        commitment_bytes = bytes(commitment)

        # 生成 proof
        proof = compute_kzg_proof(blob, int(z).to_bytes(32, "big"))
        proof_bytes = bytes(proof)

        # 验证 proof
        result = verify_kzg_proof(
            commitment_bytes,
            int(z).to_bytes(32, "big"),
            int(y).to_bytes(32, "big"),
            proof_bytes,
        )
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
