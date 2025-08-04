import random
from ecdsa import NIST256p, ellipticcurve
from phe import paillier
import hashlib
import time
from typing import List, Tuple, Any


class DDHPSIProtocol:
    def __init__(self):
        self.curve = NIST256p
        self.generator = self.curve.generator
        self.order = self.curve.order
        self.curve_params = self.curve.curve

    def hash_to_point(self, identifier: str) -> ellipticcurve.Point:
        """将标识符哈希到椭圆曲线上的点"""
        data = identifier.encode()
        digest = hashlib.sha256(data).digest()
        x = int.from_bytes(digest, 'big') % self.curve_params.p()

        # 求解 y^2 = x^3 + a*x + b
        for _ in range(3):
            y_sq = (x ** 3 + self.curve_params.a() * x + self.curve_params.b()) % self.curve_params.p()
            y = pow(y_sq, (self.curve_params.p() + 1) // 4, self.curve_params.p())

            # 检查点是否在曲线上
            if (y * y) % self.curve_params.p() == y_sq:
                return ellipticcurve.Point(self.curve_params, x, y)

            # 若不是二次剩余，尝试下一个x值
            x = (x + 1) % self.curve_params.p()

        return self.generator


class P1:
    """客户端实现"""

    def __init__(self, identifiers: List[str]):
        self.identifiers = identifiers
        self.psi_protocol = DDHPSIProtocol()
        self.k1 = random.randint(1, self.psi_protocol.order - 1)  # 客户端私钥
        self.intersection_size = 0  # 交集大小

    def round1(self) -> List[Tuple[int, int]]:
        """P1 第1轮: 计算并打乱 H(v_i)^k1"""
        points = []
        for v in self.identifiers:
            point = self.psi_protocol.hash_to_point(v)
            # 乘以k1: H(v_i)^k1
            encrypted_point = point * self.k1
            points.append((encrypted_point.x(), encrypted_point.y()))

        # 打乱点顺序
        random.shuffle(points)
        return points

    def round3(self,
               b_points: List[Tuple[int, int]],
               c_points: List[Tuple[int, int]],
               encrypted_values: List[Any]) -> Tuple[int, Any]:
        """P1 第3轮: 计算交集和同态求和"""
        curve = self.psi_protocol.curve_params

        # 从坐标重建点
        b_points = [ellipticcurve.Point(curve, x, y) for x, y in b_points]
        c_points = [ellipticcurve.Point(curve, x, y) for x, y in c_points]

        # 计算 e_j = b_j^k1
        e_points = [point * self.k1 for point in b_points]
        c_set = {(p.x(), p.y()) for p in c_points}

        matching_indices = [
            idx for idx, e_point in enumerate(e_points)
            if (e_point.x(), e_point.y()) in c_set
        ]

        self.intersection_size = len(matching_indices)

        # 同态求和匹配的加密值
        if not encrypted_values or not matching_indices:
            # 如果没有交集，返回零的加密
            public_key = encrypted_values[0].public_key if encrypted_values else None
            return self.intersection_size, public_key.encrypt(0) if public_key else None

        sum_ciphertext = encrypted_values[matching_indices[0]]
        for idx in matching_indices[1:]:
            sum_ciphertext += encrypted_values[idx]

        return self.intersection_size, sum_ciphertext


class P2:
    """服务器端实现"""

    def __init__(self, identifier_values: List[Tuple[str, int]]):
        self.identifier_values = identifier_values
        self.psi_protocol = DDHPSIProtocol()
        self.k2 = random.randint(1, self.psi_protocol.order - 1)  # 服务器私钥
        self.paillier_public_key, self.paillier_private_key = paillier.generate_paillier_keypair()  # Paillier密钥对

    def round2(self, a_points: List[Tuple[int, int]]) -> Tuple[
        List[Tuple[int, int]],
        List[Tuple[int, int]],
        List[Any]
    ]:
        """P2 第2轮: 计算并打乱响应"""
        curve = self.psi_protocol.curve_params

        # 从坐标重建点
        a_points = [ellipticcurve.Point(curve, x, y) for x, y in a_points]

        # 预计算所有点和加密值
        b_points = []
        encrypted_values = []
        for w, t in self.identifier_values:
            point = self.psi_protocol.hash_to_point(w)
            encrypted_point = point * self.k2
            b_points.append((encrypted_point.x(), encrypted_point.y()))
            encrypted_values.append(self.paillier_public_key.encrypt(t))  # 加密关联值

        # 计算 c_i = a_i^k2
        c_points = [point * self.k2 for point in a_points]
        c_points = [(p.x(), p.y()) for p in c_points]

        # 创建组合列表并打乱
        combined = list(zip(b_points, encrypted_values))
        random.shuffle(combined)
        b_points_shuffled, encrypted_values_shuffled = zip(*combined)

        # 单独打乱c_points
        random.shuffle(c_points)

        return list(b_points_shuffled), c_points, list(encrypted_values_shuffled)

    def decrypt_sum(self, sum_ciphertext) -> int:
        """解密同态和"""
        return self.paillier_private_key.decrypt(sum_ciphertext) if sum_ciphertext else 0


def simulate_protocol(
        p1_identifiers: List[str],
        p2_data: List[Tuple[str, int]]
) -> Tuple[int, int]:
    """模拟完整协议执行"""
    # 初始化参与方
    p1 = P1(p1_identifiers)  # 客户端
    p2 = P2(p2_data)  # 服务器

    # 第1轮: P1 -> P2
    a_points = p1.round1()

    # 第2轮: P2 -> P1
    b_points, c_points, encrypted_values = p2.round2(a_points)

    # 第3轮: P1 -> P2
    intersection_size, sum_ciphertext = p1.round3(b_points, c_points, encrypted_values)

    # P2解密求和结果
    intersection_sum = p2.decrypt_sum(sum_ciphertext)

    return intersection_size, intersection_sum


# 测试协议
if __name__ == "__main__":
    print("Google password checkup")
    print("=" * 50)

    # 创建测试数据
    common_id = ["user1", "user3", "user5"]
    p1_id = common_id + ["user2", "user4"]  # 客户端标识符
    p2_data = [(id, random.randint(1, 100)) for id in common_id + ["user6", "user7"]]  # 服务器数据

    print("P1标识符:", p1_id)
    print("P2数据:", [(id, val) for id, val in p2_data])
    print()

    # 执行协议
    try:
        cardinality, total_sum = simulate_protocol(p1_id, p2_data)

        print("协议结果:")
        print(f"交集大小: {cardinality}")
        print(f"交集和: {total_sum}")

        # 验证结果
        expected_intersection = set(p1_id) & set(id for id, _ in p2_data)
        expected_sum = sum(val for id, val in p2_data if id in expected_intersection)

        print("\n验证:")
        print(f"预期交集大小: {len(expected_intersection)}")
        print(f"预期交集和: {expected_sum}")

        if cardinality == len(expected_intersection) and total_sum == expected_sum:
            print("协议结果符合预期值")
        else:
            print("协议结果不符合预期值")
            print(f"  实际交集大小: {cardinality}, 预期: {len(expected_intersection)}")
            print(f"  实际交集和: {total_sum}, 预期: {expected_sum}")
    except Exception as e:
        print(f"协议执行出错: {e}")
        import traceback

        traceback.print_exc()