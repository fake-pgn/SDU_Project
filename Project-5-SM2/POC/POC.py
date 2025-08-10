import secrets
import binascii
from hashlib import sha256
from gmssl import sm3, func
import functools
import time
from concurrent.futures import ThreadPoolExecutor

# SM2椭圆曲线参数
ECC_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
ECC_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
G = (X, Y)
HASH_SIZE = 32

# 预计算缓存
ZA_CACHE = {}
POINT_ADD_CACHE = {}
MOD_INV_CACHE = {}


def constant_time_compare(a, b):
    """常数时间比较，防止时序攻击"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def mod_inv(value, modulus):
    """计算模逆元 (扩展欧几里得算法)"""
    cache_key = (value, modulus)
    if cache_key in MOD_INV_CACHE:
        return MOD_INV_CACHE[cache_key]

    if value == 0:
        return 0
    lm, hm = 1, 0
    low, high = value % modulus, modulus

    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low

    result = lm % modulus
    MOD_INV_CACHE[cache_key] = result
    return result


def ec_point_add(pt1, pt2):
    """椭圆曲线点加法"""
    cache_key = (pt1, pt2)
    if cache_key in POINT_ADD_CACHE:
        return POINT_ADD_CACHE[cache_key]

    if pt1 == (0, 0):
        return pt2
    if pt2 == (0, 0):
        return pt1

    x1, y1 = pt1
    x2, y2 = pt2

    if x1 == x2:
        if y1 == y2:
            slope = (3 * x1 * x1 + ECC_A) * mod_inv(2 * y1, P)
        else:
            result = (0, 0)
            POINT_ADD_CACHE[cache_key] = result
            return result
    else:
        slope = (y2 - y1) * mod_inv(x2 - x1, P)

    slope %= P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P

    result = (x3, y3)
    POINT_ADD_CACHE[cache_key] = result
    return result


def ec_point_mult(scalar, point):
    """标量点乘 (高效double-and-add算法)"""
    if scalar == 0 or scalar >= n:
        raise ValueError("无效的标量值")

    result = (0, 0)  # 无穷远点
    addend = point

    while scalar:
        if scalar & 1:
            result = ec_point_add(result, addend)
        addend = ec_point_add(addend, addend)
        scalar >>= 1

    return result


@functools.lru_cache(maxsize=128)
def compute_user_hash(user_id, pub_x, pub_y):
    """计算用户标识哈希ZA (SM3)"""
    cache_key = (user_id, pub_x, pub_y)
    if cache_key in ZA_CACHE:
        return ZA_CACHE[cache_key]

    id_bitlen = len(user_id.encode('utf-8')) * 8
    id_bitlen_bytes = id_bitlen.to_bytes(2, 'big')

    components = [
        id_bitlen_bytes,
        user_id.encode('utf-8'),
        ECC_A.to_bytes(32, 'big'),
        ECC_B.to_bytes(32, 'big'),
        X.to_bytes(32, 'big'),
        Y.to_bytes(32, 'big'),
        pub_x.to_bytes(32, 'big'),
        pub_y.to_bytes(32, 'big')
    ]
    joint_bytes = b''.join(components)

    hash_bytes = func.bytes_to_list(joint_bytes)
    result = sm3.sm3_hash(hash_bytes)

    ZA_CACHE[cache_key] = result
    return result


def generate_keypair():
    """生成SM2密钥对"""
    private = secrets.randbelow(n - 1) + 1
    public = ec_point_mult(private, G)
    return private, public


def generate_signature(private_key, message, user_id, public_key, k_value=None):
    """生成SM2签名，允许指定k值（用于测试）"""
    # 计算ZA
    za = compute_user_hash(user_id, public_key[0], public_key[1])
    msg_full = za + message
    msg_bytes = msg_full.encode('utf-8')

    # 计算消息哈希
    hash_value = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    e_value = int(hash_value, 16)

    # 如果未指定k值，则随机生成
    if k_value is None:
        k_seed = str(private_key) + message + str(time.time_ns())
        k_value = int(sha256(k_seed.encode()).hexdigest(), 16) % n
    else:
        k_value = k_value % n

    temp_point = ec_point_mult(k_value, G)
    x_temp = temp_point[0]

    r_value = (e_value + x_temp) % n
    if r_value == 0 or r_value + k_value == n:
        return None

    s_value = mod_inv(1 + private_key, n)
    s_value = s_value * (k_value - r_value * private_key) % n

    return (r_value, s_value)


def verify_signature(public_key, message, user_id, signature):
    """验证SM2签名"""
    r_value, s_value = signature

    if not (0 < r_value < n and 0 < s_value < n):
        return False

    # 计算ZA
    za = compute_user_hash(user_id, public_key[0], public_key[1])
    msg_full = za + message
    msg_bytes = msg_full.encode('utf-8')

    # 计算消息哈希
    hash_value = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    e_value = int(hash_value, 16)

    # 计算t值
    t_value = (r_value + s_value) % n

    # 计算验证点
    point1 = ec_point_mult(s_value, G)
    point2 = ec_point_mult(t_value, public_key)
    result_point = ec_point_add(point1, point2)

    # 计算R值并验证
    R_calculated = (e_value + result_point[0]) % n

    return constant_time_compare(r_value.to_bytes(32, 'big'), R_calculated.to_bytes(32, 'big'))


def kdf(z, klen):
    """密钥派生函数 (KDF) - 使用SM3"""
    ct = 0x00000001
    ha = b''
    klen_bytes = (klen + 7) // 8

    iterations = (klen_bytes + HASH_SIZE - 1) // HASH_SIZE

    for _ in range(iterations):
        input_data = z + ct.to_bytes(4, 'big')
        hash_list = func.bytes_to_list(input_data)
        hash_hex = sm3.sm3_hash(hash_list)
        ha += bytes.fromhex(hash_hex)
        ct += 1

    return ha[:klen_bytes]


def sm2_encrypt(public_key, plaintext):
    """SM2加密算法"""
    if public_key == (0, 0):
        raise ValueError("公钥无效 (无穷远点)")

    k = secrets.randbelow(n - 1) + 1

    # 计算C1 = k * G
    C1_point = ec_point_mult(k, G)
    C1_x, C1_y = C1_point

    # 计算点(x2, y2) = k * Pb
    kPb_point = ec_point_mult(k, public_key)
    x2, y2 = kPb_point

    x2_bytes = x2.to_bytes(32, 'big')
    y2_bytes = y2.to_bytes(32, 'big')

    # 计算t = KDF(x2 || y2, 明文长度)
    t = kdf(x2_bytes + y2_bytes, len(plaintext) * 8)

    if all(b == 0 for b in t):
        raise ValueError("KDF输出全零，需要重新加密")

    # 计算C2 = 明文 XOR t
    C2 = bytes(a ^ b for a, b in zip(plaintext, t))

    # 计算C3 = Hash(x2 || 明文 || y2)
    input_C3 = x2_bytes + plaintext + y2_bytes
    hash_list = func.bytes_to_list(input_C3)
    C3 = bytes.fromhex(sm3.sm3_hash(hash_list))

    # 构建密文: C1 || C3 || C2
    C1_bytes = C1_x.to_bytes(32, 'big') + C1_y.to_bytes(32, 'big')
    return C1_bytes + C3 + C2


def sm2_decrypt(private_key, ciphertext):
    """SM2解密算法"""
    min_length = 64 + 32 + 1
    if len(ciphertext) < min_length:
        raise ValueError(f"密文长度无效 (最小长度 {min_length} 字节, 实际 {len(ciphertext)} 字节)")

    C1_bytes = ciphertext[:64]
    C1_x = int.from_bytes(C1_bytes[:32], 'big')
    C1_y = int.from_bytes(C1_bytes[32:64], 'big')
    C1_point = (C1_x, C1_y)

    C3 = ciphertext[64:96]
    C2 = ciphertext[96:]

    # 计算点(x2, y2) = dB * C1
    x2y2_point = ec_point_mult(private_key, C1_point)
    x2, y2 = x2y2_point

    x2_bytes = x2.to_bytes(32, 'big')
    y2_bytes = y2.to_bytes(32, 'big')

    # 计算t = KDF(x2 || y2, C2长度)
    t = kdf(x2_bytes + y2_bytes, len(C2) * 8)

    if all(b == 0 for b in t):
        raise ValueError("KDF输出全零，解密失败")

    # 计算明文 = C2 XOR t
    plaintext = bytes(a ^ b for a, b in zip(C2, t))

    # 验证C3 = Hash(x2 || 明文 || y2)
    input_C3 = x2_bytes + plaintext + y2_bytes
    hash_list = func.bytes_to_list(input_C3)
    u = bytes.fromhex(sm3.sm3_hash(hash_list))

    if not constant_time_compare(u, C3):
        raise ValueError("哈希验证失败，密文可能被篡改")

    return plaintext


def batch_verify_signatures(public_key, messages, user_ids, signatures):
    """批量验证SM2签名"""
    with ThreadPoolExecutor() as executor:
        params = [(public_key, msg, uid, sig) for msg, uid, sig in zip(messages, user_ids, signatures)]
        results = list(executor.map(lambda p: verify_signature(*p), params))
    return results


# 点压缩
def compress_point(point):
    """压缩椭圆曲线点"""
    x, y = point
    prefix = 0x02 if y % 2 == 0 else 0x03
    return prefix.to_bytes(1, 'big') + x.to_bytes(32, 'big')


def decompress_point(compressed):
    """解压缩椭圆曲线点"""
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], 'big')

    y_sq = (x * x * x + ECC_A * x + ECC_B) % P
    y = pow(y_sq, (P + 1) // 4, P)

    if prefix == 0x02:
        return (x, y if y % 2 == 0 else P - y)
    else:
        return (x, y if y % 2 == 1 else P - y)


# ================ 签名误用POC验证 ================

def ecdsa_sign(private_key, message, k_value=None):
    """ECDSA签名（使用相同的椭圆曲线参数），允许指定k值（用于测试）"""
    msg_bytes = message.encode('utf-8')
    hash_value = sha256(msg_bytes).digest()
    e_value = int.from_bytes(hash_value, 'big') % n

    if k_value is None:
        k_value = secrets.randbelow(n - 1) + 1
    else:
        k_value = k_value % n

    temp_point = ec_point_mult(k_value, G)
    r_value = temp_point[0] % n
    if r_value == 0:
        return None

    s_value = mod_inv(k_value, n) * (e_value + private_key * r_value) % n
    if s_value == 0:
        return None

    return (r_value, s_value)


def poc_leaking_k():
    """POC验证：随机数k泄露导致私钥泄露"""
    print("\n===== POC验证：随机数k泄露导致私钥泄露 =====")

    # 生成密钥对
    private, public = generate_keypair()
    user_id = "test_user"
    print(f"原始私钥: {hex(private)}")

    # 生成签名并记录使用的k值
    msg = "测试消息"
    k_value = secrets.randbelow(n - 1) + 1
    signature = generate_signature(private, msg, user_id, public, k_value)
    r, s = signature

    # 从泄露的k恢复私钥
    # 公式: dA = (k - s) * (s + r)^(-1) mod n
    denominator = (s + r) % n
    if denominator == 0:
        print("错误：分母为零，无法恢复私钥")
        return

    inv_denom = mod_inv(denominator, n)
    recovered_private = ((k_value - s) * inv_denom) % n

    print(f"使用的随机数k: {hex(k_value)}")
    print(f"恢复的私钥: {hex(recovered_private)}")
    print(f"恢复结果: {private == recovered_private}")


def poc_same_user_reused_k():
    """POC验证：同一用户重复使用k导致私钥泄露"""
    print("\n===== POC验证：同一用户重复使用k导致私钥泄露 =====")

    # 生成密钥对
    private, public = generate_keypair()
    user_id = "test_user"
    print(f"原始私钥: {hex(private)}")

    # 使用相同的k为两个消息生成签名
    k_value = secrets.randbelow(n - 1) + 1
    msg1 = "消息1"
    msg2 = "消息2"

    sig1 = generate_signature(private, msg1, user_id, public, k_value)
    sig2 = generate_signature(private, msg2, user_id, public, k_value)

    # 计算两个消息的哈希值
    za = compute_user_hash(user_id, public[0], public[1])

    msg_full1 = za + msg1
    msg_bytes1 = msg_full1.encode('utf-8')
    hash_value1 = sm3.sm3_hash(func.bytes_to_list(msg_bytes1))
    e1 = int(hash_value1, 16)

    msg_full2 = za + msg2
    msg_bytes2 = msg_full2.encode('utf-8')
    hash_value2 = sm3.sm3_hash(func.bytes_to_list(msg_bytes2))
    e2 = int(hash_value2, 16)

    # 恢复私钥
    r1, s1 = sig1
    r2, s2 = sig2

    # 推导公式：dA = (s2 - s1) / (s1 - s2 + r1 - r2) mod n
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    if denominator == 0:
        print("错误：分母为零，无法恢复私钥")
        return

    inv_denom = mod_inv(denominator, n)
    recovered_private = numerator * inv_denom % n

    print(f"恢复的私钥: {hex(recovered_private)}")
    print(f"恢复结果: {private == recovered_private}")


def poc_different_users_same_k():
    """POC验证：不同用户使用相同的k导致私钥泄露"""
    print("\n===== POC验证：不同用户使用相同的k导致私钥泄露 =====")

    # 用户A
    private_A, public_A = generate_keypair()
    user_id_A = "userA"
    print(f"用户A原始私钥: {hex(private_A)}")

    # 用户B
    private_B, public_B = generate_keypair()
    user_id_B = "userB"
    print(f"用户B原始私钥: {hex(private_B)}")

    # 使用相同的k
    k_value = secrets.randbelow(n - 1) + 1

    # 用户A签名
    msgA = "AAA"
    sigA = generate_signature(private_A, msgA, user_id_A, public_A, k_value)

    # 用户B签名
    msgB = "BBB"
    sigB = generate_signature(private_B, msgB, user_id_B, public_B, k_value)

    # 计算用户A的k值（用户B恢复用户A私钥）
    # 公式: k = sA*(1+dA) + rA*dA mod n
    rA, sA = sigA
    k_recovered = (sA * (1 + private_A) + rA * private_A) % n

    # 恢复用户B的私钥（使用用户A的私钥）
    # 公式: dB = (k - sB) * inv(sB + rB, n) mod n
    rB, sB = sigB
    denominator = (sB + rB) % n
    if denominator == 0:
        print("错误：分母为零，无法恢复私钥")
        return

    inv_denom = mod_inv(denominator, n)
    recovered_private_B = ((k_recovered - sB) * inv_denom) % n

    print(f"恢复的用户B私钥: {hex(recovered_private_B)}")
    print(f"恢复结果: {private_B == recovered_private_B}")


def poc_same_d_and_k_ecdsa_sm2():
    """POC验证：相同私钥和k在SM2和ECDSA中签名导致私钥泄露"""
    print("\n===== POC验证：相同私钥和k在SM2和ECDSA中签名导致私钥泄露 =====")

    # 生成密钥对
    private, public = generate_keypair()
    user_id = "test_user"
    print(f"原始私钥: {hex(private)}")

    # 使用相同的k
    k_value = secrets.randbelow(n - 1) + 1

    # ECDSA签名
    ecdsa_msg = "ECDSA消息"
    ecdsa_sig = ecdsa_sign(private, ecdsa_msg, k_value)

    # SM2签名
    sm2_msg = "SM2消息"
    sm2_sig = generate_signature(private, sm2_msg, user_id, public, k_value)

    # 计算ECDSA消息哈希
    ecdsa_msg_bytes = ecdsa_msg.encode('utf-8')
    e1 = int.from_bytes(sha256(ecdsa_msg_bytes).digest(), 'big') % n

    # 计算SM2消息哈希
    za = compute_user_hash(user_id, public[0], public[1])
    msg_full = za + sm2_msg
    msg_bytes = msg_full.encode('utf-8')
    hash_value = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    e2 = int(hash_value, 16)

    # 恢复私钥
    r1, s1 = ecdsa_sig
    r2, s2 = sm2_sig

    # 推导公式：d = (s1*s2 - e1) * inv(r1 - s1*s2 - s1*r2, n) mod n
    numerator = (s1 * s2 - e1) % n
    denominator = (r1 - s1 * s2 - s1 * r2) % n
    if denominator == 0:
        print("错误：分母为零，无法恢复私钥")
        return

    inv_denom = mod_inv(denominator, n)
    recovered_private = numerator * inv_denom % n

    print(f"恢复的私钥: {hex(recovered_private)}")
    print(f"恢复结果: {private == recovered_private}")


def main():
    # 执行所有POC验证
    poc_leaking_k()
    poc_same_user_reused_k()
    poc_different_users_same_k()
    poc_same_d_and_k_ecdsa_sm2()


if __name__ == "__main__":
    main()