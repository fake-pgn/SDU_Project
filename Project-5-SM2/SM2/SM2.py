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

#  预计算缓存
ZA_CACHE = {}
POINT_ADD_CACHE = {}
MOD_INV_CACHE = {}


# 常数时间比较
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
    # 优化: 使用缓存
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
    # 使用缓存
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
    # 使用缓存
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

    # 计算SM3哈希
    hash_bytes = func.bytes_to_list(joint_bytes)
    result = sm3.sm3_hash(hash_bytes)

    ZA_CACHE[cache_key] = result
    return result


def generate_keypair():
    """生成SM2密钥对"""
    private = secrets.randbelow(n - 1) + 1
    public = ec_point_mult(private, G)
    return private, public


def generate_signature(private_key, message, user_id, public_key):
    """生成SM2签名"""
    # 计算ZA
    za = compute_user_hash(user_id, public_key[0], public_key[1])
    msg_full = za + message
    msg_bytes = msg_full.encode('utf-8')

    # 计算消息哈希
    hash_value = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    e_value = int(hash_value, 16)

    # 全的随机数生成
    k_seed = str(private_key) + message + str(time.time_ns())
    k_value = int(sha256(k_seed.encode()).hexdigest(), 16) % n

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
    # 验证密文长度
    min_length = 64 + 32 + 1  # C1(64) + C3(32) + 最小C2(1)
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

    #使用常数时间比较
    if not constant_time_compare(u, C3):
        raise ValueError("哈希验证失败，密文可能被篡改")

    return plaintext


def batch_verify_signatures(public_key, messages, user_ids, signatures):
    """批量验证SM2签名"""
    with ThreadPoolExecutor() as executor:
        # 创建参数列表
        params = [(public_key, msg, uid, sig) for msg, uid, sig in zip(messages, user_ids, signatures)]

        # 并行验证
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

    # 计算 y^2 = x^3 + a*x + b mod p
    y_sq = (x * x * x + ECC_A * x + ECC_B) % P

    # 求解模平方根
    y = pow(y_sq, (P + 1) // 4, P)

    # 根据前缀选择正确的y值
    if prefix == 0x02:
        return (x, y if y % 2 == 0 else P - y)
    else:  # prefix == 0x03
        return (x, y if y % 2 == 1 else P - y)


def main():
    """演示SM2完整功能"""
    # 密钥生成
    private, public = generate_keypair()
    print(f"公钥坐标: X={hex(public[0])}, Y={hex(public[1])}")
    print(f"私钥: {hex(private)}")

    # 签名演示
    print("\n===== 签名验证测试 =====")
    msg = "111"
    user_id = "202218201144"
    print(f"消息: '{msg}'")
    print(f"用户ID: '{user_id}'")

    # 签名生成
    sig = generate_signature(private, msg, user_id, public)
    while sig is None:
        print("生成无效签名，重新生成密钥...")
        private, public = generate_keypair()
        sig = generate_signature(private, msg, user_id, public)

    print(f"签名值: r={hex(sig[0])}, s={hex(sig[1])}")

    # 签名验证
    is_valid = verify_signature(public, msg, user_id, sig)
    print(f"签名验证结果: {'成功' if is_valid else '失败'}")

    if not is_valid:
        za = compute_user_hash(user_id, public[0], public[1])
        print(f"ZA: {za}")
        msg_full = za + msg
        msg_bytes = msg_full.encode('utf-8')
        hash_value = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
        e_value = int(hash_value, 16)
        print(f"消息哈希值: {hex(e_value)}")

        t_value = (sig[0] + sig[1]) % n
        point1 = ec_point_mult(sig[1], G)
        point2 = ec_point_mult(t_value, public)
        result_point = ec_point_add(point1, point2)
        print(f"验证点坐标: ({hex(result_point[0])}, {hex(result_point[1])})")

        R_calculated = (e_value + result_point[0]) % n
        print(f"计算得到的R': {hex(R_calculated)}")
        print(f"签名中的r: {hex(sig[0])}")

    # 篡改测试
    tampered_msg = "这是被篡改的消息"
    is_valid_tampered = verify_signature(public, tampered_msg, user_id, sig)
    print(f"篡改消息后验证: {'成功' if is_valid_tampered else '失败'}")

    # 加密解密演示
    print("\n===== 加密解密测试 =====")
    plaintext = b"111"  # 明文
    print(f"原始明文: {plaintext.decode('utf-8')}")

    try:
        # 加密
        ciphertext = sm2_encrypt(public, plaintext)
        print(f"密文长度: {len(ciphertext)}字节")
        print(f"密文（十六进制）: {binascii.hexlify(ciphertext).decode()}")

        # 解密
        decrypted = sm2_decrypt(private, ciphertext)
        print(f"解密结果: {decrypted.decode('utf-8')}")

        # 篡改测试 - 修改C3部分
        print("\n===== 篡改测试 (修改C3) =====")
        tampered_cipher = bytearray(ciphertext)
        if len(tampered_cipher) > 64:
            # 修改C3的第一个字节
            tampered_cipher[64] ^= 0x01

            try:
                decrypted = sm2_decrypt(private, bytes(tampered_cipher))
                print(f"解密结果: {decrypted.decode('utf-8')}")
                print("篡改密文解密成功 (不应该发生)")
            except ValueError as e:
                print(f"解密失败 (预期结果): {str(e)}")

        # 篡改测试 - 修改C2部分
        print("\n===== 篡改测试 (修改C2) =====")
        tampered_cipher = bytearray(ciphertext)
        if len(tampered_cipher) > 96:
            # 修改C2的第一个字节
            tampered_cipher[96] ^= 0x01

            try:
                decrypted = sm2_decrypt(private, bytes(tampered_cipher))
                print(f"解密结果: {decrypted.decode('utf-8')}")
                print("篡改密文解密成功 (不应该发生)")
            except ValueError as e:
                print(f"解密失败 (预期结果): {str(e)}")

    except Exception as e:
        print(f"加解密过程中出错: {str(e)}")
        import traceback
        traceback.print_exc()

    # 批量验证演示
    print("\n===== 批量签名验证测试 =====")
    num_signatures = 10
    messages = [f"消息{i}" for i in range(num_signatures)]
    user_ids = [f"用户{i}" for i in range(num_signatures)]
    signatures = []

    # 生成多个签名
    for i in range(num_signatures):
        sig = generate_signature(private, messages[i], user_ids[i], public)
        while sig is None:
            sig = generate_signature(private, messages[i], user_ids[i], public)
        signatures.append(sig)

    # 批量验证
    start_time = time.time()
    results = batch_verify_signatures(public, messages, user_ids, signatures)
    batch_time = time.time() - start_time

    # 单个验证
    single_times = []
    for i in range(num_signatures):
        start = time.time()
        verify_signature(public, messages[i], user_ids[i], signatures[i])
        single_times.append(time.time() - start)

    avg_single_time = sum(single_times) / num_signatures

    print(f"批量验证 {num_signatures} 个签名耗时: {batch_time:.4f}秒")
    print(f"单个验证平均耗时: {avg_single_time:.6f}秒")
    print(f"验证结果: {all(results)}")


if __name__ == "__main__":
    main()