from ecpy.curves import Curve, Point
import hashlib
import random

# 使用比特币的 secp256k1 曲线
curve = Curve.get_curve('secp256k1')
n = curve.order  # 曲线阶
G = curve.generator  # 基点

# 中本聪的公钥（创世区块公钥）
satoshi_pubkey = Point(
    0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6,
    0x49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f,
    curve
)


def forge_signature():
    """伪造中本聪的数字签名"""
    while True:
        u = random.randint(1, n - 1)
        v = random.randint(1, n - 1)

        if v % n != 0:
            break

    R_prime = u * G + v * satoshi_pubkey
    r_prime = R_prime.x % n
    v_inv = pow(v, n - 2, n)
    s_prime = (r_prime * v_inv) % n

    e_prime = (u * s_prime) % n

    # 构造伪造的签名
    forged_signature = (r_prime, s_prime)
    forged_message_hash = e_prime

    return forged_signature, forged_message_hash


def verify_signature(pubkey, message_hash, signature):
    """验证ECDSA签名"""
    r, s = signature

    if not (1 <= r < n and 1 <= s < n):
        return False

    w = pow(s, n - 2, n)
    u1 = (message_hash * w) % n
    u2 = (r * w) % n
    P = u1 * G + u2 * pubkey

    return P.x % n == r


def main():
    """主函数：伪造并验证签名"""
    # 伪造中本聪的签名
    forged_sig, forged_hash = forge_signature()
    print("伪造的签名 (r, s):")
    print(f"r = {hex(forged_sig[0])}")
    print(f"s = {hex(forged_sig[1])}")
    print(f"对应的消息哈希: {hex(forged_hash)}")

    # 验证伪造的签名
    is_valid = verify_signature(satoshi_pubkey, forged_hash, forged_sig)
    print(f"\n签名验证结果: {'成功' if is_valid else '失败'}")


if __name__ == "__main__":
    main()