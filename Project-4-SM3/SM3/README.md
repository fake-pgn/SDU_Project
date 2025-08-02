# SM3 ���ʵ����༶�Ż�˵��

## ����

����Ŀ���� SM3 ��ϣ�㷨�� **�������ʵ��**������������Ż�����չ����ѭ��չ����SIMD �����������̲߳��У����������㷨ִ��Ч�ʡ������ĵ�����ϸ˵���㷨ԭ���Ż�˼·����ѧ�Ƶ����������ʵ�֡�


---
## ���л���

* ����ϵͳ��Windows 11 (64-bit)
* ��������Visual Studio 2022 (MSVC, C++14)
* ��������Intel Core i7-11800H @ 2.30GHz
* �ڴ棺16 GB

---


---

## SM3 ��ʵ�����Ż�

SM3 ���й���������ַ������Ӵ��㷨����� 256 λժҪ�����������Ϣ��䡢��Ϣ��չ�������û�������ѹ���������ɡ�

### ��Ϣ��չ
��������� `M[i]` ��չΪ 68 �� `W[j]` �� 64 �� `W1[j]`��

W[j] = P1(W[j-16] XOR W[j-9] XOR (W[j-3] <<< 15)) XOR (W[j-13] <<< 7) XOR W[j-6]

W1[j] = W[j] XOR W[j+4]

### ѹ������
��ÿ������ʹ�� 64 �ֵ�����

SS1 = ((A <<< 12) + E + (T_j <<< (j mod 32))) <<< 7

SS2 = SS1 XOR (A <<< 12)

TT1 = FF_j(A,B,C) + D + SS2 + W1[j]

TT2 = GG_j(E,F,G) + H + SS1 + W[j]

���� ABCD EFGH ������ `state`



---

## ����ʵ��

```cpp
// ʡ��ͷ�ļ�...
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    // ��Ϣ��չ
    for (int i = 0; i < 16; ++i)
        W[i] = load_be32(block + 4*i);
    for (int j = 16; j < 68; ++j)
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15))
               ^ ROTL(W[j-13],7) ^ W[j-6];
    for (int j = 0; j < 64; ++j)
        W1[j] = W[j] ^ W[j+4];

    // 64 ��ѹ��
    auto A=state[0], B=state[1], ...;
    for (int j = 0; j < 64; ++j) {
        uint32_t Tj = (j<16?0x79CC4519:0x7A879D8A);
        uint32_t SS1 = ROTL(...);
        // ...
    }
    // ���� state
}
```


---

## �Ż���һ����չ������������

### �Ż�����

SM3 �ж��ʹ�õĻ����û��Ͳ���������`ROTL`��`P0`/`P1`��`FF`��`GG`���������ͨ����ʵ�֣�������������ÿ����ͷ�֧�жϡ�ͨ����չ�����ԣ����ٺ������ÿ����ͷ�֧�жϣ������������������Ż�Ч����

### �ؼ�����

```cpp
#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define P0(x)   ((x) ^ ROTL(x,9) ^ ROTL(x,17))
#define P1(x)   ((x) ^ ROTL(x,15) ^ ROTL(x,23))
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x)&(y))|((x)&(z))|((y)&(z)))
#define GG0(x,y,z) FF0(x,y,z)
#define GG1(x,y,z) FF1(x,y,z)
```

* **����**����ֱ���滻���޺������á�
* **��֧�ϲ�**��`FF`/`GG` ������ʽͨ�� `FF0/FF1` ��֣��Ƴ� `j<16` �жϵĶ����֧��

��ѧ�Ƶ����û����� `P0/P1` Ϊ���Ա任��ʹ��ѭ������ʽչ���ɺϲ������λ����������

---

## �Ż������ѭ��չ��

### �Ż�����

����ѭ�������жϺ��������㿪����������ˮ�����¡�

### �ؼ�����

```cpp
// չ�� 4 ��Ϊһ��
for (int j = 0; j < 64; j += 4) {
    // �� 0
    SS1 = calc_SS1(A,E,Tj[j]); SS2 = SS1^(...);
    TT1 = FF(A,B,C)+D+SS2+W1[j]; TT2=...;
    D=C; C=ROTL(B,9); B=A; A=TT1;
    // �� 1,2,3 ͬ��
}
```

* **���� `j<64` �жϴ���**��ԭ 64 �� -> 16 �Ρ�
* **��������ϲ�**��`j+k` ֱ��չ�������ٶ�̬���㡣

---

## �Ż�������SIMD ������

### �Ż�����

���� x86 SSE/AVX ָ��ͬʱ����������ݣ�������ݲ��жȡ�

### ��Ϣ��չ������

```cpp
// W1 ���㲢�� 4 ��Ԫ��
for (int j = 0; j < 64; j += 4) {
    __m128i vW = _mm_loadu_si128((__m128i*)(W + j));
    __m128i vW4 = _mm_loadu_si128((__m128i*)(W + j + 4));
    __m128i vW1 = _mm_xor_si128(vW, vW4);
    _mm_storeu_si128((__m128i*)(W1 + j), vW1);
}
```

* ÿ�ζ�д 128 λ��4��32 λ�����ٶ� \~4�� �����汾��
* `_mm_xor_si128` ����ִ�� 4 ·���

### ��������������

```cpp
        __m128i tj_vec = _mm_set1_epi32(Tj[j]);
        __m128i w_vec = _mm_set1_epi32(W[j]);
        __m128i w1_vec = _mm_set1_epi32(W1[j]);

        uint32_t tj = _mm_extract_epi32(tj_vec, 0);
        uint32_t w_val = _mm_extract_epi32(w_vec, 0);
        uint32_t w1_val = _mm_extract_epi32(w1_vec, 0);
```

* �����ڴ���ط�֧�����������Ĵ����㲥��

---

## �Ż����ģ����̲߳���

### �Ż�����

�Զ����Ĵ���Ϣ���ֿ鲢��ѹ����������������ʡ�

### �ؼ�����

```cpp
size_t NB = pad_len / 64;
size_t NT = std::min(std::thread::hardware_concurrency(), NB);

// 1. ׼��ÿ�߳�״̬����
std::vector<std::vector<uint32_t>> thread_states(NT, std::vector<uint32_t>(8));
for (size_t t = 0; t < NT; ++t)
    std::memcpy(thread_states[t].data(), IV, sizeof(IV));

// 2. ����ѹ��
size_t offset = 0;
for (size_t t = 0; t < NT; ++t) {
    size_t cnt = NB/NT + (t < NB%NT ? 1 : 0);
    threads.emplace_back([&, t, offset, cnt](){
        process_blocks(thread_states[t].data(),
                       padded + offset*64,
                       cnt);
    });
    offset += cnt;
}

// 3. �ȴ����ϲ�
for (auto &th : threads) th.join();
std::memcpy(state, IV, sizeof(IV));
for (size_t t = 0; t < NT; ++t) {
    uint8_t tmpblk[64];
    for (int i = 0; i < 8; ++i)
        store_be32(tmpblk + 4*i, thread_states[t][i]);
    sm3_compress_optimized(state, tmpblk);
}
```

* **״̬����**��ÿ�̶߳��� `state`�������޳�ͻ��
* **����ϲ�**�����߳��м� `state` �����·���ѹ����

---

