# SDU_Project

## 个人信息
- 姓名：张浩辰
- 学号：202218201144
- 专业：网安

## 仓库说明
本仓库中包含本次创新实践课程的六个项目及全部子项目**均为个人独立完成**，其中每个文件夹对应一个项目，里面包含相应的代码及说明文档，可进行查看。

**注：** 六个项目开发时，我为每个项目分别建立了一个仓库，本仓库为六个仓库的合成仓库，所以具体某个文件的History commit记录无法显示出来，若想访问查看具体每个文件的commit记录，可以访问原仓库，地址分别如下如下：


* [Project-1-SM4](https://github.com/fake-pgn/Project-1-SM4)
* [Project-2-watermark](https://github.com/fake-pgn/Project-2-watermark)
* [Project-3-poseidon2](https://github.com/fake-pgn/Project-3-poseidon2)
* [Project-4-SM3](https://github.com/fake-pgn/Project-4-SM3)
* [Project-5-SM2](https://github.com/fake-pgn/Project-5-SM2)
* [Project-6-Google-Password-Checkup](https://github.com/fake-pgn/Project-6-Google-Password-Checkup)

## 项目内容

本人独立完成了全部六个项目，及每个项目中的相应子任务，具体完成的内容如下：

### Project 1: 做 SM4 的软件实现和优化
- **a)** 从基本实现出发，优化 SM4 的软件执行效率，至少应覆盖：T-tableESNI最新的指令集（GFNI、VPROLD 等）
- **b)** 基于 SM4 的实现，做 SM4-GCM 工作模式的软件优化实现

---

### Project 2: 基于数字水印的图片泄露检测
- 编程实现图片水印嵌入和提取（可依托开源项目二次开发）
- 进行鲁棒性测试，包括但不限于：翻转、平移、截取、调整对比度

---

### Project 3: 用 circom 实现 Poseidon2 哈希算法的电路
1. Poseidon2 哈希算法参数参考 [参考文档 1](https://eprint.iacr.org/2023/323.pdf) 的 Table 1，使用：(n, t, d) = (256, 3, 5) 或 (256, 2, 5)
2. 电路的公开输入为 Poseidon2 哈希值，隐私输入为哈希原像，哈希算法的输入只考虑一个 block。
3. 使用 Groth16 算法生成证明

**参考文档：**
1. [Poseidon2 哈希算法](https://eprint.iacr.org/2023/323.pdf)  
2. [Circom 说明文档](https://docs.circom.io/)  
3. [Circom 电路样例](https://github.com/iden3/circomlib)

---

### Project 4: SM3 的软件实现与优化
- **a)** 与 Project 1 类似，从 SM3 的基本软件实现出发，参考付勇老师的 PPT，不断优化 SM3 的软件执行效率
- **b)** 基于 SM3 的实现，验证 length-extension attack
- **c)** 基于 SM3 的实现，根据 [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) 构建 Merkle 树（10 万叶子节点），并实现：叶子的存在性证明及不存在性证明

---

### Project 5: SM2 的软件实现优化
- **a)** 考虑到 SM2 用 C 语言较复杂，可以使用 Python 做 SM2 的基础实现及各种算法改进尝试
- **b)** 基于 `20250713-wen-sm2-public.pdf` 中提到的签名算法误用场景：分别做 POC 验证给出推导文档及验证代码
- **c)** 伪造中本聪的数字签名

---

### Project 6: Google Password Checkup 验证
- 来自刘巍然老师的报告  
- 参考论文 [Google Password Checkup](https://eprint.iacr.org/2019/723.pdf) 的 **Section 3.1**（即 Figure 2 中的协议）  
- 尝试实现该协议（编程语言不限）
