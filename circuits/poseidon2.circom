pragma circom 2.2.2;

//  S-box 实现 (x^5)
template SBox() {
    signal input x;
    signal output out;
    
    signal x2; signal x4;
    x2 <== x * x;
    x4 <== x2 * x2;
    out <== x4 * x;  // x^5 = (x^2)^2 * x
}

// 单轮 Poseidon2 操作
template Poseidon2Round(roundType, roundIdx, t) {
    signal input in[t];
    signal output out[t];
    
    // 标准 MDS 矩阵 (t=3)
    var MDS[3][3] = [
        [5, 7, 1],
        [3, 4, 1],
        [1, 1, 2]
    ];
    
    // 预计算的轮常数 (t=3, 总轮数=64)，注：由于真实的轮常数规模较大，我们这里只列出示例，完整的轮常数见文件roundnum.txt
    var RC[64][3] = [
        [123, 456, 789], [234, 567, 891], [345, 678, 912], [456, 789, 123],
        [567, 891, 234], [678, 912, 345], [789, 123, 456], [891, 234, 567],
        [912, 345, 678], [123, 456, 789], [234, 567, 891], [345, 678, 912],
        [456, 789, 123], [567, 891, 234], [678, 912, 345], [789, 123, 456],
        [891, 234, 567], [912, 345, 678], [123, 456, 789], [234, 567, 891],
        [345, 678, 912], [456, 789, 123], [567, 891, 234], [678, 912, 345],
        [789, 123, 456], [891, 234, 567], [912, 345, 678], [123, 456, 789],
        [234, 567, 891], [345, 678, 912], [456, 789, 123], [567, 891, 234],
        [678, 912, 345], [789, 123, 456], [891, 234, 567], [912, 345, 678],
        [123, 456, 789], [234, 567, 891], [345, 678, 912], [456, 789, 123],
        [567, 891, 234], [678, 912, 345], [789, 123, 456], [891, 234, 567],
        [912, 345, 678], [123, 456, 789], [234, 567, 891], [345, 678, 912],
        [456, 789, 123], [567, 891, 234], [678, 912, 345], [789, 123, 456],
        [891, 234, 567], [912, 345, 678], [123, 456, 789], [234, 567, 891],
        [345, 678, 912], [456, 789, 123], [567, 891, 234], [678, 912, 345],
        [789, 123, 456], [891, 234, 567], [912, 345, 678], [123, 456, 789]
    ];

    // 1. 添加轮常数
    signal afterAddRC[t];
    for (var i = 0; i < t; i++) {
        afterAddRC[i] <== in[i] + RC[roundIdx][i];
    }
    
    signal afterSbox[t];
    component sboxes[t];
    
    if (roundType == 0) { // 全轮
        for (var i = 0; i < t; i++) {
            sboxes[i] = SBox();
            sboxes[i].x <== afterAddRC[i];
            afterSbox[i] <== sboxes[i].out;
        }
    } else { // 部分轮 (仅第一个元素)
        sboxes[0] = SBox();
        sboxes[0].x <== afterAddRC[0];
        afterSbox[0] <== sboxes[0].out;
        
        for (var i = 1; i < t; i++) {
            afterSbox[i] <== afterAddRC[i];
        }
    }
    
    // 3. MDS 矩阵乘法
    for (var i = 0; i < t; i++) {
        out[i] <== MDS[i][0] * afterSbox[0] + 
                  MDS[i][1] * afterSbox[1] + 
                  MDS[i][2] * afterSbox[2];
    }
}

// 完整的 Poseidon2 哈希函数
template Poseidon2(nInputs) {
    signal input in_private[nInputs];
    signal output hash_output;
    
    // 算法参数 (t = 输入数 + 1)
    var t = nInputs + 1;
    var RF = 8;      // 全轮数
    var RP = 56;     // 部分轮数
    var totalRounds = RF + RP;
    
    // 初始状态设置
    signal state[totalRounds+1][t];
    state[0][0] <== in_private[0];
    state[0][1] <== in_private[1];
    state[0][2] <== 0;  // 容量元素
    
    // 轮操作组件
    component rounds[totalRounds];
    
    for (var r = 0; r < totalRounds; r++) {
        // 确定轮类型 (首尾RF/2为全轮，中间为部分轮)
        var roundType = 0;
        if (r >= RF/2 && r < totalRounds - RF/2) {
            roundType = 1;
        }
        
        rounds[r] = Poseidon2Round(roundType, r, t);
        
        // 连接输入
        for (var i = 0; i < t; i++) {
            rounds[r].in[i] <== state[r][i];
        }
        
        // 连接输出
        for (var i = 0; i < t; i++) {
            state[r+1][i] <== rounds[r].out[i];
        }
    }
    
    // 最终哈希输出 (状态第一个元素)
    hash_output <== state[totalRounds][0];
}

// 主组件 (2个输入元素)
component main = Poseidon2(2);