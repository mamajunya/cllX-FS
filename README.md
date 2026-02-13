# cllX-FS-Pro

后量子安全文件加密系统

## 项目简介

cllX-FS-Pro 是一个基于后量子密码学的文件加密系统，提供军事级别的数据保护。

核心特性：
- 后量子安全：ML-KEM-768 (NIST Level 3) 抵抗量子计算机攻击
- 高性能：加密速度 1065 MB/s，支持大文件（已测试 7.6 GB）
- 双界面：图形界面 (GUI) 和命令行 (CLI)
- 完整性保护：ChaCha20-Poly1305 AEAD 自动验证
- 零开销：文件开销仅 0.002%
- 中英文界面：支持语言切换
- 嵌入密钥模式：可选将密钥嵌入加密文件

## 快速开始

### 图形界面（推荐）

启动 GUI：
```bash
# Windows
run_gui.bat

# 或直接运行
.\target\release\cllxfs-gui.exe
```

使用步骤：
1. 选择"加密"或"解密"模式
2. 选择输入文件或文件夹
   - 点击"选择文件"：加密/解密单个文件
   - 点击"选择文件夹"：将整个文件夹打包加密为单个 .cllx 文件
3. 选择输出位置
   - 单文件模式：选择输出文件
   - 文件夹加密模式：选择输出 .cllx 文件
   - 文件夹解密模式：选择输出文件夹
4. 输入密码（可选）
5. 点击开始按钮

文件夹加密功能：
- 将整个文件夹打包为单个 .cllx 文件（类似 zip 压缩）
- 自动保持完整的目录结构
- 加密模式：文件夹 → 单个 .cllx 文件
- 解密模式：.cllx 文件 → 恢复完整文件夹结构
- 使用 tar 格式打包，确保跨平台兼容性

### 命令行界面

加密文件：
```bash
# 使用密码加密
cllxfs encrypt -i input.txt -o output.cllx -r user@example.com -p YOUR_PASSWORD

# 使用随机密钥加密
cllxfs encrypt -i input.txt -o output.cllx -r user@example.com
```

解密文件：
```bash
# 自动查找密钥文件
cllxfs decrypt -i output.cllx -o decrypted.txt

# 指定密钥文件
cllxfs decrypt -i output.cllx -o decrypted.txt -k output.cllx.key
```

## 安装

### 从源码构建

前置要求：
- Rust 1.70+
- Cargo

构建步骤：
```bash
# 克隆仓库
git clone https://github.com/yourusername/cllX-FS-Pro.git
cd cllX-FS-Pro

# 构建 CLI 版本
cargo build --release --bin cllxfs

# 构建 GUI 版本
cargo build --release --bin cllxfs-gui

# 可执行文件位于
# target/release/cllxfs.exe (CLI)
# target/release/cllxfs-gui.exe (GUI)
```

## 技术架构

### 加密算法

| 组件 | 算法 | 安全级别 |
|------|------|----------|
| 密钥封装 | ML-KEM-768 | NIST Level 3 (后量子) |
| 数据加密 | ChaCha20-Poly1305 | 256-bit (AEAD) |
| 密钥派生 | HKDF-SHA3-256 | 256-bit |
| 哈希 | BLAKE3 | 256-bit |

### 加密流程

```
文件 → 分块(1MB) → cllX-Math变换 → ChaCha20-Poly1305加密 → Merkle树 → 容器
```

cllX-Math变换层：
- 整数矩阵扩散（16×16上三角矩阵）
- ChaCha20掩码混淆
- 完全可逆，100%字节一致
- 详见 CLLX_MATH.md

### 密钥管理

密码加密模式：
- 用户提供密码
- SHA-256 派生加密密钥
- ChaCha20-Poly1305 加密私钥
- 密钥文件：CLLX-PWD + 加密的私钥 (2424 bytes)

密钥加密模式：
- 系统生成随机密钥
- ML-KEM-768 密钥对 (2400 bytes)
- 密钥文件：原始私钥

嵌入密钥模式：
- 私钥直接嵌入 .cllx 文件
- 无需单独的 .key 文件
- 方便但安全性略低

### 完整性保护

- AEAD 认证标签 (16 bytes per chunk)
- 自动验证数据完整性
- 防止数据篡改
- 错误密钥自动拒绝

## 性能测试

测试环境：
- CPU: [Your CPU]
- RAM: [Your RAM]
- OS: Windows 11

测试结果：

| 文件大小 | 加密时间 | 解密时间 | 吞吐量 | 开销 |
|---------|---------|---------|--------|------|
| 132 B   | <500ms  | <500ms  | -      | -    |
| 7.6 GB  | 10s  | ~10s    | 1065 MB/s | 0.002% |

验证测试：
- 小文件测试 (132 bytes)：加密/解密成功，文件内容完全匹配
- 大文件测试 (7.6 GB)：SHA-256 哈希完全匹配，高性能处理
- 错误密码测试：正确拒绝错误密码，密码学级别验证

## 技术栈

核心依赖：
- pqc-ml-kem - ML-KEM-768 后量子密钥封装
- chacha20poly1305 - ChaCha20-Poly1305 AEAD 加密
- blake3 - BLAKE3 哈希算法
- hkdf - HKDF 密钥派生
- sha2 / sha3 - SHA-2/SHA-3 哈希

GUI 框架：
- egui - 即时模式 GUI 框架
- eframe - egui 应用框架
- rfd - 原生文件对话框
- sysinfo - 系统监控

工具库：
- serde / bincode - 序列化
- rayon - 并行处理
- clap - CLI 参数解析

## 命令行参考

加密命令：
```bash
cllxfs encrypt [OPTIONS]

选项：
  -i, --input <FILE>        输入文件路径
  -o, --output <FILE>       输出文件路径
  -r, --recipient <KEY>     接收者公钥
  -c, --chunk-size <SIZE>   分块大小 (默认: 1048576)
  -p, --password <PASS>     密码 (可选)
```

解密命令：
```bash
cllxfs decrypt [OPTIONS]

选项：
  -i, --input <FILE>        输入文件路径
  -o, --output <FILE>       输出文件路径
  -k, --key <FILE>          密钥文件路径 (可选)
```

## 常见问题

Q: 忘记密码怎么办？
A: 无法恢复。这是密码学的基本原理，确保数据安全。

Q: 密钥文件丢失怎么办？
A: 无法恢复。请务必备份密钥文件到多个安全位置。

Q: 支持哪些文件类型？
A: 所有文件类型，包括文档、图片、视频、压缩包等。

Q: 加密后的文件可以在其他电脑上解密吗？
A: 可以，只需要加密文件、密钥文件和 cllX-FS-Pro 程序。

Q: 这个加密安全吗？
A: 非常安全。使用 NIST 标准的后量子算法，可抵抗量子计算机攻击。

## 项目状态

已完成功能：
- Phase 1: 核心基础设施
- Phase 2: ML-KEM-768 集成
- Phase 3: 系统级功能
- Phase 4: CLI 工具
- 密码加密功能
- 图形界面 (GUI)
- cllX-Math 变换层

测试状态：
- 单元测试：23/23 通过
- 集成测试：3/3 通过
- 大文件测试：7.6 GB 通过

## 许可证

本项目采用 MIT 许可证 - 详见 LICENSE 文件

## 致谢

- NIST - 后量子密码学标准化
- Rust 社区 - 优秀的生态系统
- egui - 出色的 GUI 框架
- 所有贡献者和用户

## 联系方式

- 项目主页: https://github.com/yourusername/cllX-FS-Pro
- 问题反馈: https://github.com/yourusername/cllX-FS-Pro/issues
- 邮箱: 2061647815@qq.com

cllX-FS-Pro - 自我数据，面向未来
