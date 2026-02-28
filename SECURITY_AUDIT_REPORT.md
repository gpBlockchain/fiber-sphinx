# 安全审计报告: fiber-sphinx

## 1. 执行摘要

### 项目信息
- **项目名称**: fiber-sphinx
- **版本**: 2.3.0
- **语言**: Rust (Edition 2021, MSRV 1.76.0)
- **项目类型**: 密码学库 — Sphinx mix network 协议的 Rust 实现
- **审计日期**: 2026-02-28
- **审计范围**: 全部源代码 (src/lib.rs, src/tests.rs)，依赖安全，规范一致性

### 关键数字
| 指标 | 数值 |
|------|------|
| 源代码行数 | 739 (lib.rs) + 565 (tests.rs) |
| 公共 API 数量 | 15 |
| 内部函数数量 | 9 |
| 现有测试数 | 18 单元测试 + 3 文档测试 |
| 审计项总数 | 20 |
| 运行时依赖数 | 6 |

### 审计结论

**整体评估: 安全性良好** 🟢

fiber-sphinx 是一个编写良好的密码学库，具有以下安全亮点:
- 正确使用恒定时间比较 (subtle crate) 防止计时侧信道攻击
- 使用 checked_add/checked_sub 防止整数溢出
- 遵循 "先认证后处理" (authenticate-then-process) 原则
- 实现与 Sphinx/BOLT#4 规范一致，经测试向量验证
- 无 `unsafe` 代码块
- 依赖无已知 CVE

未发现 Critical 或 High 级别漏洞。发现 3 个 Low 级别和 2 个 Informational 级别的改进建议。

---

## 2. 风险评级

| 级别 | 数量 | 说明 |
|------|------|------|
| ■ Critical | 0 项 | 无 |
| ■ High | 0 项 | 无 |
| ■ Medium | 0 项 | 无 |
| ■ Low | 3 项 (2 已修复) | 密钥清零 ✅、shift 函数断言 ✅、资源上限 |
| ■ Informational | 2 项 | version 字段验证、错误类型信息泄露 |

---

## 3. 详细发现

### FINDING-001: 无显式密钥材料清零机制
- **严重级别**: Low
- **审计项**: AUDIT-CRYPTO-005
- **描述**: 共享密钥 (`shared_secret`)、派生密钥 (`rho`, `mu`, `ammag`, `um`) 及临时密钥在使用后未被显式清零。密钥材料在栈/堆上存留直至被 Rust 的所有权系统销毁，但编译器可能优化掉清零操作。
- **影响**: 在内存转储 (core dump)、冷启动攻击 (cold boot attack) 或同一进程中的其他漏洞场景下，攻击者可能从内存中恢复密钥材料。
- **关键代码引用**:
  ```rust
  // lib.rs:250-252 - 共享密钥在栈上
  let shared_secret = self.shared_secret(secret_key);
  let rho = derive_key(HMAC_KEY_RHO, shared_secret.as_ref());
  let mu = derive_key(HMAC_KEY_MU, shared_secret.as_ref());
  ```
- **修复方案**: 引入 `zeroize` crate，为 `ForwardKeys` 和 `ReturnKeys` 结构体添加 `Zeroize` + `ZeroizeOnDrop` derive，确保密钥材料在 drop 时自动清零。
- **修复状态**: ✅ 已修复

### FINDING-002: shift_slice 函数仅使用 debug_assert
- **严重级别**: Low
- **审计项**: AUDIT-MEMORY-002
- **描述**: `shift_slice_left` 和 `shift_slice_right` 函数使用 `debug_assert!(amt <= arr.len())` 验证参数边界，该断言仅在 debug 模式下生效。在 release 模式下，若 `amt > arr.len()`，`arr.len() - amt` 会发生减法下溢 panic。
- **影响**: 当前所有调用者均在调用前验证参数，因此实际不可利用。但若未来新增调用者忘记检查，可能导致 release 模式下的 panic。这是一个纵深防御 (defense-in-depth) 问题。
- **关键代码引用**:
  ```rust
  // lib.rs:553-555 (修复前)
  fn shift_slice_left(arr: &mut [u8], amt: usize) {
      debug_assert!(amt <= arr.len());
      let pivot = arr.len() - amt;
  ```
- **修复方案**: 将 `debug_assert!` 升级为 `assert!`，在 release 模式下也进行边界检查，提供纵深防御。
- **修复状态**: ✅ 已修复

### FINDING-003: 无最大 packet_data_len 和 hops 数量限制
- **严重级别**: Low
- **审计项**: AUDIT-MEMORY-004
- **描述**: `OnionPacket::create` 不限制 `packet_data_len` 和 `hops_path` 的长度。极端输入可能导致大内存分配。
- **影响**: 攻击者（如恶意调用者）可传入极大的 `packet_data_len`（如 `usize::MAX/2`）导致 OOM。但该函数由应用层控制参数，攻击面有限。
- **关键代码引用**:
  ```rust
  // lib.rs:158 - 无上限检查
  pub fn create<C: Signing>(
      session_key: SecretKey,
      hops_path: Vec<PublicKey>,
      hops_data: Vec<Vec<u8>>,
      assoc_data: Option<Vec<u8>>,
      packet_data_len: usize,  // 无上限
      ...
  ```
- **修复建议**: 建议在库文档中明确说明调用者应控制参数范围，或添加可选的最大值检查。
- **修复状态**: 未修复 (建议性)

### FINDING-004: version 字段未验证
- **严重级别**: Informational
- **审计项**: AUDIT-INPUT-001
- **描述**: `OnionPacket::from_bytes` 接受任意 version 字节 (0-255)，但 `create` 函数总是设置 `version: 0`。
- **影响**: 无直接安全影响。这可能是为了前向兼容性的有意设计。但若接收方依赖 version 值进行处理分支，可能导致意外行为。
- **关键代码引用**:
  ```rust
  // lib.rs:203 - 未验证 version
  let version = bytes[0];
  // lib.rs:730 - create 始终设置 version: 0
  Ok(OnionPacket { version: 0, ... })
  ```
- **修复建议**: 可在 `from_bytes` 中添加 version 检查，或在文档中说明 version 字段的预期值。
- **修复状态**: 未修复 (信息性)

### FINDING-005: 错误类型可被区分
- **严重级别**: Informational
- **审计项**: AUDIT-ERRINFO-001
- **描述**: `peel()` 方法在不同失败原因时返回不同的错误类型 (`HmacMismatch` vs `HopDataLenTooLarge` vs `HopDataLenUnavailable`)，理论上允许攻击者区分失败原因。
- **影响**: 由于 HMAC 验证在数据解密之前进行，且攻击者无法控制解密后的数据内容，因此无法利用错误差异获取有用信息。属于理论风险。
- **关键代码引用**:
  ```rust
  // lib.rs:257-258 - HMAC 检查先于解密
  if expected_hmac.ct_eq(&self.hmac).unwrap_u8() != 1 {
      return Err(SphinxError::HmacMismatch);
  }
  // lib.rs:266-273 - 解密后的长度检查
  let data_len = get_hop_data_len(&packet_data).ok_or(SphinxError::HopDataLenUnavailable)?;
  ```
- **修复建议**: 可考虑将所有 peel 错误统一为一个错误类型，但这会降低调试体验。当前设计在安全性和可用性间取得了合理平衡。
- **修复状态**: 未修复 (信息性)

---

## 4. 审计覆盖矩阵

| 函数/模块 | DIM-CRYPTO | DIM-INPUT | DIM-MEMORY | DIM-LOGIC | DIM-SERDE | DIM-ERRINFO | DIM-SPEC |
|-----------|:----------:|:---------:|:----------:|:---------:|:---------:|:-----------:|:--------:|
| OnionPacket::create | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ |
| OnionPacket::peel | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ |
| OnionPacket::from_bytes | — | ✅ | ✅ | — | ✅ | ✅ | — |
| OnionPacket::into_bytes | — | — | ✅ | — | ✅ | — | — |
| OnionPacket::shared_secret | ✅ | — | — | — | — | — | ✅ |
| OnionErrorPacket::create | ✅ | — | — | ✅ | — | — | ✅ |
| OnionErrorPacket::parse | ✅ | ✅ | — | ✅ | — | — | ✅ |
| OnionErrorPacket::xor_cipher_stream | ✅ | — | — | — | — | — | ✅ |
| OnionErrorPacket::concat/split | — | — | ✅ | — | ✅ | — | — |
| derive_key | ✅ | — | — | — | — | — | ✅ |
| generate_filler | ✅ | — | ✅ | ✅ | — | — | ✅ |
| construct_onion_packet | ✅ | — | ✅ | ✅ | — | — | ✅ |
| shift_slice_left/right | — | — | ✅ | — | — | — | — |
| OnionSharedSecretIter | ✅ | — | — | ✅ | — | — | ✅ |
| derive_next_hop_* | ✅ | — | — | — | — | — | ✅ |

✅ = 已审计 | — = 不适用

---

## 5. 依赖安全状态

| 依赖 | 版本 | CVE 状态 | 备注 |
|------|------|----------|------|
| secp256k1 | 0.30.0 | ✅ 无已知 CVE | 成熟的椭圆曲线库 |
| sha2 | 0.10.8 | ✅ 无已知 CVE | RustCrypto SHA-2 实现 |
| hmac | 0.12.1 | ✅ 无已知 CVE | RustCrypto HMAC 实现 |
| chacha20 | 0.9.1 | ✅ 无已知 CVE | RustCrypto ChaCha20 实现 |
| thiserror | 1.0.63 | ✅ 无已知 CVE | 错误处理宏 |
| subtle | 2.6.1 | ✅ 无已知 CVE | 恒定时间操作库 |
| hex-conservative | 0.2.1 (dev) | ✅ 无已知 CVE | 仅测试依赖 |

**总结**: 所有依赖均为维护良好的 Rust 密码学生态库，无已知安全漏洞。

---

## 6. 改进建议（非漏洞类）

### 6.1 测试覆盖增强
- **边界条件测试**: 建议添加 `packet_data_len = 0` 和单跳场景的边界测试
- **模糊测试**: 建议引入 `cargo-fuzz` 对 `from_bytes` 和 `peel` 进行模糊测试
- **属性测试**: 建议使用 `proptest` 验证序列化/反序列化 roundtrip 属性

### 6.2 代码质量
- **forward_stream_cipher 性能**: 当前逐字节处理，可改为批量处理提升性能
  ```rust
  fn forward_stream_cipher<S: StreamCipher>(stream: &mut S, n: usize) {
      let mut dummy = vec![0u8; n];
      stream.apply_keystream(&mut dummy);
  }
  ```
  注意: 大量分配可能导致 OOM，需权衡。

### 6.3 文档增强
- 在公共 API 文档中明确安全假设（如 session_key 必须用 CSPRNG 生成）
- 在 `create` 文档中说明 `packet_data_len` 的合理范围

---

## 7. 安全亮点

以下是项目中值得称赞的安全实践：

1. **恒定时间 HMAC 比较**: 使用 `subtle::ConstantTimeEq` 防止计时攻击
2. **先认证后处理**: `peel()` 先验证 HMAC 再解密处理，`parse()` 先验证 HMAC 再调用 parse_payload
3. **整数溢出保护**: 关键路径使用 `checked_add`/`checked_sub` 防止溢出
4. **无 unsafe 代码**: 整个库没有使用 `unsafe` 关键字
5. **完整的测试向量**: 包含 5 跳完整测试向量，与规范文档一致
6. **良好的错误处理**: 使用 `thiserror` 定义明确的错误类型，fallible 操作返回 Result
7. **域分离密钥派生**: 使用不同的 HMAC key ("rho", "mu", "pad", "um", "ammag") 实现域分离

---

## 附录: 完整 TODO 文档终态

参见 [SECURITY_AUDIT_TODO.md](./SECURITY_AUDIT_TODO.md)
