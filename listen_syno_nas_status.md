# Synology NAS UDP Status Listener

本文档对应脚本：`listen_syno_nas_status.py`。

这个脚本用于监听 Synology Assistant 局域网发现协议中的 NAS 状态响应。它可以主动发送 UDP 广播探测包，也可以只监听网络中已有的 Synology Assistant / NAS UDP 流量。

## 工作流程

1. 脚本创建 UDP 监听 socket，优先绑定本地 `9999`，失败后依次尝试 `9998`、`9997`。
2. 默认创建 UDP 发送 socket，优先绑定本地源端口 `1234`。
3. 默认向 `255.255.255.255:9999` 发送若干轮 Synology Assistant 风格的探测包。
4. 收到 UDP 包后调用 `parse_syno_udp.py` 解析 `SYNO` 明文包。
5. 只把 `packet_type = 0x02` 或 `packet_type = 0x06` 的响应当作 NAS 状态包。
6. 从响应包的 `field 0xA7` 读取状态枚举，并映射为 `IDS_LST_SYS_READY`、`IDS_LST_SYS_BOOTING` 等状态名称。
7. 按设备 key 记录最近状态，只在状态或关键字段变化时输出；加 `--print-all` 可打印每个状态包。

## 监听与探测端口

| 用途 | 默认值 | 说明 |
| --- | --- | --- |
| 本地监听端口 | `9999,9998,9997` | 按顺序尝试绑定，绑定成功后只使用该端口 |
| 探测目标地址 | `255.255.255.255` | 默认全网段广播 |
| 探测目标端口 | `9999` | NAS 侧 Synology Assistant UDP 发现端口 |
| 探测源端口 | `1234` | 和 Synology Assistant 行为一致；被占用时自动退到随机端口 |

## 探测包格式

脚本当前构造的是明文 `SYNO` 探测包：

```text
[8-byte clear header]
[field 0xA4: u32]
[field 0xA6: u32]
[field 0x01: u32 packet_type]
```

明文包头固定为：

```hex
12 34 56 78 53 59 4E 4F
```

字段编码为：

```text
field_id(1 byte) + length(1 byte) + value(length bytes)
```

脚本默认探测参数：

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `0xA4` | `0x01020000` | 逆向得到的发现请求候选固定字段 |
| `0xA6` | `0x00000078` | 逆向得到的发现请求候选固定字段 |
| `0x01` | `0x0f,0x01` | 默认分别发送两种候选 packet type |

注意：响应侧状态解析已经比较稳定；主动探测侧仍保留可配置参数，是为了方便后续用抓包继续校正不同 DSM/Assistant 版本的行为。

## 响应包筛选规则

脚本只把下面两种包当作状态响应：

| `packet_type` | 名称 | 用途 |
| --- | --- | --- |
| `0x02` | `BResponse` | NAS 发现响应，包含状态字段 |
| `0x06` | `JResponse` | NAS 发现响应的另一类变体，也包含状态字段 |

其他包会被忽略。加 `--verbose` 后，脚本会打印 `non_status_packet`，用于观察被忽略的包型。

## 输出字段

脚本输出是一行 key-value 文本，例如：

```text
time=2026-04-24 14:16:10 key=00:1b:21:bd:94:ce packet=BResponse status=IDS_LST_SYS_READY ip=192.168.2.6 status_value=1 field_ip=1.0.0.0 field_remote_ip=1.0.0.0 mac=00:1b:21:bd:94:ce conf=1 con=5001
```

字段说明：

| 输出字段 | 来源 | 说明 |
| --- | --- | --- |
| `time` | 本机时间 | 脚本打印该状态的时间 |
| `key` | `mac` 优先，其次显示 IP | 用来识别同一台 NAS 的内部 key |
| `packet` | `field 0x01` | 响应包类型，通常是 `BResponse` 或 `JResponse` |
| `status` | `field 0xA7` | NAS/DSM 状态枚举名称 |
| `status_value` | `field 0xA7` | NAS/DSM 状态原始整数值 |
| `progress` | `field 0x79 / 100` | 当处于内存测试状态时输出实际百分比，例如 `4.97%` |
| `progress_raw_x100` | `field 0x79` | 内存测试进度的原始整数值，例如 `497` |
| `ip` | UDP 源地址优先 | 最终展示的 NAS IP；比 `0x18/0x48` 更可靠 |
| `src_ip` | UDP 源地址 | 仅当最终展示 IP 与 UDP 源地址不一致时输出 |
| `field_ip` | `field 0x48` | 协议字段候选 IP；当前仅作调试参考 |
| `field_remote_ip` | `field 0x18` | 协议字段候选 remote IP；当前仅作调试参考 |
| `mac` | `field 0x7C/0x21/0x19` 候选 | NAS 物理地址，脚本按这些字段顺序尝试提取 |
| `name` | `field 0x52/0x53/0x50/0x51/0xA2` 候选 | NAS 名称，若响应包中可解析则输出 |
| `model` | `field 0x78` 优先 | NAS 型号，例如 `SA6400` |
| `platform` | `field 0x70` | Synology 平台串，例如 `synology_epyc7002_sa6400` |
| `serial` | `field 0xC0` 优先 | NAS 序列号，例如 `V9F7O2T68BY24` |
| `conf` | `field 0x71` | 配置/确认类标志，具体业务含义仍需结合包型判断 |
| `con` | `field 0x76` | 默认 HTTPS 或服务端口；实测为 `5001` |

## 已确认协议字段

下面这些字段已经通过你提供的真实抓包坐实：

| 字段 ID | 示例值 | 含义 |
| --- | --- | --- |
| `0x11` | `HOMENAS` | 服务器名称 |
| `0x19` | `00:1b:21:bd:94:ce` | MAC 地址 |
| `0x70` | `synology_epyc7002_sa6400` | 平台 / 产品族字符串 |
| `0x71` | `1` | 配置标志 |
| `0x75` | `5000` | HTTP 端口 |
| `0x76` | `5001` | HTTPS 端口或服务端口 |
| `0x77` | `7.3.2` | DSM 短版本字符串 |
| `0x78` | `SA6400` | 型号 |
| `0x79` | `497` | 内存测试进度，单位为百分比乘以 `100` |
| `0xA7` | `1` | 系统状态枚举 |
| `0xC0` | `V9F7O2T68BY24` | 完整序列号 |
| `0xC1` | `DSM` | 产品族 |

另外几项值得继续观察：

| 字段 ID | 示例值 | 当前理解 |
| --- | --- | --- |
| `0x12` | `192.168.2.6` | 设备 IPv4 候选字段 |
| `0x14` | `192.168.2.1` | 网关候选字段 |
| `0x1E` | `192.168.2.7` | 同网段辅助 IP 候选字段，可能与发现端或路由环境相关 |
| `0x18` | `1.0.0.0` | 当前仍不可信，暂不作为真实 IP 使用 |
| `0x48` | `1.0.0.0` | 当前仍不可信，暂不作为真实 IP 使用 |
| `0x49` | `249.79.1.0` | 辅助 IPv4 原始字段，语义未完全确认 |
| `0x73` | `9FO2T8BY24` | 序列号相关短字段，不作为最终序列号 |

## DSM 状态枚举

`status` 来自响应包里的 `field 0xA7`。当前已恢复的常见枚举如下：

| `status_value` | `status` | 含义 |
| --- | --- | --- |
| `0` | `IDS_LST_SYS_UNCONFIG` | 未配置 / 未初始化 |
| `1` | `IDS_LST_SYS_READY` | DSM 已就绪 |
| `2` | `IDS_LST_SYS_UNINSTALL` | DSM 未安装 |
| `3` | `IDS_LST_SYS_UPDATING` | 更新 / 升级中 |
| `4` | `IDS_LST_SYS_CRASH` | 系统异常 / 崩溃态 |
| `5` | `IDS_LST_SYS_BOOTING` | DSM 启动中 |
| `6` | `IDS_LST_SYS_QUOTA_CHECKING` | 配额检查中 |
| `7` | `IDS_LST_SYS_SERVICE_STARTING` | 服务启动中 |
| `8` | `IDS_LST_SYS_NET_ERROR` | 网络错误 / 连接失败 |
| `9` | `IDS_LST_SYS_MEMORY_TEST_IN_PROGRESS_INFERRED` | 内存测试进行中 |
| `10` | `IDS_LST_SYS_NET_TESTING` | 网络测试中 |
| `11` | `IDS_LST_SYS_RECOVERABLE` | 可恢复 |
| `12` | `IDS_WAKEUP_OFF_LINE` | 唤醒 / 离线相关状态 |
| `13` | `IDS_LST_SYS_CHECKING_PROGRESS` | 检查进度中 |
| `14` | `IDS_LST_SYS_MIGRAT` | 可迁移 |

这些状态和 Synology Assistant 自带帮助页中的 UI 文案是一致的，官方帮助里对应条目包括：

| 枚举 | UI 文案 |
| --- | --- |
| `5` | `Booting` |
| `6` | `Checking quota` |
| `8` | `Connection failed` |
| `9` | `memory test progress at X%` |
| `14` | `Migratable` |
| `2` | `Not installed` |
| `12` | `Offline` |
| `1` | `Ready` |
| `11` | `Recoverable` |
| `7` | `Starting services` |

另外，帮助页里还有 `Configuration lost` 和 `memory test progress at X%` 两类 UI 状态。其中：

| UI 文案 | 当前协议映射状态 |
| --- | --- |
| `Configuration lost` | 高概率对应 `IDS_LST_SYS_UNCONFIG (0)`，但还缺直接活包证据 |
| `memory test progress at X%` | 已由活包确认对应 `status_value = 9`，并且 `field 0x79 = 百分比 x 100` |

## 主程序补充逆向

这部分是对 `SynologyAssistant.bin` 主程序进一步静态逆向后，当前已经能坐实的结论。

### 1. 内存测试向导确实带管理员口令验证

在 Linux 主程序里，和内存测试相关的字符串已经同时出现：

| 证据字符串 | 说明 |
| --- | --- |
| `slotMemTestTrigged()` | 点击内存测试入口后的槽函数 |
| `slotDoMemTest` | 内存测试执行槽 |
| `Enter the Admin's Password` | 内存测试向导标题/提示 |
| `Administrator account:` | 管理员账号输入标签 |
| `Hint:` | 向导提示区标题 |
| `It is important that you enter the correct server name and password here...` | 明确要求输入正确服务器名和密码 |

也就是说，你看到“发起内存测试后要求验证管理员账户和密码”，这不是偶发行为，而是 Assistant 主程序本来就有的一页认证 UI。

更关键的是，这条链现在已经不只是“有认证页”，而是已经能追到认证后的第一条真实发送：

| 位置/函数 | 已确认行为 |
| --- | --- |
| `0x45d4b0` | 读取 `ConfirmPasswd` / `ConfirmAccount` 两个向导字段 |
| `0x45b0c0(account, password, nas, 1)` | MemTest 认证与发包主函数 |
| `0x47d010` | 对管理员密码做本地自定义编码 |
| `0x47d1c0` | `0x47d010` 的解码伴随函数 |
| `0x4abe80` | 组装 `packet_type = 0x0c` 的控制请求字段列表 |
| `0x4abb00` | 对非 request-class 包做加密/包装 |
| `0x4ac900` | 最终 UDP 发送函数 |

其中 `0x45b0c0` 里可以明确看到：

1. 密码走 `QString::toUtf8_helper -> snprintf -> 0x47d010`
2. 账号走 `QString::toLocal8Bit_helper -> snprintf`
3. 账号字符串被写入请求结构的 `+0xc24` 附近
4. 明文控制 payload 的 `packet_type` 被直接写成 `0x0c`
5. 随后 `0x4abe80` 组包，`0x4abb00` 做加密包装，最后由 `0x4ac900` 发出

也就是说，“点内存测试 -> 输入管理员账号密码 -> 立刻发控制包”这条主链已经坐实，而且它不是 HTTP，而是 Assistant 自己的 UDP 控制路径；真正上网线的是 `alt/encrypted` 头那一路，不是普通清晰发现包。

### 1.1 `0x47d010` 不是网页接口，而是本地自定义密码编码器

之前只知道主程序里有 `http://sy.to/encryptpassword` 这个字符串；现在可以进一步确认：

- MemTest 认证链上真正被调用的是 `0x47d010`
- `0x47d010` 不是 `QCryptographicHash`
- 它也不是直接去访问 `http://sy.to/encryptpassword`

`0x47d010` 的行为已经能复现为：

1. 把密码按 UTF-8 取字节
2. 按 8 字节一组补零
3. 每组与一个固定 `8x8` 矩阵相乘
4. 每个结果按有符号 12 bit 整数编码
5. 再映射到一个固定的 64 字符字母表输出

固定字母表是：

```text
UPX-BkYa4Fyi2DjcLef6WmOA8pZrshQ+uv7Vwx3G9oHb1EIJKzMg5NqRSCtTld0n
```

现在这对编解码已经能对上：

- `0x47d010` 负责编码
- `0x47d1c0` 负责解码
- 外层还有两层 QString 包装：
  - `0x44bc17`：`QString -> encode -> QString`
  - `0x44bd2e`：`QString -> decode -> QString`

也就是说，这不是“单向混淆”，而是一套完整的本地私有字符串编解码器。MemTest 管理员密码在主程序里会先走这套编码，再进入后续控制请求结构。

### 1.2 当前已确认的 MemTest 请求字段骨架

在 `0x45b0c0 -> 0x4abe80` 这一段里，当前已能明确看到 builder 参数里至少包含：

```text
0xa4, 0xa6, 0x01, 0x19, 0x2a, 0x4a, 0xc2, 0xc5
```

这些字段现在可以进一步细化为：

| 字段 | 结构偏移 | 语义 |
| --- | --- | --- |
| `0x01` | `+0xed0` | `packet_type = 0x0c` |
| `0x2a` | `+0x74` | 管理员密码经过 `0x47d010` 编码后的字符串 |
| `0x4a` | `+0xc24` | 管理员账号字符串 |
| `0xc5` | `+0x2f8c` | 本地 key ID / sender key id，由 `0x4affb0` 取出并注入 |
| `0xc2` | `+0x2f40` | 从现有 `NASINFO` 克隆并原样回带的控制字 |

另外，和这条链配套的还有：

| 字段 | 结构偏移 | 语义 |
| --- | --- | --- |
| `0xc4` | `+0x2f48` | `0x40` 字节 key string |
| `0xc6` | `+0x2f90` | 远端 key ID / lookup id，用于按 `MAC + key_id` 查本地 key |

支撑这组判断的直接证据有：

- `4af8e0` 用格式串 `%s+%08x` 和 `%s,%lx` 维护一条 `MAC + key_id -> key,timestamp` 的本地缓存
- `4afc00` 用同样的 `%s+%08x` 取回 key，并在找不到时打印：
  - `No key`
  - `fail to find key for %s+%08x.`
- 二进制里还有明确日志：
  - `my key is %s, ID %08x`
  - `FAILED to encrypt`
  - `No key to decrypt`

因此现在已经可以确认：

- 这不是普通发现包
- 这是一条 `packet_type = 0x0c` 的控制请求
- `0x0c` 不属于 `request-class`
- 因为 `4ab220` 只把 `0x01/0x13` 视为 request-class，所以 `0x0c` 一定会进入 `0x4abb00` 的加密包装路径
- 最终发出去的是 `alt_or_encrypted` 头的 UDP 包

### 1.3 `0x0c` 的完整外层包封装已经对上 `crypto_box_seal`

这一步现在已经可以收敛到标准构造，而不是“某种私有加密黑盒”：

- `4b6a40` 负责把缓存里的 `0xc4` 十六进制 key string 直接解成 32 字节公钥
- `4b4600 -> 4b4930 -> 4b6330` 生成临时密钥并导出 32 字节临时公钥
- `4b4660` 用 `blake2b(ephemeral_public_key || remote_public_key, digest_size=24)` 生成 24 字节 nonce
- `4bd0a0 -> 4bcfd0 -> 4c19f0` 对明文 `0x0c` TLV 执行公钥盒加密
- 最终密文 blob 的固定开销正好是 `48` 字节：
  - `32` 字节临时公钥
  - `16` 字节 MAC
  - 再加密文主体
- 外层再加 `8` 字节 `12 34 55 66 53 59 4e 4f` 头

所以当前可以把最终发包形式写成：

```text
udp_packet =
  ALT_HEADER ||
  crypto_box_seal(clear_payload, remote_public_key)
```

### 1.4 现在可直接构造的 `0x0c` 明文 payload

脚本按主程序里的固定顺序构造：

```text
0xa4, 0xa6, 0x01, 0x19, 0x2a, 0x4a, 0xc2, 0xc5
```

对应语义如下：

| 顺序 | 字段 | 内容 |
| --- | --- | --- |
| 1 | `0xa4` | 固定 `0x01020000` |
| 2 | `0xa6` | 固定 `0x00000078` |
| 3 | `0x01` | `packet_type = 0x0c` |
| 4 | `0x19` | 目标 NAS 的 MAC 地址字符串 |
| 5 | `0x2a` | 管理员密码经 `0x47d010` 编码后的字符串 |
| 6 | `0x4a` | 管理员账号 |
| 7 | `0xc2` | 从目标 `NASINFO` 克隆回带的控制字 |
| 8 | `0xc5` | sender key id |

### 1.5 真实抓包补齐了远端公钥获取流程

这次 `memtest_192.168.2.11.pcapng` 里能看到完整前置交换：

```text
18:15:45  192.168.2.7 -> 255.255.255.255:9999  clear UDP len=157
18:15:47  192.168.2.11 -> 192.168.2.7:9999     alt/encrypted UDP len=457
18:17:00  192.168.2.7 -> 255.255.255.255:9999  alt/encrypted UDP len=180
18:17:02  192.168.2.11 -> 192.168.2.7:9999     alt/encrypted UDP len=457
```

第一包 `157` 字节不是 MemTest 本身，而是 key exchange 明文请求。它的 TLV 顺序是：

```text
0xa4, 0xa6, 0x01, 0xb0, 0xb1, 0xb8, 0xb9, 0x7c, 0xc4, 0xc5
```

关键字段：

| 字段 | 语义 |
| --- | --- |
| `0x01` | `packet_type = 0x01` |
| `0xb0` / `0xb8` | key exchange 范围值，抓包中为 `0x1c0` |
| `0xb1` / `0xb9` | 抓包中为 `0` |
| `0x7c` | 本机网卡 MAC 字符串 |
| `0xc4` | 本机临时 public key，64 hex 字符 |
| `0xc5` | 本机 sender key id |

NAS 随后的 `457` 字节回包进入的是 Assistant 的 `FHOSTPacketReadEncrypted` 路径。该路径会先检查 `alt/encrypted` 头，再用本机 keypair 做 `crypto_box_open` 风格解密；它和发出 MemTest 请求时的 sealed-box 构造相关，但不能简单等同于“对旧 pcap 直接执行 `crypto_box_seal_open` 就一定能打开”。被动 pcap 里看得到本机公钥，但看不到当时 Assistant 的临时私钥，所以旧 pcap 不能直接解出 NAS 公钥。

正确做法仍然是主动复现这一步：我们自己生成一对临时 key，发同样的 `0x01 + 0xc4/0xc5` 请求，然后尝试用自己的私钥解 NAS 回包，抽取其中的 `0xc4` 作为远端 NAS 公钥。实测时如果 NAS 已经处于 `MEMORY_TEST_IN_PROGRESS`，它可能只继续回状态或旧会话相关的 encrypted 包，不再对新的 key exchange 返回可由当前临时私钥解开的内容。

`syno_memtest_flow.py` 现在已经补上这条路径：

- `--fetch-remote-key`：主动发 key exchange 并解密 NAS 回包
- `--dump-key-exchange-json`：打印解密后的 TLV
- `--dump-key-exchange-packet-hex`：打印 157 字节明文请求
- `--dump-key-exchange-response-hex`：打印候选回包原始 hex，方便继续逆向解密失败原因
- 如果 `--send-memtest` / `--dry-run-packet` 没提供 `--remote-key-hex`，脚本会自动先执行 `--fetch-remote-key`

### 1.6 Python PoC 的当前能力

新的 `syno_memtest_flow.py` 现在已经可以：

- 复现密码编码 `0x47d010`
- 复现 `0x01 + 0xc4/0xc5` key exchange
- 主动解出目标 NAS 的远端 public key
- 直接构造完整 `0x0c` 明文 TLV
- 直接做 `crypto_box_seal`
- 拼出最终的 `alt_or_encrypted` UDP 包
- 直接向目标 `9999/udp` 发 MemTest 请求

`0xc2` 的 bit 级定义还没有独立枚举表，但它在当前 MemTest 触发链里的角色已经明确：它不是现算随机值，而是从目标设备的现有 `NASINFO` 里克隆出来并原样回带的控制字。

### 2. 未初始化 NAS 的配置/安装流程不是纯 UDP

从 `slotManagerDoNetInstall` / `CThreadNetInstall` 往下追，目前已经确认：

1. 安装线程下层对象会显式创建 `QTcpSocket`
2. 它会对目标地址执行 `connect` / `waitForConnected(3000ms)`
3. 随后通过 `QIODevice::write()` 往 socket 写一段私有二进制控制报文
4. 线程里还会继续调用另一个发送/接收函数并长时间等待返回

因此，`NetInstall` / “给未初始化 NAS 配置并安装”的主流程，已经可以排除“只靠普通 UDP 发现包完成”的可能。当前更接近：

- 第 1 段：UDP 发现与选中设备
- 第 2 段：TCP 私有会话执行安装/配置

也就是一个“两段式流程”，而不是单一 UDP 控制。

### 3. 还没完全钉死的点

下面这些点仍在继续追：

| 未完成项 | 当前状态 |
| --- | --- |
| `http://sy.to/encryptpassword` 在程序其它路径中的作用 | 已确认它不在当前 MemTest 主认证发送链上，但它在别处的用途还没完全归档 |
| `0xc2` bit 级定义 | MemTest 链上已知是克隆回带的控制字，但还没拆出每一位的业务含义 |

## 常用命令

主动广播探测并监听：

```bash
python3 listen_syno_nas_status.py
```

只监听，不主动发探测包：

```bash
python3 listen_syno_nas_status.py --no-probe
```

打印所有状态包，而不是只打印变化：

```bash
python3 listen_syno_nas_status.py --print-all
```

打印解析后的完整 JSON，适合继续逆向字段：

```bash
python3 listen_syno_nas_status.py --dump-json --verbose
```

只打印每个包里的字符串字段，适合确认序列号、型号、名称分别落在哪个字段：

```bash
python3 listen_syno_nas_status.py --dump-strings --print-all
```

只运行 30 秒后退出：

```bash
python3 listen_syno_nas_status.py --duration 30
```

改成单播探测某台 NAS：

```bash
python3 listen_syno_nas_status.py --target-ip 192.168.2.6
```

MemTest PoC 自检：

```bash
python3 syno_memtest_flow.py --self-test-codec
python3 syno_memtest_flow.py --self-test-seal
```

只获取目标 NAS 的远端公钥，不触发 MemTest：

```bash
python3 syno_memtest_flow.py \
  --target-ip 192.168.2.11 \
  --no-credentials \
  --fetch-remote-key \
  --dump-key-exchange-json
```

如果 Windows 机器有多个网卡，建议显式指定抓包里 `0x7c` 对应的本机网卡 MAC。你这次 pcap 里该值是：

```bash
python3 syno_memtest_flow.py \
  --target-ip 192.168.2.11 \
  --no-credentials \
  --fetch-remote-key \
  --local-mac 02:11:32:2a:d6:1c \
  --verbose \
  --dump-key-exchange-response-hex \
  --dump-key-exchange-json
```

如果 NAS 已经处于 `MEMORY_TEST_IN_PROGRESS`，它可能只继续回状态包，不再接受新的认证/key exchange；这种情况下等内存测试结束后再执行上面的 key 获取命令。

只组包，不发送：

```bash
python3 syno_memtest_flow.py \
  --target-ip 192.168.2.11 \
  --username admin \
  --password 'your-password' \
  --dry-run-packet
```

直接发起 MemTest 并等待状态切到内存测试中：

```bash
python3 syno_memtest_flow.py \
  --target-ip 192.168.2.11 \
  --username admin \
  --password 'your-password' \
  --send-memtest \
  --wait-memory-test 60
```

只发送 `packet_type = 0x01` 探测：

```bash
python3 listen_syno_nas_status.py --packet-types 0x01
```

调整探测轮数和间隔：

```bash
python3 listen_syno_nas_status.py --rounds 5 --interval 2
```

## 参数说明

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--listen-ports` | `9999,9998,9997` | 本地接收端口候选列表 |
| `--target-ip` | `255.255.255.255` | 探测目标 IP，可设为广播地址或单台 NAS 地址 |
| `--target-port` | `9999` | 探测目标端口 |
| `--bind-send-port` | `1234` | 探测包本地源端口，失败时自动随机绑定 |
| `--packet-types` | `0x0f,0x01` | 逗号分隔的探测包类型列表 |
| `--a4` | `0x01020000` | 探测包 `field 0xA4` 的 u32 值 |
| `--a6` | `0x00000078` | 探测包 `field 0xA6` 的 u32 值 |
| `--rounds` | `3` | 启动时发送几轮探测 |
| `--interval` | `1.0` | 探测轮次之间的间隔秒数 |
| `--timeout` | `0.5` | select 轮询等待时间 |
| `--duration` | `0.0` | 运行时长，`0` 表示一直运行 |
| `--no-probe` | 关闭 | 只监听，不发送探测包 |
| `--print-all` | 关闭 | 每个状态包都打印；默认只打印状态变化 |
| `--dump-json` | 关闭 | 打印 `parse_syno_udp.py` 的完整解析结果 |
| `--dump-strings` | 关闭 | 打印每个包里解析出的字符串字段，方便定位序列号字段 |
| `--verbose` | 关闭 | 打印探测发送、非状态包、解析错误等调试信息 |

## 序列号获取

Synology Assistant 的“序列号”来自同一个 UDP 发现响应包，不需要登录 DSM Web API。抓到的 `BResponse` 已经确认字段关系如下：

| 字段 ID | 示例值 | 含义 |
| --- | --- | --- |
| `0xC0` | `V9F7O2T68BY24` | 完整 NAS 序列号 |
| `0x73` | `9FO2T8BY24` | 序列号相关的截断/派生字段，不作为最终序列号使用 |
| `0x78` | `SA6400` | NAS 型号 |
| `0x70` | `synology_epyc7002_sa6400` | 平台/产品族字符串 |
| `0x77` | `7.3.2` | DSM 主版本号字符串 |

脚本现在优先从 `field 0xC0` 读取序列号，并输出为 `serial`。

脚本的识别规则是：

1. 优先检查 `field 0xC0`。
2. 如果 `0xC0` 不存在，再检查其他可能字符串字段。
3. 候选值必须是 8 到 20 位的大写字母/数字组合。
4. 候选值不能是 MAC 地址、纯数字、已识别的名称或型号。

如果输出里还没有 `serial`，请运行：

```bash
python3 listen_syno_nas_status.py --dump-strings --dump-json --print-all
```

然后重点看输出中类似 `V9F7O2T68BY24` 这种字母数字混合字符串。确认字段 ID 后，可以把该字段固定加入脚本的优先序列号字段列表。

## IP 字段注意事项

实际测试中，某些响应包里的 `field 0x18` / `field 0x48` 会被解析成 `1.0.0.0` 这类明显不是 NAS 地址的值。因此脚本当前把 UDP 回包源地址作为最终展示 IP。

也就是说：

| 字段 | 推荐用途 |
| --- | --- |
| `ip` | 作为真实 NAS 地址使用 |
| `src_ip` | 调试时确认 UDP 源地址 |
| `field_ip` | 继续逆向 `0x48` 时参考 |
| `field_remote_ip` | 继续逆向 `0x18` 时参考 |

如果 `--dump-json --verbose` 抓到更多不同 DSM 状态下的响应包，可以继续把 `0x18`、`0x48`、`0x76`、`0x71` 的准确业务语义拆得更细。

## 依赖

脚本只依赖 Python 标准库和同目录下的 `parse_syno_udp.py`。

运行前确保当前目录包含：

```text
listen_syno_nas_status.py
parse_syno_udp.py
```
