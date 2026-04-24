# SynologyAssistant_reverse

这是一个用于研究DSM的SynologyAssistant是如何探寻发现局域网中的DSM状态并对其进行设置的项目

如果你不需要看其UDP包的传输细节和内容解析而是只需要解析NAS的广播状态，你可以转到[这个文件](./listen_syno_nas_status.md)来查看具体介绍

## 介绍

Synology Assistant 获取 NAS/DSM 状态的主链路：

1. 本机通过 UDP 广播向局域网发送 `SYNO` 协议探测包。
2. NAS 返回 `SYNO` 协议响应包，响应内容是带 8 字节头的 TLV 序列。
3. Assistant 把响应解到内部 `NASINFO` 结构。
4. 其中 `field 0xA7 -> NASINFO +0xeb4` 这个字段在 `BResponse/JResponse` 下是系统状态枚举。
5. UI 直接把这个枚举值映射成 `Booting`、`Starting services`、`Ready`、`Recoverable`、`Migratable` 等状态文本。

## 传输层与套接字

- 广播发送目标端口：`9999`
- 发送端本地 bind：`1234`
- 接收端本地 bind：优先 `9999`，失败回退 `9998/9997`
- 发送使用 `QUdpSocket::writeDatagram`

来源：

- `0x456ee0`
  - `movl $0x4d2, %esi` -> bind 本地 `1234`
  - `QHostAddress(SpecialAddress=1)` -> 广播地址
  - `movl $0x270f, %r8d` -> 发往 `9999`
- 接收端绑定逻辑此前已在 `0x45668c` 附近确认为尝试试 `9999`无法连通后再回退 `9998/9997`

## 协议外层格式

### 包头

明文头：

```hex
12 34 56 78 53 59 4E 4F
```

也就是：

```text
0x12345678 + "SYNO"
```

另一种头：

```hex
12 34 55 66 53 59 4E 4F
```

附近伴随 `No key to decrypt` / `Failed to decrypt packet` 字符串，属于另一条加密/协商分支。

### 普通字段编码

普通字段为 TLV：

```text
+--------+--------+------------------+
| id(1B) | len(1) | value(len bytes) |
+--------+--------+------------------+
```

已经对上的编码/解析函数：

- `0x4aa650`：字符串类字段编码
- `0x4aa1b0`：字符串类字段解析
- `0x4aa470`：固定长度标量编码
- `0x4aa330`：固定长度标量解析
- `0x4aa830`：数组/复合字段解析

### 特殊字段

下面三个字段不会走普通字段描述表 `0x89f160` 的 NASINFO 落表逻辑：

- `0x72`
- `0xA0`
- `0xA1`

值得注意的是：

- `0x72` 有明确语义。构包函数 `0x4ab840` 会把长字段 `0x2A` 切成多个 `0x72` 分片发出；解析函数 `0x4ab03e` 再把这些分片拼回长字符串区。
- `0xA0/0xA1` 目前没有看到落到 NASINFO 的描述表项，也没有看到它们出现在最小广播发现请求的构包字段表里。`0x4aaea3..0x4aaef7` 只是把它们从 “unknown PKT-ID” 日志里豁免，然后按“读 `len(1)` 和 payload”的方式跳过。

推测：

- `0xA0/0xA1` 仍然属于 `id + len + payload` 外观的协议扩展块
- 其不参与最小发现/状态监测主链路
- 没有证据表明它们会直接映射到 `NASINFO` 固定偏移

另外 `0x2A` 在构包时会被拆成多个 `0x72` 分片发送，所以抓包里连续出现 `0x72` 时，首先要考虑它是不是长字段重组块。

## 已确认字段与包类型

当前已经稳定确认的字段映射：

- `0x01 -> +0xed0`：`packet_type`
- `0x18 -> +0xea0`：`remote_ip`
- `0x48 -> +0xeb8`：`ip`
- `0x71 -> +0xec4`：`conf`
- `0x76 -> +0xeb0`：`con`
- `0xA7 -> +0xeb4`：`status_or_err`

已见响应包类型：

- `0x02`：`BResponse`
- `0x03`：`NSET`
- `0x04`：`QCF`
- `0x06`：`JResponse`
- `0x12`：另一类响应

**注意：`0xA7` 这个字段是复用位点。**

- 在 `BResponse/JResponse` 语境下，它是 NAS/DSM 系统状态。
- 在 `QCF/NSET` 日志语境下，同一个偏移会被解释为 `err`。

## 发现请求包类型

`0x4ab220` 这个辅助函数只接受两种请求类包类型：

```asm
4ab220: cmpl $0x1, %edi
4ab223: je   0x4ab230
4ab225: cmpl $0x13, %edi
4ab228: je   0x4ab230
```

随后它会在解析/校验路径里被调用：

- `0x4ab270`：取 `NASINFO +0xed0` 后调用 `0x4ab220`
- `0x4acb4a`：同样读取 `+0xed0` 后调用 `0x4ab220`

结合已经坐实的响应类型集合只有：

- `0x02`
- `0x03`
- `0x04`
- `0x06`
- `0x12`

可以把请求侧候选收敛到：

- `0x01`
- `0x13`

### 发送字段表构造器

`0x4abe80` 确认是将发送的 field_id 写进发送描述结构的函数。

它的行为是：

- 第一项 field_id 取自 `edx`
- 后续 field_id 依次取自 `ecx`、`r8d`、`r9d` 和栈上传入的可变参数
- 直到遇到 `0` 结束
- 最终把字段列表写到发送结构 `+0xc` 开始的位置，计数写到 `+0x8`

### 最小广播发现请求的固定字段

调用点 `0x45bc40`：

- 广播地址 `255.255.255.255`
- 目标端口 `9999`
- 调用 `0x4abe80`

对应寄存器取值：

```asm
45bca1: movl $0x1,  %r8d
45bca7: movl $0xa6, %ecx
45bcac: movl $0xa4, %edx
45bd11: callq 0x4abe80
```

最小广播发现请求的固定字段表：

- `0xA4`
- `0xA6`
- `0x01`

注意：是“固定字段 ID”，不是字段值。**字段 `0x01` 本身就是 `packet_type` 字段。**

广播请求包除 `packet_type` 外还有固定必选字段：最小主链路里，`packet_type` 之外至少还固定带 `0xA4`、`0xA6`

###  `packet_type = 0x01`

普通明文 LAN 广播发现，当前可以定为packet_type = 0x01`

Reason:

1. `0x4ab220` 只把 `0x01/0x13` 当成 request-class
2. `0x45bc40` 是直接发往 `255.255.255.255:9999` 的最小广播请求路径
3. 这条路径只挂最小字段表 `[0xA4, 0xA6, 0x01]`，没有 NetSetting/配置字段
4. 所以它对应的是普通发现，而不是配置/控制请求

###  `packet_type = 0x13` 的语义

- `packet_type = 0x13` 属于控制/配置类 request-class 包
- 它不是普通发现主链路，而是和 `sendNetSetting` / 带密钥材料的控制请求同一类

证据：

1. `0x4ab220` 只接受 `0x01/0x13` 为 request-class
2. `0x4ac900` 在 request-class 分支上：
   - 取本机 key：`0x4aff20`
   - 取 key id：`0x4affb0`
   - 写入 `field 0xC4`（41 字节公钥/十六进制串）
   - 写入 `field 0xC5`（4 字节 key id）
   - 然后调用明文构包 `0x4ab510`
3. `0x4599f0` 这条发送函数会：
   - 先挂最小字段 `[0xA4, 0xA6, 0x01]`
   - 通过 `0x4ac1d0` 追加 `0xB0/0xB1/0xB8/0xB9`
   - 取 key 和 key id
   - 日志出现 `%s:%d my key is %s, ID %08x`
   - 并按 `%s:%d sendNetSetting-round: %d` 多轮发送
4.  `0x13` 更像NetSetting/配置协商请求的request-class 控制包类

## DSM 启动状态字段与枚举值

### 状态字段位置

状态字段直接位于 UI 映射调用链：

```asm
0x47a040: mov esi, dword ptr [rbx + 0xeb4]
0x47a053: call 0x478050
```

也就是 UI 在展示 NAS 状态时，直接把 `NASINFO +0xeb4` 作为入参送给 `0x478050`。

`field 0xA7` 在 `BResponse/JResponse` 中就是 DSM 的系统状态字段。

### 状态枚举映射函数

`0x478050` 是状态枚举到文本资源 ID 的映射函数。它先做范围判断：

```asm
47806d: cmpl $0xe, %esi
478070: ja   0x478190
```

然后走 jump table，把 `0..14` 映射到不同资源 ID；超出范围则走数值格式化回退路径。

### 资源 ID 到字符串符号

资源表初始化函数 `0x49e440` 会把 `_dummy_tag_IDS_*` 字符串指针写进 `0x8a1080` 对应表项。把这张表抽出来后，`0x478050` 对应的状态资源可以完全恢复。

最终枚举表如下：

| 状态值 | 资源 ID | 资源符号 | 含义 |
| --- | --- | --- | --- |
| `0` | `0x101` | `IDS_LST_SYS_UNCONFIG` | 未配置 / 未初始化 |
| `1` | `0xfe` | `IDS_LST_SYS_READY` | Ready |
| `2` | `0x102` | `IDS_LST_SYS_UNINSTALL` | 未安装 |
| `3` | `0x103` | `IDS_LST_SYS_UPDATING` | Updating / Upgrading |
| `4` | `0xf7` | `IDS_LST_SYS_CRASH` | 系统异常 / 崩溃态 |
| `5` | `0xf5` | `IDS_LST_SYS_BOOTING` | Booting |
| `6` | `0xfd` | `IDS_LST_SYS_QUOTA_CHECKING` | Quota checking |
| `7` | `0x100` | `IDS_LST_SYS_SERVICE_STARTING` | Starting services |
| `8` | `0xfb` | `IDS_LST_SYS_NET_ERROR` | 网络错误 / 连接失败 |
| `9` | fallback | 无固定资源 ID | 保留值；`0x478050` 对它走数值回退显示 |
| `10` | `0xfc` | `IDS_LST_SYS_NET_TESTING` | 网络测试中 |
| `11` | `0xff` | `IDS_LST_SYS_RECOVERABLE` | Recoverable |
| `12` | `0x23c` | `IDS_WAKEUP_OFF_LINE` | Wakeup/Offline |
| `13` | `0xf6` | `IDS_LST_SYS_CHECKING_PROGRESS` | Checking progress |
| `14` | `0xfa` | `IDS_LST_SYS_MIGRAT` | Migratable |

其中最常见的几个值是：

- `5` -> `BOOTING`
- `7` -> `SERVICE_STARTING`
- `1` -> `READY`
- `11` -> `RECOVERABLE`
- `14` -> `MIGRAT`
- `2` -> `UNINSTALL`

## 软件获取 NAS 状态的完整流程

1. Assistant 创建发送 socket，bind 本地 `1234`。
2. Assistant 构造 `SYNO` 明文请求包。
3. 对“普通发现/状态刷新”这条主链路，最小固定字段表是：
   - `0x01`
   - `0xA4`
   - `0xA6`
4. Assistant 向广播地址 `255.255.255.255:9999` 发送请求。
5. NAS 收到后返回 `SYNO` 响应包。
6. Assistant 在本地 `9999` 接收；如果占用，则退到 `9998/9997`。
7. 响应包被解成 `NASINFO`：
   - `0x01` -> `packet_type`
   - `0x18` -> `remote_ip`
   - `0x48` -> `ip`
   - `0x71` -> `conf`
   - `0x76` -> `con`
   - `0xA7` -> `status_or_err`
8. 如果响应是 `BResponse/JResponse`，`0xA7` 会被当成状态枚举。
9. UI 代码读取 `NASINFO +0xeb4`，调用 `0x478050`，把枚举值翻译成最终状态文本。

## 可复原的报文骨架与解析

### 最小发现请求骨架

按当前证据，普通发现请求的最小骨架应该写成：

```hex
12 34 56 78 53 59 4E 4F
A4 04 ?? ?? ?? ??
A6 04 ?? ?? ?? ??
01 04 01 00 00 00
```

解析：

- `12 34 56 78 53 59 4E 4F`：明文 `SYNO` 头
- `A4/A6`：当前已经能确认是最小广播发现请求里的固定字段，但还没恢复出精确字段名
- `01`：字段 ID，表示 `packet_type`
- `04`：长度 4
- `01 00 00 00`：`packet_type = 0x01`

### 响应包里带 Booting 示例

如果某台 NAS 返回如下核心字段：

```hex
12 34 56 78 53 59 4E 4F
01 04 02 00 00 00
18 04 C0 A8 01 64
48 04 C0 A8 01 0A
76 04 01 00 00 00
71 04 01 00 00 00
A7 04 05 00 00 00
```

可以解析成：

- `0x01 = 0x02` -> `BResponse`
- `0x18 = C0 A8 01 64` -> `remote_ip = 192.168.1.100`
- `0x48 = C0 A8 01 0A` -> `ip = 192.168.1.10`
- `0x76 = 1` -> `con = 1`
- `0x71 = 1` -> `conf = 1`
- `0xA7 = 5` -> `IDS_LST_SYS_BOOTING`

于是 UI 最终显示的就是 Booting。

如果把最后一段改成：

```hex
A7 04 07 00 00 00
```

那就是：

- `status = 7`
- `IDS_LST_SYS_SERVICE_STARTING`

最终 UI 会显示 Starting services。

再改成：

```hex
A7 04 01 00 00 00
```

那就是：

- `status = 1`
- `IDS_LST_SYS_READY`

最终 UI 会显示 Ready。

## 解析工具

`parse_syno_udp.py` 可以直接解析抓到的 UDP payload，并对已确认的包类型和状态值做注释：

```bash
python3 parse_syno_udp.py --hex "12 34 56 78 53 59 4E 4F ..."
python3 parse_syno_udp.py --file payload.bin --pretty
```

当前脚本会额外做这些事：

- 给 `field 0x01` 标注 `packet_type_name`
- 在 `BResponse/JResponse` 中把 `field 0xA7` 解成状态符号名
- 标注一个包是否带有 `0x01 + 0xA4 + 0xA6` 这组 discovery core fields
- 标注一个请求是否更像最小发现，还是更像控制/带密钥请求
