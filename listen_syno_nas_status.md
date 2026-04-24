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
