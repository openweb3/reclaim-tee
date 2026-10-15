# TEE 内部耗时计量：方案与实施记录

2026-10-15。状态：已实现并本地验证，镜像已按最终代码重建，**尚未部署**。

目标：把 TEE 处理一次请求的时间拆到可归因的几段上，并且这些数字在 AWS SEV-SNP 实例上拿得到。

## 0. 结论

- 一次请求一行，十三个分段，字段名只定义一次。
- 明细由 TEE 自己开一个端口供外部拉取，不主动外推。结构化 logger 保留：聚合行与 stall 行走它，落在串口上，用 `get-console-output` 读。CloudWatch 不在方案里。
- level 管的是**写进日志多少**：`summary` 每窗口一行聚合，`full` 再加每请求一行。
  18092 的环与 level 无关，任何级别都收全量请求记录。反过来（环跟着 level 走）会让长跑推荐的
  `summary` 顺手关掉明细通道，而环里空着和「这台 TEE 很闲」看起来一模一样。
- 默认关闭。`TEE_TIMING=off|summary|full`，改这三个环境变量就能调，不用重新打包。
- 串口不再是样本量的限制。环里保留 4096 条记录（约 2 MB），1 req/s 覆盖约 68 分钟，0.1 req/s 覆盖约 11 小时。

## 1. 现场证据

2026-10-15 实测，命令只读。

| 项 | 实测值 | 来源 |
| --- | --- | --- |
| TEE 实例 | `i-01406dfaa4272363d`，running，私网 10.0.1.189 | `describe-instances` |
| 规格 | c6a.large，2 vCPU，4096 MiB，AmdSevSnp=enabled | `describe-instances` 与 `describe-instance-types` |
| IAM instance profile | `null` | `describe-instances` |
| 串口输出字节数 | 65536（正好打满） | `get-console-output --latest` |
| 窗口内行数 | 529 行，其中应用行约 60 条 | 落盘的 `/tmp/tee_console.txt` |
| 窗口覆盖时间 | 2026-10-10 02:55Z 至 2026-10-15 06:37Z | 同上 |
| 每条应用行出现次数 | 2 次 | 逐行 `uniq -c` |
| 窗口内已有失败证据 | `upstream TLS handshake to chatgpt.com:443 failed: EOF` 3 次，`http: TLS handshake error from 10.0.1.151` 4 次 | 同上 |
| 改动前的数据面日志 | 只有上游握手失败一行 | `transport/channel.go` |
| 应用输出去向 | `MultiWriter(os.Stdout, /dev/console)` | `deploy/snp-image/loader/main.go:638` |
| 时钟 | `CLOCK_REALTIME` 被 SNTP 步进，`CLOCK_MONOTONIC` 不动 | `shared/clock_discipline_linux.go:103` |
| 收据时间戳精度 | 整秒 | `tokenhive/tee/service.go` 的 StartedAt 赋值 |

三条推论：

1. 串口是唯一的常驻通道，5 天里被写到只剩 60 条应用行。窗口不是宽裕，是刚好没被写满。
2. 上游握手 `EOF` 与 Hub 侧握手失败同时存在，说明联调已经走到拨号上游这一步，而现有日志只有一句无法归因的失败。
3. 每条行出现两次，最可能是 loader 的 `MultiWriter(os.Stdout, /dev/console)` 里 `os.Stdout` 本身就是 console。loader 属于 R 签名的 base UKI，本 fork 拿不到密钥，所以只能按 2 倍计预算。

## 2. 计时区间

按「修一次能挪动它」选，不按「代码里好插」选。段名是日志契约的一部分，不复用。

| 段 | 起点锚点 | 终点锚点 | 为什么值得测 |
| --- | --- | --- | --- |
| `read` | `tee/rpc.go` `ServeExecute` 入口 | 请求体读完并解码 | Hub 到 TEE 链路慢会先在这里出现 |
| `gate` | `tee/service.go` `Execute` 入口 | 体积上限检查之后 | 全部准入拒绝路径，纯 CPU |
| `cred` | 同上 | 凭据信封解封并合入头 | X25519 加 AEAD，确认它不是瓶颈 |
| `hash` | 同上 | spec 摘要算完 | 纯 CPU |
| `seq` | 同上 | 序号分配返回 | 唯一改状态的步骤，全局互斥加一次写盘 |
| `acquire` | `transport/channel.go` `Do` 入口 | 拿到连接或拨号名额 | 池命中还是排队，决定后面两段要不要付 |
| `dial` | `transport/channel.go` `dialTCP` | 原始管道建立 | 首次还要建到 Hub 的 WS 隧道，失败就挂这里 |
| `tls` | 同上 | 上游 TLS 握手返回 | 经 Hub、agent、OpenAI 三跳，信任库配错在这里静默死 |
| `write` | `transport/channelpool.go` `exchange` | 请求字节写完 | 解释 TTFB 的起点 |
| `ttfb` | 同上 | 响应头解析完 | 上游排队加生成时间，真实请求里最大 |
| `body` | 同上 | 响应体中继结束 | 大部分是上游生成时间，附带字节数与块数 |
| `sign` | `tee/service.go` `perform` | `Sign` 返回 | 上行路径唯一的密码学操作，含证据规范化 |
| `emit` | `tee/rpc.go` | 收据帧写完 | 证据内嵌后这一帧到几十 KB |

三条语义，都写进了代码注释：

- 这是一条链，不是一棵树。每个打点关闭上一段并开下一段，所以段的和就是请求的墙钟时间，没有任何一毫秒被记两次。
- `egress_ms` 是唯一不在这条链上的数：它量的是写响应帧被阻塞的时间，落在 `body` 里面，所以它是字段而不是段。
- 冷连接才有 `dial` 和 `tls`。热连接没有这两段，这就是读者区分两者的方式。死连接重拨时 `acquire` 与 `write` 各记一遍时间，但段名在一条记录里只出现一次，记的是两遍的总和。

## 3. 输出：一套字段名，两种呈现

字段名只定义一次（`tee.TimingRecord.Flat`），log 行与 `/timing` 端点共用。持续时间都是毫秒浮点，单位写在字段名里。

请求行：`job` `provider` `host` `method` `stream` `cold` `outcome` `bytes` `chunks` `egress_ms`，失败时多一个 `error`，其余是各段的 `_ms`。

```
{"level":"info","message":"tee.request","job":"9f3a…","provider":"openai","host":"chatgpt.com",
 "method":"POST","stream":true,"cold":true,"outcome":"complete","bytes":18342,"chunks":57,
 "egress_ms":8.2,"read_ms":0.4,"gate_ms":0.1,"cred_ms":0.3,"hash_ms":0.02,"seq_ms":1.2,
 "acquire_ms":0.05,"dial_ms":12.3,"tls_ms":118.7,"write_ms":0.2,"ttfb_ms":903.1,
 "body_ms":4201.0,"sign_ms":2.1,"emit_ms":0.6}
```

stall 行：`job` `provider` `host` `method` `stream` `cold` `stage` `waited_ms`，warn 级，不带已完成段。

聚合行：`requests` `cold` `failed` `window`，各段 `_p50_ms` `_p95_ms` `_n`，最后一个是 `sink` 段，量的是把一条记录交给 sink 花掉的 TEE 自身耗时。

`/timing` 响应：`service` `retained` `served` `total` `dropped` `records` `aggregate`，每条记录带 `seq` 与 `at`。没有分页也没有过滤：一次拉取拿到环里现存的全部记录，调用方按 `seq` 自己维护游标。

容量：

| 通道 | 计算 | 结果 |
| --- | --- | --- |
| 串口 | 65536 B，每行出现两次，明细行约 300 B | 约 110 次请求后窗口开始滚 |
| 环，默认 4096 | 每条约 500 B | 约 2 MB 内存，1 req/s 覆盖 68 分钟，0.1 req/s 覆盖 11 小时 |
| 环，上限 65536 | 同上 | 约 35 MB，够一次长压测 |

「单轮剖析请求数上限」现在由内存决定，不由串口决定。要更长窗口调 `TEE_METRICS_RETAIN`。

## 4. 日志自身的开销

聚合行里的 `sink` 段就是这一项：sink 接收一条记录花多久。它比别处重要，因为 sink 的一头是串口写，而串口写是这里唯一可能比它所描述的工作更贵的东西。这个数停在微秒级，说明测量干净；涨到毫秒级，说明先调低 level 再相信窗口里的其他数字。

一次记录写进串口会不会拖慢它自己所属的那次请求？会一点，但只到响应流关闭为止：报告在 handler 的 defer 里跑，在收据帧已经 flush 之后。这个取舍写在 `ServeExecute` 的注释里。

## 5. 落点

| 文件 | 内容 |
| --- | --- |
| `tokenhive/tee/timing.go` | 新增。分段常量、`Timings` 记录器、`TimingReporter` 聚合器、`Flat` 字段渲染、`TimingSinks` 扇出 |
| `tokenhive/tee/service.go` | `Config.Timing`、`newTimings`、`reportTiming`、`watchStall`，以及 `gate`/`cred`/`hash`/`seq`/`sign` 打点 |
| `tokenhive/tee/rpc.go` | 记录的生命周期、`read`/`emit` 打点、`egress_ms` 累计、拒绝路径也上报 |
| `tokenhive/tee/transport.go` | `Request.JobID`，以及「transport 可以往 ctx 里的记录打点」这条约定 |
| `tokenhive/transport/channel.go` | `acquire`/`dial`/`tls` 打点、`SetCold`、握手失败行带上 job |
| `tokenhive/transport/channelpool.go` | `write`/`ttfb`/`body` 打点 |
| `tokenhive/metrics/` | 新增。留存环加 `GET /timing` 拉取端点 |
| `tokenhive/cmd/tee/main.go` | 三个 timing 旗标、metrics 监听、结构化 logger sink（zap 字段来自 `Flat`） |
| `tokenhive/cloudtest/snp/crosshost.py` | `TEE_METRICS_ADDR=0.0.0.0:18092`、`TOKENHIVE_TEE_TIMING`、安全组放开 18092 |

记录为什么走 ctx 而不是签名字段：打点的人分布在三层（handler 读体、service 准入、transport 换包），走签名就要改 `Service.Execute` 和 `Transport.Do`，而 `Execute` 有上百个调用点。`Request.JobID` 仍然加了，它是给 transport 自己的日志行用的。

## 6. 阶段

- Phase 0，零代码：收齐现有信号。见第 1 节。
- Phase 1，最小改动：请求结束一行加 stall 一行。已实现。
- Phase 2，分段明细：十三段、聚合行、sink 自身耗时。已实现。
- Phase 3，通道：**原计划是 CloudWatch，改为 TEE 自开 `/timing` 端口由外部拉取**。已实现。
- Phase 4，会话路径：未做。`/v1/session` 目前不打点，`OpenSession` 拿到的记录是 nil，所有打点都是空操作。要做就是 `ServeSession` 开记录、`relaySession` 收尾上报这一件事。

## 7. 已定的点

1. 日志出口：结构化 logger。字段由 `Flat` 统一渲染，所以拉取与日志同名同单位。
2. 归因方式：`Request` 加 `JobID`，分段打点走 ctx。
3. 重建：完成 Phase 1 之后直接建镜像，不立刻部署。
4. 请求数上限：4096 条记录，约 2 MB。机器是 2 vCPU / 4 GiB，这个量级可忽略。要更长窗口调 `TEE_METRICS_RETAIN`，上限 65536。

## 8. 反面清单

- 不逐块打日志。会话和 SSE 每块一行会在几分钟内吃掉整个窗口。
- 不把明细默认打开。会让 bench 的门槛失去意义，也会在并发下互相拖慢。
- 不用收据里的 `StartedAt`、`FinishedAt` 做分段。它们是整秒。
- 不用 `Unix()` 相减算耗时。SNTP 会步进 realtime。
- 不在日志里记 path、query、header。凭据就在 header 里。
- 不靠改 loader 去掉重复行。loader 在 R 签名的 base UKI 里，本 fork 没有密钥。
- 不依赖 CloudWatch。日志落在串口上，`get-console-output` 就能读。

## 9. 在 AWS 上怎么用

部署时带 level，不带就是 off：

```
TOKENHIVE_TEE_TIMING=full ./crosshost.sh up --tee-only --host-ip 10.0.1.151
```

`crosshost.py` 会把 `TEE_METRICS_ADDR=0.0.0.0:18092` 和 level 写进 user-data，并把 18092 放进安全组的同组放行。user-data 只在实例创建时生效，改 level 要重启 TEE 进程。

从 Hub 机（10.0.1.151）拉取：

```
curl -s "http://10.0.1.189:18092/timing" | jq '.retained, .dropped, .total'
curl -s "http://10.0.1.189:18092/timing" | jq -c '.records[] | select(.seq > 1200) | {job, cold, ttfb_ms, tls_ms}'
```

四点注意：

- 这个端口是明文，没有 mTLS。所以这里的 curl 退出码是有意义的，不像 18090 那样必然报 `(60) self-signed certificate`。
- 拉完先看 `dropped` 与 `retained`。`dropped` 涨了，说明环已经滚过你要的窗口。
- 端点不认查询参数，本地用 `select(.seq > 上次拉到的最大 seq)` 去重即可。
- 记录里的 `job` 是 Hub 生成的那个 16 字节 ID 的十六进制，可以和 Hub 自己的日志对齐。

串口仍然可以看，只是不再需要它承担明细：`get-console-output --latest` 里有启动三行、每隔 `TEE_TIMING_WINDOW` 的聚合行、以及 stall 行。
