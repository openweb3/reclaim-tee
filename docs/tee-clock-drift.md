# TEE guest 时钟漂移故障：诊断与修复

> 一台跑了两周的 SEV-SNP TEE 悄悄失去了轮换能力。表面症状是 RA-TLS 刷新每次都失败，
> 根因是 guest 内核时钟的频率误差累积到击穿重试窗口。本文记录怎么发现的、为什么不会自愈、
> 以及怎么修的。
>
> 分支 `fix/tee-clock-discipline`，实现 commit `23eec8e` 与 `bdb32a2`。

## 1. 症状

旧 TEE `i-042539e8587e4c02e` 的 console 里，每一轮 RA-TLS 刷新都失败，错误永远是同一条：

```
NitroTPM cert chain: x509: certificate has expired or is not yet valid:
  current time T is before NotBefore T+Δ
```

有两个细节一开始很反直觉。

第一，报错说证书**尚未生效**，不是过期。NitroTPM 叶证书的 `NotBefore` 由 hypervisor 盖章，
guest 伪造不了，所以这条错误只有一个解释：**guest 自己的钟落后于真实时间，落后量就是 Δ**。

第二，失败的只有轮换，请求处理一切正常。`/v1/execute` 照常返回，因为手里那张初始证书
还有效。于是监控上一片绿。

## 2. 诊断链

### 2.1 先排除宿主时钟

`get-console-output` 末行时间戳与本地 `date -u` 只差 14 秒，就是拉取的延迟。宿主是准的，
漂的是 guest 内部时钟。这一步值得先做，因为它排除了一个看起来最像的嫌疑。

### 2.2 从错误信息里直接读出漂移量

Δ 就是落后量，不用另找指标。23 个样本，从 2026-10-07 的 24 秒涨到 10-09 的 30 秒。

线性回归给出 **26.5 ppm，2.3 秒/天，方向恒为落后**，全程无跳变。频率误差，不是固定偏差。

### 2.3 确认起点是准的

loader 起来的第一条日志 `2026-09-23T06:06:44.917Z`，EC2 LaunchTime 是 `06:06:04Z`，
差 41 秒，其中 UEFI 加 loader 约 5.5 秒。

起点准、频率错，这就排除了「NTP 没同步」「时区错了」这类起点类原因。

### 2.4 根因：clocksource 竞争

这一步有个坑。要看到 clocksource 的选择过程，必须取**不带 `--latest`** 的完整 console。
带 `--latest` 只有本次启动的尾部，BIOS 和内核早期日志都被截掉了：

```
[3.325692] clocksource: Switched to clocksource kvm-clock     ← 先注册了 hypervisor 时钟
[3.785145] clocksource: tsc: ...
[3.807792] clocksource: Switched to clocksource tsc           ← 又被覆盖
tsc: Detected 2650.000 MHz                                    ← 未校准的标称频率
```

`kvm-clock` 走 hypervisor 的 MSR 时钟，本来是准的。clocksource watchdog 认为 `tsc` 更适合，
把它提升到 `kvm-clock` 之上，而 SEV-SNP 下的 `tsc` 频率是从 `GUEST_TSC_FREQ` 读回来的标称 P0 值，
没有校准。26.5 ppm 就是这么来的。

顺便排除一个看似匹配的 CVE：`CVE-2025-38508` 讲的就是 SEV-SNP Secure TSC 的
`TSC_FACTOR` 与标称频率不符，修复版本是 6.16。本机内核 `7.0.0-1011-aws` 远高于它，
所以不是那个 bug，就是没做频率校准。

最后回到源头确认：`deploy/snp-image/tier-build.sh` 的 `SNP_CMDLINE` 当时只有
`console=ttyS0,115200`，没有任何 `tsc=` 或 `clocksource=` 校正项。

## 3. 为什么会演变成致命故障

漂移本身不可怕。可怕的是它吃掉了一个具体的预算。

轮换节奏由三个常量决定（`tokenhive/cmd/tee/ratls_refresh.go`）：

| 常量 | 值 | 作用 |
|---|---|---|
| `snpReissueWindow` | 9m48s | NitroTPM 只在叶证书到期前这个窗口内重签 |
| `snpRotationLead` | 9m | 轮换瞄准 `NotAfter − 9m`，故意落在窗口内 |
| `minRefreshFloor` | 2m | 失败后的重试下限 |

`snpRotationLead` 比窗口小 48 秒，所以排定的第一次尝试就落在窗口内，正常情况下能直接拿到新叶。
失败后按 `minRefreshFloor` 退避 2 分钟重试，那一次落在 `NotAfter − 6m48s`，仍在窗口内，也能成功。

**但这个重试能成功的前提是重试网格不整体平移。** guest 的钟落后 Δ 之后，同一个 `NotAfter` 在
guest 看来更靠后，于是每一次重试的实际执行时刻在平台那边都提前了 Δ。当 Δ 追上
`snpReissueWindow − minRefreshFloor` 这段余量，重试网格的**整窗**就跨过了平台的重签窗口。

那一刻起，不是「偶尔失败」，是**每一次都失败**：排定的首次尝试按 `snpRotationLead` 算已经太早，
重试按 floor 算也太早。轮换能力永久归零，日志安静下来，叶证书按自己的节奏过期。

`SNPAdmissionDeadline`（`shared/router_runtime.go:99`）取的就是叶证书的 `NotAfter`，
它同时是准入期限和新鲜度门。过期那一刻起，所有推理请求被拒。

按 2.3 秒/天，从故障当天的 30 秒走到 120 秒约 **39 天**，也就是这台机器会在 2026-11-18 前后
彻底拒单。没有告警，因为业务侧看到的是「一直好好的机器突然全拒」。

### 为什么自愈机制没救回来

`AttestationHealth` 的自愈门槛是连续失败 6 次（`attestSelfHealAfter`，
`shared/attestation_health.go:26`），达到就 warm reboot。但这里的失败形态恰好绕开了它：

每轮刷新先失败一次（`RecordFailure` 把 `consecFails` 加到 1，`router_runtime.go:272`），
2 分钟后的重试成功了（`RecordSuccess` 把计数清零，`router_runtime.go:279`）。
下一轮重复这个模式。计数在 1 和 0 之间来回，永远到不了 6。

**失败一次、随后自愈、整体存活，这是最坏的形态**：系统看起来是健康的，唯一的症状是日志里
每次刷新都有一条 error。

## 4. 修复

两条独立的路子，同时上。

### 4.1 A：把 clocksource 钉在 hypervisor 时钟上

治本。让 watchdog 没有东西可提升，`kvm-clock` 就一直留在首位。

`deploy/snp-image/tier-build.sh:29`：

```bash
CMDLINE="${SNP_CMDLINE:-console=ttyS0,115200 clocksource=kvm-clock}"
```

这一行进 base UKI 的 kernel cmdline，被 systemd-measure 测入 PCR 11。

改 cmdline 的成本比看上去低。`snp-build.sh:334-336` 明写 base UKI 的 sha256
"is printed for diagnostics only; it is no longer a production pin or rollout dependency"，
`SNP_BASE_UKI_*` 与 `SNP_BASE_DIGEST_*` 全仓库无人读取。`EXPECTED_PEER_BASE_DIGEST` 只被
`tee_k/config.go:59` 与 `tee_t/config.go:50` 消费，TokenHive 的 `cmd/tee` 不读它。
所以生产上唯一的 pin 是 app 摘要（PCR 8），重建 base UKI 不需要重钉任何 allowlist。

### 4.2 B：broker 定期 SNTP 校时

兜底。假设某天又冒出别的频率误差，校时能把落后量按住。

新文件 `shared/clock_discipline_linux.go`，落点在
`shared/snp_attestation_broker_linux.go:84-85`：

```go
logger, _ := NewLoggerFromEnv("tokenhive-tee-broker")
DeployClockDiscipline(logger)
```

落点选 broker 有两个原因。broker 以 root 跑（loader 用 `exec.Command(entry)` 起它，不带降权
`SysProcAttr`），是唯一能改系统时钟的进程，app 侧只有 `CAP_NET_BIND_SERVICE`，改不了钟。
broker 已经有 root 专属动作的先例，`resetGuestFromBroker` 就是调 `syscall.Reboot`。
首次校时是同步的，`DeployClockDiscipline` 返回后才进入 serve，所以第一次 attestation
一定是对着校过的钟测的；之后的周期校时才放进 goroutine。

几个设计选择：

- **每 15 分钟校一次**（`clockResyncInterval`），broker 起来时先立刻同步一次，之后按
  `time.Tick` 走。按本次实测的 26.5 ppm 折算，15 分钟内漂约 24 纳秒，残余量对这个平台可以忽略，
  而成本只是一次 link-local 往返。间隔再密收益也不明显，因为 A 已经把频率误差消掉了，
  B 只是兜底。
- **自己实现 SNTP 四时间戳握手，零新依赖。** `golang.org/x/time v0.15.0` 已在 go.mod，
  但只装了 `rate` 子包，没有 `ntp`，网络受限也拉不到。
- **参考源用 `169.254.169.123`**（Amazon Time Sync，link-local，UDP 123）。不需要改安全组，
  出网本来就是 `-1 0.0.0.0/0`。健康往返是亚毫秒级，所以单次查询的超时只给 3 秒，
  再久也只是拖延下一次尝试。
- **只动 `CLOCK_REALTIME`，且用 step 不用 slew。** Go 的 monotonic deadline 不受校时影响，
  `CLOCK_MONOTONIC` 一旦被 slew 会破坏 `time.Ticker` 的节奏。
- **单次校正上限 10 分钟**（`maxClockStep`）。一个畸形或被伪造的回复不该把机器的钟推到天荒地老。
  真实漂移是秒/天级，这个天花板永远碰不到合法校正。
- **校验 origin stamp。** 服务器回显的 `req[24:32]` 必须等于发出的 `req[40:48]`，
  否则拒掉。这挡的是重放和伪造的回复。
- **拒收未同步的回复（LI 3、stratum 16+）。** 服务器自己失去参考源时会这样标记，
  其时间戳是占位值。chrony/ntpd 同样拒收，信它等于让一个退化的源把钟推最多 10 分钟。
- **纪元推断解码（2036 回绕）。** NTP 的 32 位秒在 2036-02-07 归零，解码时把结果推到
  本地时钟所处的纪元。否则回绕后的回复会被读成 1900 年前后，偏移量超过 10 分钟上限被拒，
  校时从此永远失败。
- **校时失败只告警不改钟**，`logger` 为 nil 也照跑。校时是健康设施，不该因为日志系统建不起来就停摆。
  测不准的时刻就不猜，下个 tick 再试。
- **成功路径不打日志**，只有失败才 `Warn`。每 15 分钟一行成功日志，噪音大于信息量。
- **`time.Tick` 而非 `NewTicker` + `defer Stop()`。** 承载周期校时的 goroutine 永不返回，
  `defer` 是死代码。

### 4.3 为什么不是别的做法

不加 `tsc=` 之类的频率补偿参数，是因为 A 已经把 clocksource 换掉了，再配一个频率参数属于
对症不对因。

不引入 chrony 或 systemd-timesyncd，是因为这台机器没有 systemd。TEE 是一段 UKI 加 loader 当 PID 1，
`deploy/snp-image/tier-build.sh` 只把 loader 放进 initrd，没有 init 系统也没有包管理器。

不做每次 attestation 前都校时。校时是 UDP 往返，放在每次证明的热路径上会把网络抖动
引成证明失败。

## 5. 验证

### 5.1 单元测试

新增 5 个测试（`shared/clock_discipline_linux_test.go`）：`sntpOffset` 的表驱动三例、
NTP 时间戳往返与纪元偏移、`applyClockStep` 的拒绝路径、五个畸形回复的拒绝、一个正常回复的接受。

`applyClockStep` 只测拒绝路径（超上限）与 `offset == 0` 的 no-op 分支，**不测接受路径**。
那是真的 `clock_settime`，单元测试没资格改跑它那台机器的钟。

跑法有个坑。本机是 darwin/arm64，`//go:build linux && !mobile` 会把所有 `_linux.go` 排除掉，
`go test ./shared/` 静默报 "no tests to run"（既有的 `attestation_health_linux_test.go`
同样跑不到）。交叉编译后挂进容器真跑：

```bash
GOOS=linux GOARCH=amd64 go test -c -o /tmp/shared_linux.test ./shared/
docker run --rm --platform=linux/amd64 -v /tmp/shared_linux.test:/t:ro <alpine pinned> /t -test.v
```

校验测试真的编进去了：`strings /tmp/shared_linux.test | grep TestXxx`。

其余检查：`shared` 全包 0 FAIL ｜ harness（在 `/tmp` 的干净 worktree 里，仓库内跑会把
`.sim` 残留变成假 FAIL）0 FAIL，scenario 17/18 全过 ｜ 31 个 cloudtest Python 单测通过 ｜
受影响包 `GOOS=linux` 编译 + vet + gofmt 干净。

### 5.2 产物核对

- AMI 的 `snp-app` tag 与 `deploy/snp-digests.env` 一致 ⇒ `crosshost.sh up` 能锁对镜像
  （它靠这个 tag 锁定，见 `crosshost.sh:286-296`）。
- base UKI 的 kernel cmdline 含 `clocksource=kvm-clock`。本机没有 `objcopy`（exit 127），
  `strings snp-base.efi | grep console=` 就够。

**别信 `snp-digests.env` 里的 `COMMIT` 字段。** `snp-build.sh:299` 把 `REPO_ROOT` 覆写成
`CLONE_DIR`，记下的是干净 clone 的 HEAD，不是工作树的。实测它写 `cfe3720` 而真实 HEAD 是
`bdb32a2`。唯一可信的核对是：

```bash
tar -xf app-bundle.tar -C /tmp/x && go version -m /tmp/x/app | grep vcs.revision
```

### 5.3 真机确认

新 TEE `i-01406dfaa4272363d`（私网 10.0.1.189，AMI `ami-03ca62b0d44017ba6`，
app digest `snp-app:1260f3ae…88ff6d836`）的 console：

| 项 | 旧机 | 新机 |
|---|---|---|
| `Command line` | `console=ttyS0,115200` | `console=ttyS0,115200 clocksource=kvm-clock` |
| `Switched to clocksource tsc` | 每轮都被覆盖一次 | **0** |
| `Detected 2650.000 MHz` | 有 | **0** |
| `RA-TLS refresh failed` | 每轮一次 | **0** |

broker pid=88、app pid=89 uid=65532 都正常。console 时钟与本地 `date -u` 只差拉取延迟。

## 6. 换 TEE 的后续动作

修复本身不生效于已跑偏的机器，必须换机重签。三件事：

```bash
# 1) 起新 TEE，--new 不终止旧机，旧记录挪到 superseded
cd tokenhive/cloudtest/snp
./crosshost.sh up --tee-only --new --host-ip 10.0.1.151

# 2) 改 Hub 的 hive.env 三行，然后重启 Hub
#    HIVE_TEE_ENDPOINT / HIVE_TEE_EXPECTED_APP / HIVE_RELAY_ALLOWED_CIDRS
#    只改文件不重启不生效，hive 不处理 SIGHUP

# 3) 确认新机服务正常后退役旧机
./crosshost.sh down --superseded
```

`--host-ip 10.0.1.151` 是 Hub 的私网地址，即 `crosshost.json` 里 `relay_url` 用的那个。
省掉它会重跑 cross-host 模式，是错的拓扑。

`retire.py` 只删 `superseded` 里记过的 id，且要求当前 tee 处于 `running`。
新 TEE 没起来它会拒绝，不会误删。

provider agent 需要重连一次重新注册凭据，换 TEE 会换 inbox key。

### 顺带确认的两件事

**换私网 IP 不需要动 AWS 安全组。** `sg-0d76afda7f81e798c` 的 18090 入站规则是按
**SG 自身引用**放行的（`UserIdGroupPairs[0].GroupId` 就是这个 SG 本身），
Hub 主机同属该 SG，所以 IP 从 .199 变 .189 在网络层完全透明。
但 `HIVE_RELAY_ALLOWED_CIDRS` 是 Hub 应用层白名单，必须跟着改。

**别用 curl 退出码判断 TEE 连通。** RA-TLS 的叶证书由 NitroTPM 签，链在 attestation 证据里
而不在握手证书链里，所以 `curl --cacert hub-ca.pem` 必然报
`(60) SSL certificate problem: self-signed certificate`。Hub 是靠 `attest.Verifier` 验的。
连通性判据要看 `* Connected to <ip> port 18090` 且握手续到 `Request CERT`。

判断「文件改了但没生效」只有一个可靠手段：

```bash
sudo tr '\0' '\n' < /proc/<hub-pid>/environ | grep HIVE_TEE_
```

## 7. 还能查的

- `nextRefreshDelay`（`ratls_refresh.go:288` 附近）的网格计算目前只用 `minRefreshFloor`
  与窗口做保守夹取，没有把「guest 钟可能不准」当输入。如果将来出现别的走时误差源，
  这里可以加一道「按估计偏差提前」的调整。
- 校时日志目前只在失败时告警。加个成功后的偏差值 debug 日志会让下次诊断快一点，
  代价是每 15 分钟一行。这次没加是觉得收益不抵噪音。
- `AttestationHealth` 的连续失败计数清零机制，让「每轮失败一次」的形态静默了。
  给 `RecordSuccess` 记一个累计失败数并按周期上报，能把这类问题从「靠翻日志」变成「看指标」。
