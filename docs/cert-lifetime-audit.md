# TEE / Hub 证书有效期审计与长寿命部署方案

> **状态**：§1–§6 写于最初那轮审计，当时未改动任何机器，是**提案**；§7 起是**实施记录**，每节开头写明对应提交或
> 分支。前面被后续工作推翻的结论都已就地标注（`>` 引用块），**读结论以最后一节为准**。凡是带行号的引用，写该节时
> 是准的，之后随代码增删会漂移——定位请以函数名为准。
>
> **对象**：Hub `52.215.235.214`（`i-018b872fa8ecdefc8`, priv `10.0.1.151`）——一台**独立主机**，上面跑的是另一个
> 仓库 `tokhive-mvp` 的 `bin/hive`（本文凡说"Hive"都是它）；TEE 是 `tokenhive/cloudtest` 起的 SEV-SNP 实例，
> **每次重建 AMI 都会换**，当前值以 `tokenhive/cloudtest/crosshost.json` 为准（本文 §3、§6 里抓到的
> `10.0.1.63` / `i-0393503927c542557` 是当时的实例，早已终止，仅作证据保留）。region `eu-west-1`。

---

## 1. 结论（TL;DR）

1. 那条警告**不是无害的**。它的含义是：Hive 无法再通过 RA-TLS 验签 TEE，因此**拿不到 TEE 的 inbox 公钥**，provider 无法把凭据封装给 TEE —— 走真实 TEE 的 supply 链路是断的。进程不崩（只是 `Warn` + 反复重试），所以表现为"静默降级"。
2. 根因是 **AWS 签发的 NitroTPM 叶证书只有 3 小时有效期**，而 TEE 的 RA-TLS 证书在**进程启动时只签发一次、之后永不刷新**，把这份 3 小时的证据一直挂在证书里。于是**每次 TEE 启动约 3 小时后，任何做日期校验的验证方都会拒绝它**。
3. 因此"把证书有效期调长"这个思路**对这条链无效**：3h / 24h / 6d / 20d 这几张都是 AWS 签发的，你改不了。唯一有效的杠杆是让 TEE **在最短的那张证书过期前重新出证（re-attest 并重签 RA-TLS）**。这个机制代码里**已经写好但没接线**——**接线已于 §7 完成**（当时遗留的准入 margin 问题见 §10）。
4. 好消息：其余你自己可控的证书（mTLS CA/叶、Secure Boot 密钥、GCP vTPM CA、内嵌 Nitro 根）都已经是"十年级"，不需要动。

**至此之后的进展（本节四条的后续，逐节展开）**：

| 节 | 内容 |
|---|---|
| §7–§9 | 接上刷新循环；Hub 侧从 `pin` 切到 `-tee-verify attestation`；证书有效期与三件套一致性 |
| §10 | 修掉每 2h50m 一次的准入黑窗：把「准入」与「签名」的截止时刻拆成两个（`SNPAdmissionDeadline` / `SNPSigningDeadline`） |
| §11 | 逐条核对轮换对买家/卖家的影响面 |
| §12 | 交易所的硬边界（在签名截止前切断）+ 同 listener 上另外两条路径的同类缺陷 |
| §13 | 会话终端收据：在还有余量可签时主动切断隧道 |
| §14 | 恶意买家能否借轮换白嫖 token；AWS 故障时的止损现状 |
| §15 | 换 TEE 的标准流程（含两个会静默产出错误状态的坑）；§16 把它改成"先建 → 再切 → 最后删" |
| §17 | 决策记录：「只在结尾证明」能达成什么、不能达成什么 |
| §18 | 决策记录：Hub 自己计费能否取代 TEE 的受理证明（分界线是收据的 `Completion`） |
| §19 | **实施记录：方案 B** —— 轮换瞄准重签窗口 + 签名处换手，消掉 §11 的四个掐断点 |

---

## 2. 警告的完整链路（代码级）

```
Hive 启动
 └─ cmd/hive/main.go:82   inboxSource → source(startup)   // GET https://10.0.1.63:18090/v1/credential-key
     └─ teeclient/deployment.go:82  VerifyPeerCertificate = shared.VerifyRATLSPeer(...)
         └─ shared/ratls_verifier.go:136  fmt.Errorf("ratls: %w", err)
             └─ shared/secure_boot.go:213  fmt.Errorf("SEV2 prerequisite: %w", err)
                 └─ shared/snp_combined_aws.go:217  verifyNitroTPMDocument(env.NitroTPM)
                     └─ shared/snp_combined_aws.go:338  verifyNitroChain(leaf, cabundle)
                         └─ :380  leaf.Verify(x509.VerifyOptions{Roots: [内嵌 Nitro 根]})
                             ⇒ x509: certificate has expired or is not yet valid
```

- 失败在 `main.go:82`，是 `slog.Warn(...)`，**不是** `return err` → Hive 继续跑（实测 PID 77036 存活）。
- 但 `main.go:101` 的 `ConfigureDynamicSupply` → `supplyChannel()`（`internal/service/supply.go`）**只做配置校验、不连 TEE**，所以进程"看起来正常"，实际 TEE 通道是坏的。
- `InboxSource()` 每次调用都会重新握手重试 → **每次都会失败**（"Hive will keep asking" 但永远拿不到）。

**两侧验证的差异（重要）**：

| 验证方 | 代码 | 会不会查 NitroTPM 链日期 | 会不会查 RA-TLS 叶日期 | 实际失效点 |
|---|---|---|---|---|
| Hive（市场 Hub） | `VerifyRATLSPeer` | 会（`leaf.Verify`） | 不会 | **3h** |
| tokenhive hub (`-mtls-ca`，默认 pin 模式) | `ClientMTLSConfig` (`internal/mtls/mtls.go`) | 不会 | 会 | **24h** |
| tokenhive hub (`-tee-verify=attestation`，见 §7) | `VerifyRATLSPeer` | 会（`leaf.Verify`） | 不会 | **3h** |

所以 3h～24h 之间是"只有 Hive 坏、tokenhive 侧还好"；超过 24h 两边都坏。
切到 `-tee-verify=attestation` 后，tokenhive 侧与 Hive 同构（都受 3h NitroTPM 链约束），
于是 §5 方案 A 的刷新对**两个**验证方同时生效，24h 台阶消失。

---

## 3. 全证书清单（含实测有效期）

### 3.1 TEE 的 RA-TLS 证书链（实测自 `openssl s_client 10.0.1.63:18090` 抓到的活体证书）

| 证书 | 签发者 | notBefore | notAfter | 有效期 |
|---|---|---|---|---|
| RA-TLS 叶 `CN=tokenhive-tee` | 自签 | 09-17 09:23 | 09-18 10:23 | 24h（当时实测；**自签叶代码已改为 5y，见 §8**） |
| **NitroTPM 叶** `i-0393…-tpm….aws` | AWS NSM | 09-17 10:23:15 | **09-17 13:23:18** | **3h00m03s ← 已过期，就是它** |
| Nitro 实例中间 CA | AWS | 09-17 10:22 | 09-18 10:22 | 24h |
| Nitro zonal 中间 CA | AWS | 09-17 04:28 | 09-22 23:28 | ~6d |
| Nitro regional 中间 CA | AWS | 09-16 00:52 | 10-06 01:52 | 20d |
| Nitro 根（内嵌 pin） | AWS | 2019-10-28 | 2049-10-28 | ~30y |

### 3.2 仓库内你自控的证书

| 文件 | 主体 | 有效期 | 评价 |
|---|---|---|---|
| `tokenhive/cloudtest/snp/.certs/hub-ca.pem` | `CN=tokenhive-mtls-ca` | 09-17 → **2036-09** | 10y ✅ |
| `.certs/hub-cert.pem` | `CN=tokenhive-sim-hub` | 09-17 → **2031-09** | 5y ✅ |
| `.certs/mp-ca.pem` | `CN=tokenhive-sim-provider-ca` | 09-17 → **2036-09** | 10y ✅ |
| `.certs/mp-cert.pem` | `CN=tokenhive-sim-provider` | 09-17 → **2031-09** | 5y ✅ |
| `.certs/hub-ca.key` / `mp-ca.key` | CA 私钥 | — | ✅ 保留用于免重建重签 |
| `.certs/tee-cert.pem` | `CN=tokenhive-tee` | 09-16 → **09-17（已过期）** | ⚠️ 陈旧副本（旧 TEE 的），仅本地留存 |
| `deploy/secure-boot/PK.crt`, `KEK.crt` | Reclaim Secure Boot | 2026-08 → **2036-08** | 10y ✅ |
| `deploy/secure-boot/R.crt` | Reclaim Cross-Cloud Release Key | 2026-09 → **2046-09** | 20y ✅ |
| `shared/aws_nitro_root.pem` | `CN=aws.nitro-enclaves` | 2019 → **2049** | 30y ✅ |
| `shared/gcp_vtpm_ca_{root,intermediate}.crt` | Google EK/AK CA | 2022 → **2122** | 100y ✅ |

### 3.3 Hub 机 `/etc/tokhive/`

| 文件 | 主体 | 有效期 | 说明 |
|---|---|---|---|
| `hive-client.pem` | `CN=tokenhive-sim-hub`（由 tokenhive-mtls-ca 签） | 09-17 → **2031-09** | ✅ 与 `.certs/hub-cert.pem` 同源 |
| `hive-client-key.pem` | — | — | ✅ |
| `hub-ca.pem` | `CN=tokenhive-mtls-ca`（自签根） | 09-17 → **2036-09** | ✅ |
| （无 `mtls/tee-cert.pem`） | — | — | 同事遇到的"找不到 pem"即此：该路径是 `crosshost.sh` 在 `cd ~` 下的相对路径 |

> 注：`ssh-key.pem`、`*.pub.pem`、`*-key.pem` 不是证书，无有效期。

---

## 4. 根因：3 小时悬崖

> 本节描述的是 **§7 接线之前**的形态（当时 tokenhive 侧没有刷新调用者）。§7 已接上刷新循环；
> 接上之后的剩余缺陷（准入 margin 比 AWS 的重签提前量长）见 §10。

两部分叠加：

1. **AWS 侧不可控**：NitroTPM 出证时，AWS NSM 签发的叶证书 **TTL 仅 3 小时**（本次实测 3h00m03s；中间 CA 也都是 24h/6d/20d 级别）。
2. **TEE 侧可修**：`shared.NewRATLSManager` 在**进程启动时**签一张 24h 的自签 RA-TLS 叶，并把**那一刻**的出证证据（含那张 3h 的 NitroTPM 叶）塞进证书扩展 `.2`。之后：
   - `tokenhive/platform/sevsnp/adapter.go` 的 `GetCertificate` 返回**启动时钉住的**快照；
   - `Adapter.Refresh()` / `sharedManager.Refresh()` **存在但没有任何生产调用者**（`tokenhive/` 内除了测试，无人调用）。

   → **TEE 启动 3 小时后，证书里的 NitroTPM 叶过期，Hive 验签开始失败，直到 TEE 重启。**

**已经写好的正确机制（reclaim-tee 侧在用，tokenhive 侧当时没用）**：

- `shared/router_runtime.go` 的 `SNPAdmissionDeadline()` / `SNPSigningDeadline()`：两者都取自 NitroTPM 叶的
  `NotAfter` —— 前者就是 `NotAfter` 本身（验证方停收的时刻），后者是 `NotAfter − SNPSigningMargin`（5 分钟）。
  <br>（2026-09-22 变更，见 §10。当时这里是单个 `SNPAttestationExpiry() = NotAfter − SNPRefreshMargin(30min)`，
  那个 30 分钟正是 §10 那条黑窗的成因。）
- `shared/router_runtime.go` 刷新循环：按 `clamp(Until(签名截止), 下限 minRefreshFloor, 上限 RATLSRefreshIntervalSNP=2h)` 定时 `ratls.Refresh(ctx)`。

即：设计意图本来就是"跟着 AWS 的 3h 走、提前换证"，只是 tokenhive 的 TEE 没接这条线。

---

## 4.5 24 小时台阶：实例中间 CA 与 RA-TLS 叶各自的影响

### A. RA-TLS 叶（`CN=tokenhive-tee`，TEE 自签，boot+24h）
按"是否做标准链校验（含日期）"分类：

| 客户端 | 代码 | 查对端叶日期？ | 24h 之后 |
|---|---|---|---|
| tokenhive hub → TEE(18090) | `internal/mtls/mtls.go:88` `ClientMTLSConfig` → `leaf.Verify(Roots=pin)` | **查** | **新建握手失败**：`tee certificate is not pinned: x509: certificate has expired` |
| Hive → TEE(18090) | `VerifyRATLSPeer` | 不查 | 不受影响（它 3h 就坏了） |
| TEE 自己 | Go TLS server + `GetCertificate` | 不查自己 | 无感，照旧发出过期叶 |
| 已建立的 TLS 连接 | — | 只在握手时校验 | **不中断**，可跨过 24h |
| 其它标准客户端（`curl --cacert` 不带 `-k` 等） | 标准校验 | 查 | 被拒 |

当前部署里唯一的此类客户端 = `tokenhive/cloudtest/snp/crosshost.sh:383-384` 给 `./tee/hub` 的
`-mtls-ca mtls/tee-cert.pem`（hub 作为 client 调 TEE 的 `/v1/execute`、`/v1/receipts` 等）。

**⚠️ 连带风险（比 24h 更容易踩到）**：这个 pin 是 `buildTEEClientTLS()` → `LoadCAPath()`
（`tokenhive/cmd/hub/main.go:411-427`）**启动时读一次**的静态锚。
→ TEE 一旦**重启或轮换 RA-TLS 密钥**，pin 立即失效（`not pinned`），**早于** 24h。
→ 反之：**TEE 换叶后，hub 必须重抓 `tee-cert.pem` 并重启**。这一点与 §5 方案 A 直接冲突（见该处 caveat）。

> **后续（2026-09-17，见 §9.2）**：三个真实部署调用点已从 `-mtls-ca` pin 切到 `-tee-verify attestation`，
> hub 不再钉具体证书，换叶/换密钥自动接受；pin 模式只保留给 simulated / harness。上述"连带风险"因此
> 只对"仍在用 pin 的部署"成立。

### B. Nitro 实例中间 CA（AWS 签发，`CN=i-0393…eu-west-1.aws.nitro-enclaves`，boot+24h）
- 它在 NitroTPM doc 的 `cabundle` 里，而 `verifyNitroChain` 的 `leaf.Verify` 校验**整条链**的日期。
- ⇒ **"只把 NitroTPM 叶换新"是无用的**：24h 时链依旧断。**必须在 24h 前重新出证整份 document**。
- 更长远：zonal CA ~6d、regional CA 20d 也会到期 ⇒ 不刷新的 TEE 会依次在
  **3h → 24h → ~6d → 20d** 四个台阶上继续失效（即使只修了叶）。

### C. 汇总：自 TEE 启动起算

| 时刻 | 到期证书 | 开始失败的一方 |
|---|---|---|
| 3h | NitroTPM 叶 | Hive（attestation 链日期） |
| 24h | Nitro 实例中间 CA | 所有做链校验的验证方（Hive 早已失败） |
| 24h | RA-TLS 叶 | tokenhive hub 的 `-mtls-ca` pin、标准校验客户端 |
| ~6d | Nitro zonal CA | 链校验（须重新出证） |
| 20d | Nitro regional CA | 链校验（须重新出证） |
| 2031 / 2036 | hub-cert / mTLS CA | 常规轮换，不紧张 |

**净结论**：3h 是最严约束，已自动覆盖 24h。24h 的意义在于——
**无论是"只换叶"还是"每天重启一次"，都不够**；必须**重新出证整份 document**（方案 A），
且必须同步处理 hub 的 pin（见下）。

---

## 5. 部署与操作方案

### 方案 A（推荐，唯一的根治）：给 tokenhive 的 TEE 接上 RA-TLS 刷新
- 在 `tokenhive/cmd/tee` 里，参照 `shared/router_runtime.go` 的循环调用 `adapter.Refresh(ctx)`：
  - 间隔 = `min(RATLSRefreshIntervalSNP(2h), SNPNitroLeafNotAfter(证书)−SNPRefreshMargin(30min))`。
    <br>（2026-09-22 起：瞄准 `SNPSigningDeadline = NotAfter − 5min`，下限 2min —— 见 §7.2 与 §10。）
  - 由于 NitroTPM 叶是 3h，实际节奏 ≈ **每 2h 或 ~2.5h 一次**，远早于 3h 悬崖。
- 一次改动同时解决两件事：
  - Hive 侧（3h，NitroTPM 链日期）—— 每次刷新都换一张新的 3h 叶；
  - tokenhive `-mtls-ca` 侧（24h，RA-TLS 叶日期）—— 刷新会重签叶证书。
- `Adapter.Refresh` 注释已声明"旋转 RA-TLS 密钥与证据、新握手使用新 epoch"，语义现成。
- **⚠️ 必须同时处理 hub 的 pin，否则会"修好 Hive、弄坏 hub"**：
  `Adapter.Refresh` 会轮换 RA-TLS **密钥**（`adapter.go:149`），而 hub 的 pin
  （`mtls/tee-cert.pem`）是**启动时读一次**的静态锚（`cmd/hub/main.go:411-427` → `LoadCAPath`）。
  TEE 一换叶，hub 就会以 `not pinned` 拒绝 TEE。三选一：
  - (i) hub 定期重抓 `tee-cert.pem` 并热重载 / 重启；
  - (ii) hub 改用 attestation 验证（`VerifyRATLSPeer` 同款：验证据 + SPKI 绑定 + `-expected-app`）**替代**钉具体证书——本来就能容忍换叶；
  - (iii) 让 TEE 的 RA-TLS 叶由**固定长期 CA** 签发，hub 钉该 CA（需改 `NewRATLSManager`，当前是自签叶）。

### 方案 B（测试期权宜）：定时重启 TEE
- 每 **< 3h** 重启一次 TEE（或触发一次重新出证）。零代码，但会打断进行中的会话与 inbox key。

### 方案 C（不建议）：放宽验证方
- 让 `verifyNitroChain` 不校验那张短命 AWS 叶的日期（只验 COSE 签名 + 链到内嵌根 + user_data/PCR/module_id 绑定）。
- 能绕过，但**削弱了新鲜度语义**（3h 窗口本身就是 AWS 表达的"这份出证有多新"）。除非明确只为临时联调，否则不建议动。

### 方案 D（保持非 AWS 证书长寿命，基本已完成）
- mTLS CA 10y / 叶 5y（已做）；如需进一步减少轮换，可把叶提到 10y。
- Secure Boot PK/KEK 10y、R 20y，GCP vTPM CA 100y、内嵌 Nitro 根 30y —— 都无需改。
- **纪律**：不要再把 24h 的一次性 fixture 烧进 AMI（上次 `.certs` 就是这么污染 bundle 的）；保留 `hub-ca.key` / `mp-ca.key`，以后换叶只需重签、不必重建 AMI。
- **代码已对齐（见 §8）**：`gencerts` / `EnsureMTLSCerts` 生成的那几张原本仍是 24h，现已改为 CA 10y / 叶 5y，与磁盘上的 `.certs` 一致；自签 RA-TLS 叶 24h → 5y。

---

## 5.5 方案 A 会让 provider 的 accessToken 被反复重新加密吗？——**不会**

因为这里有两把**互相独立**的密钥：

| 密钥 | 生成 / 轮换时机 | 代码 | 方案 A 轮换它吗 |
|---|---|---|---|
| RA-TLS 密钥 + 证据 | TEE 启动时；`Adapter.Refresh` 可轮换 | `platform/sevsnp/adapter.go:151` | **是** |
| 凭据 inbox 密钥（X25519） | **TEE 进程启动时一次**，私钥不落盘 | `cmd/tee/main.go:176` `tee.GenerateInboxKey()` | **否**（refresh 完全不碰） |

`Adapter.Refresh` 只重建 RA-TLS epoch（`Refresh` → `a.manager.Refresh` → `buildEpoch`）；
inbox 密钥是 `main.go:176` 单独生成、直接传给 `tee.NewService`（`:216`）的，与 refresh 路径无交集。

### 另外，"Hub 重新加密"这个动作在当前架构里本来就不存在
- **加密方是 provider agent 自己**：`provider/agent.go:363` `tee.EncryptCredential(pub, reg.Provider, a.cfg.Credential)`；
  公钥由 agent 经 Hub 中转取得（`agent.go:454` → `GET /v1/credential-key`）。
- **Hub 只中转公钥、只存密文**：`hub/hub.go:335-344`（"The Hub is only a relay"）、`hub/agentnet.go:117`（"The Hub only ever holds this ciphertext"）。
- **每个 job 只是把已存密文原样挂上**：`hub/hub.go:363-370` `attachCredential()` → `credentialStore.Get(provider)`，**不重新加密**。
- 唯一例外：`hub.go:346-361` `RegisterCredential` 是"无 agent 的一次性 Hub 直连 TEE"路径，Hub 代客封装一次——同样只加密一次。

### 什么时候才需要重新密封？**TEE 重启**（不是刷新）
- `cmd/tee/main.go:170-179`：inbox 私钥不持久化，"**a restart rotates the key** and agents re-register with the fresh public half"。
- `hub/tee.go:186-194`：Hub **故意不按 TTL 缓存** inbox key —— "the key rotates on every TEE restart"，缓存窗口内会把死钥匙发给重连 agent → "whose sealed envelopes the new TEE can no longer open"。

**这恰好是方案 A 优于方案 B 的核心理由**：
- **方案 A**（只轮换 RA-TLS、进程不重启）→ inbox 密钥不变 → **已封好的 envelope 持续有效，零重新加密**。
- **方案 B**（每 <3h 重启 TEE）→ inbox 每次都换 → **每次重启后所有 provider 都要用新公钥重新上报/密封一遍**。方案 B 的隐藏代价 = 周期性全量重密封。

### ⚠️ 方案 A 的两个实现注意点（不是加密问题，但实现时不能漏）
1. **刷新本身不产生不可用窗口**：`GetCertificate` 只在**当前 epoch 自己的证据**越过截止时刻时返回 `platform.ErrNotReady`（`adapter.go`），而轮换是一次原子替换 —— 旧 epoch 一直在服务，直到新的（把截止时刻推得更远的）epoch 顶上来。刷新耗时（NitroTPM + SEV 两次设备往返）落在旧证据仍然有效的区间内，所以没有"刷新期间新连接被拒"这回事。
   <br>（2026-09-22 更正：这里原文写的是"`Refresh` 全程 `healthy=false` → 每次刷新都有一个新连接不可用的小窗口"。那描述的是更早那版实现 —— 用一个可变的 `healthy` 标志表示"正在刷新"，现已改为从 epoch 自身派生准入判据。真正会产生不可用窗口的是**轮换连续失败、当前 epoch 越过自己的截止时刻**，其大小由 §10 的两个截止时刻决定。）
2. **receipt signer 必须跟随轮换**：`cmd/tee/main.go:208` `signer := proof.NewSigner(epoch)` 用的是**启动时捕获**的 epoch 快照；而 receipt 的 `KeyID` 就是该 epoch 签名密钥的 SPKI 哈希（`proof/receipt.go:305`；`internal/mtls/mtls.go:111-115` 注明 RA-TLS 叶的 "SPKI is the receipt KeyID"）。→ 只加一个 Refresh ticker 而不换 signer，会出现"RA-TLS 已轮换、receipt 仍用旧 epoch 签"，校验方按连接 attested key 核对时会失败。实现时必须把 signer/service 做成跟随 `adapter.Snapshot()`。

---

## 6. 不改机器的即时缓解（本次可用）

- 只想让 Hive 立刻能用：**重启 TEE**（重新出证，拿到新的 3h 窗口）。
- 只想验证"到底是什么过期"：`openssl s_client -connect 10.0.1.63:18090 -showcerts` 抓证书，再看 `.2` 扩展里 NitroTPM 叶的 `notAfter`。本次即用此法确认。
- 关注点提示：Hub 上 Hive 现在是**手工 tmux 跑**（无 systemd unit），重启/升级都要手工——排障时别误判成"服务已停止"。

---

## 附：复现本次审计的命令

```bash
# 1) 活体抓 TEE 证书并解析 .2 扩展里的 NitroTPM 链
ssh -i ssh-key.pem ubuntu@52.215.235.214 \
  'openssl s_client -connect 10.0.1.63:18090 -cert /etc/tokhive/hive-client.pem \
   -key /etc/tokhive/hive-client-key.pem -showcerts </dev/null 2>/dev/null' > /tmp/teecert_raw.txt
# 再用 cbor2 解 .2 扩展 → nitrotpm → COSE_Sign1 → payload.certificate / cabundle

# 2) 全仓证书有效期一览
for f in $(find . -name '*.pem' -o -name '*.crt' | grep -v '\.git/'); do
  openssl x509 -in "$f" -noout -subject -dates 2>/dev/null && echo "  ^ $f"
done
```

---

## 附录 B：选项 (ii)"改用 attestation 验证"具体是什么意思

### B.1 现状：hub 是"钉某一张证书"
- `cmd/hub/main.go:110` `-mtls-ca mtls/tee-cert.pem`
- → `main.go:411-427` `buildTEEClientTLS()` → `internal/mtls/mtls.go:66-108` `ClientMTLSConfig()`
- 里面做的是：`InsecureSkipVerify: true`（不查主机名）+ `VerifyPeerCertificate` → `leaf.Verify(Roots = {tee-cert.pem 那一张}, KeyUsages=[ServerAuth])`。
- 语义 = **"对端必须出示这一张证书"**。因为 SNP 的 RA-TLS 叶是自签的（`subject=issuer=CN=tokenhive-tee`），pin 的"CA"其实就是那张叶自己。
- 所以：证书**过期**即失效（24h）；TEE **换密钥/换叶**即失效（更早）；每次出证后都得人工重抓 `tee-cert.pem` 并重启 hub。
- 注意：这条路径**完全不看证书里的证据** —— 它信任的是"部署时运维手工 pin 过这张证书"（TOFU）。

### B.2 (ii)：不钉证书，改验"证书里带的证据"
把 `VerifyPeerCertificate` 换成 `shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{...})`（`shared/ratls_verifier.go:162-179`，返回的正是 `tls.Config.VerifyPeerCertificate` 回调）。它做三件事：

1. **解析对端这一握手出示的证书**（`ratls_verifier.go:43-70`）：
   - `spkiDER = MarshalPKIXPublicKey(leaf.PublicKey)`
   - 从扩展 `.2`（+ `.3` Secure Boot 标记）取证据：`snpAttestationFromCert(leaf)`
   - → `validateSEVSNP(snp, spkiDER)`
2. **验证证据是真硬件签的、且镜像正是期望的那个**（`verifyCombinedSecureBoot` → `verifyCombined` → `verifyCombinedAWS`）：
   - NitroTPM COSE_Sign1 签名 → 链到内嵌 `aws.nitro-enclaves` 根（`shared/aws_nitro_root.pem`，2019→2049）
   - SEV-SNP report（AMD 链 + VCEK/ASK/ARK + TCB/策略）
   - **SPKI 绑定**：证据的 `report_data` / NitroTPM `user_data` 提交的是**这张证书 SPKI 的哈希**（`snp_combined_aws.go:70-82 awsCombinedV2ReportData(bound=spkiDER,…)`）。⇒ 一张合法证据**不能被挪用到另一把 TLS 密钥上**（防拼接/重放）。这就是"验证据 + SPKI 绑定"的含义。
   - 返回 `app = snp-app:<sha256(bundle)>`、`base = snp-base:<PCR11>`
3. **比对 pin**：`gotDigest == opts.ExpectedImageDigest`（即 `-expected-app`），可选 `ExpectedBaseDigest` 钉 PCR 11（`ratls_verifier.go:168-176`）。

Hive 早就是这么干的：`hive/internal/teeclient/deployment.go:82` `shared.VerifyRATLSPeer(RATLSVerifyOptions{ExpectedImageDigest: d.ExpectedApp, ExpectedBaseDigest: d.ExpectedBase})`，配 `InsecureSkipVerify: true` + 仍然出示自己的 client 证书。

### B.3 落到 hub 要改什么（只此一处）
只有 `buildTEEClientTLS()`（`cmd/hub/main.go:411-427`）需要把 CA pin 换成 attestation 校验：

```go
cfg := &tls.Config{
    InsecureSkipVerify: true,
    MinVersion:         tls.VersionTLS12,
    VerifyPeerCertificate: shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
        ExpectedImageDigest: expectedApp,  // 复用 hub 已有的 -expected-app
        ExpectedBaseDigest:  expectedBase, // 可选，新增 flag
    }),
    Certificates: []tls.Certificate{clientCert}, // hub 仍须出示自己的证书
}
```

- **复用现成旗标**：hub 已经有 `-expected-app`（`cmd/hub/main.go:103`，`snp-app:<sha256 hex>`），今天只用在 receipt 校验（`buildVerifier` → `attest.Verifier{ExpectedApp}`，`main.go:460`）；部署脚本 `crosshost.sh` 也已把它传给 hub。通道校验直接复用，不引入新概念。
- **不影响另一方向**：`ServerMTLSConfig`（`ClientAuth=RequireAndVerifyClientCert` + `ClientCAs`）**只用在 TEE 侧**（`cmd/tee/main.go:256`、`cmd/faketee/main.go:235`），即"TEE 验 hub"那半边（hub-cert 到 2031/2036，本就不紧张）。所以 (ii) **只改 hub 验 TEE 这半边**，mTLS 仍是双向的。
- 建议加一个开关（如 `-tee-verify=pin|attestation`）以保留回退路径。

> **已实现（2026-09-17）**：`-tee-verify=pin|attestation`（默认 `pin`）已落地，`-expected-base` 未加（与 receipt 校验器一致地只钉 app）。见 §7。

### B.4 收益 / 前提
| | 钉证书（现状） | attestation（ii） |
|---|---|---|
| TEE 换叶 / 轮换密钥 | **拒绝**（须重抓 + 重启 hub） | **自动接受**（镜像哈希不变即可） |
| 信任来源 | 部署时手工 pin（TOFU） | 每次握手重新验证硬件证据 + 镜像身份 |
| 仍受 AWS 3h/24h 约束吗 | 是（叶 24h） | **是**（`verifyNitroChain` 仍 `leaf.Verify`） |

---

## 7. 实施记录：方案 A + 选项 (ii)（branch `fix/tee-ratls-refresh-attestation-verify`）

已实现，**只改本地代码，未动 AWS 上的 TEE 与 hub**（未重新部署、未改 `crosshost.json` 状态）。

### 7.1 改了什么

| 文件 | 改动 |
|---|---|
| `tokenhive/cmd/tee/ratls_refresh.go`（新） | epoch 刷新循环：`epochRefresher` 接口、`epochAssembly`、`serviceRuntime`（可热替换的 `*tee.Service`）、`nextRefreshDelay`、`runEpochRefresh` |
| `tokenhive/cmd/tee/main.go` | `buildEpoch` 改为返回 assembly；handler 经 `svcRuntime.get()` 取当前 service；`-mtls` 之外新增：sevsnp 平台启动刷新 goroutine |
| `tokenhive/cmd/tee/epoch_sevsnp.go` | 把 `*sevsnp.Adapter` 作为 `Refresher` 一并返回（simulated 返回 nil） |
| `tokenhive/cmd/tee/epoch_default.go` | 同上，`Refresher` 恒为 nil（软件证据不过期） |
| `shared/router_runtime.go` | `RunRATLSRefresh` 的第一个参数由 `*RATLSManager` 放宽为 `RATLSRefresher` 接口（`Refresh(context.Context) error`），使 tokenhive 的 adapter 能复用同一条循环/节奏/失败策略；tee_k/tee_t 的调用点不变 |
| `tokenhive/cmd/hub/main.go` | 新增 `-tee-verify=pin\|attestation`（默认 `pin`）；attestation 分支用 `shared.VerifyRATLSPeer`（证据 + SPKI 绑定 + `-expected-app`），仍出示 hub client 证书；`validateApplicationPin` 抽成唯一一处 pin 形状校验（receipt 校验器与握手共用） |
| `tokenhive/cmd/tee/ratls_refresh_test.go`（新） | 节奏 + 轮换落地的测试 |
| `tokenhive/cmd/hub/main_test.go` | `-tee-verify` 两种模式的测试 |

### 7.2 节奏（`nextRefreshDelay`）

```text
delay = clamp( Until(SNPSigningDeadline(当前证据)), 上限 RATLSRefreshIntervalSNP=2h, 下限 minRefreshFloor )
SNPSigningDeadline = NitroTPM 叶 NotAfter − SNPSigningMargin(5min)
```

> 2026-09-22 变更（见 §10）：原式为 `Until(SNPAttestationExpiry)`，即 `NotAfter − SNPRefreshMargin(30min)`，
> 下限 `10min`；现在瞄准的是**签名**截止时刻，下限收到 `2min`。

- 3h 叶 → 首次 2h 后轮换（此时叶还剩 1h，AWS 尚未重签 ⇒ 同叶空转，不换 epoch），此后 55min 后再来一次，
  正好落在 AWS 的重签点之后 → **永不接近 3h 悬崖**。
- AWS 若缩短叶 TTL，节奏自动跟随（上限不再独裁）——这条正是"别再靠猜"的部分。
- `Snapshot()` 失败（adapter 已无可用 epoch）→ 退回 `minRefreshFloor` 重试，而不是等满 2h 上限。

### 7.3 三个不能漏的实现点（§5.5 列出的两个 + 一个新增）

1. **signer 跟随轮换**：`serviceRuntime.adopt` 用 `proof.NewSigner(新 epoch)` 重建 service 并原子替换；handler 每次请求经 `get()` 取当前实例，所以轮换不需要重启、也不需要断连。旧实例仍被在途请求持有（因此旧 epoch 的 receipt 依然自洽可验）。
2. **证据必须先落盘再换 signer**：`adopt` 的顺序是 `WriteTEEIdentity` → `RecordTEEEvidence` → 替换 service。生产用 hash-only receipt，`EvidenceHash` 只能靠 evidence store 反查（本地 + 供 Hub 拉取的 `/v1/evidence`）；先换 signer 就会出现"签得出、验不了"的窗口。落盘失败 ⇒ 整个轮换放弃，旧 service 继续签（有测试覆盖）。
3. **inbox 密钥完全不碰**：仍由 `cmd/tee/main.go` 启动时 `GenerateInboxKey()` 生成一次、不落盘，不进 `serviceRuntime.template` 之外的任何轮换路径 → **provider 的密文 envelope 无需重新加密**（§5.5 结论在实现后依然成立）。
4. **`AttestationHealth` 传 nil**：那条自愈路径会重启客户机，tokenhive 的 TEE 进程没有对应的恢复动作，故不加；刷新失败只记录日志（同时表现为 Hub 侧 TLS 对端消失）。这是**已知取舍**，见 7.6。

### 7.4 验证到什么程度

| 验证 | 结果 |
|---|---|
| `go build ./...`、`go build -tags sevsnp ./...` | 通过（`demo_lib` 的 cgo 链接失败是缺 `bin/libreclaim` 的既有环境问题，与本次无关） |
| `go vet ./shared/... ./tokenhive/...` | 干净 |
| `go test ./shared/... ./tokenhive/...` | 全绿 |
| `ratls_refresh_test.go`：合成 AWS-tagged 证据（含自造的 NitroTPM 叶 `NotAfter`）驱动节奏 | 长寿命叶→2h 上限；1h 叶→~30min（证明节奏真的跟随 AWS，而不是固定上限）；已过期叶→10min 下限；`Snapshot` 失败→10min |
| `ratls_refresh_test.go`：一次真实循环迭代（预取消 ctx） | 轮换后 service 实例被替换、`tee_identity.json` 指向新 key、证据进 store；证据不可发布时**拒绝轮换**且旧 service 继续签 |
| `main_test.go`：`-tee-verify` 两模式 | pin 模式无 CA ⇒ 返回 nil（明文通道）；pin 模式仍能对钉住的 CA 做链校验；**attestation 模式对"无 attestation 扩展的合法证书"必须拒绝**（fail-closed，而不是退化成只跳主机名校验）；`-mtls-ca` 与 attestation 同时给 ⇒ 报错；缺/坏 `-expected-app` ⇒ 报错 |
| `tokenhive/harness/harness.sh` | ✅ 0 FAIL（场景 1–18）。第一次运行出现过 4 处 FAIL，**全部**是本机删除护栏导致 `.sim` 清理失效，与本次改动无关；已用四组对照实验确认，见 7.5 |

### 7.5 第一次 harness 运行那 4 处 FAIL 的归因（已实验确认）

本机存在"**单轮**删除超过 50 个非 `/tmp` 路径即静默拒绝"的护栏（`[safe-delete][SAFE_DELETE_BULK_CONFIRM_REQUIRED]`，scope=turn）。`.sim` 里积压了前两天的大量 receipt 时，harness 开头的 `wipe "$SIM"` 会把这一轮的删除额度耗尽：

- `!! FAIL: expected 2 receipts under cheap-sim, got 4`、`!! FAIL: expected 1 receipt, got 4` —— 后续场景的 `wipe` 变成空操作，计数断言量到的是上一场景残留（脚本自己的注释就说："a refused wipe is not a harmless no-op — it turns a real assertion into a measurement of the previous scenario"）。
- `!! FAIL: mTLS request did not complete` + `tee mtls: tls: private key does not match public key` —— 部分删除后 `.sim/hub-client.pem` 是 09-17 的旧证书，而 `hub-ca.pem`/`hub-client-key.pem` 被 `EnsureMTLSCerts` 重新生成（`writePEMIfAbsent` 逐文件判断，于是产生"新 CA + 新私钥 + 旧证书"的错配三元组）；`tls.LoadX509KeyPair` 在 hub 读**自己**的证书时失败，与本次改动的验证模式无关。

四组对照（`FAIL` 计数）：

| 运行位置 | base `507170c` | new `4c4347d` |
|---|---|---|
| 主仓库（删除护栏生效、`.sim` 有积压） | 0（积压已被前次运行部分清掉） | **0** |
| `/tmp` git worktree（删除不受护栏影响，`.sim` 全新） | 0 | **0** |

结论：harness 场景 1–18 在本次改动前后都是 0 FAIL；上面 4 处 FAIL 只出现在"删除额度耗尽"的那一次运行里。

> 顺带发现（与本次无关，**已单独修复，见 §8**）：`EnsureMTLSCerts` 用 `writePEMIfAbsent` 逐文件判断，只要 `hub-ca.pem` / `hub-client.pem` / `hub-client-key.pem` 三件套中有任一缺失，就会只补缺失的那几个，产出互不匹配的一套。应改为"三件套要么全部复用、要么全部重生成"。

### 7.6 未做 / 后续

> **后续已落地（2026-09-17）：四个调用点全部切换完毕，见 §9。** 下面保留当时的判断，作为切换前的记录。

- **未切换任何部署调用点**（按"先不要动 AWS"的指示）。切到 attestation 只需改旗标，四个调用点的处置：

  | 位置 | 现状 | 建议 |
  |---|---|---|
  | `tokenhive/cloudtest/snp/crosshost.sh:383`（跨机 AWS，现行主路径） | `-mtls-ca mtls/tee-cert.pem` | 换成 `-tee-verify attestation`（同行组里已有 `-allowed-platforms aws-sev-snp -expected-app 'snp-app:${app_hash}'`，无需另加；`-mtls-cert/-mtls-key` 保留） |
  | `tokenhive/cmd/single/main.go:219`（单机密实例） | `-mtls-ca, teeCert` | 换成 `"-tee-verify", "attestation"`。但这样 `fetchTEECert()`/`teeCert` 与 tee 的 `-init-addr` 自举就失去消费者，属于一次额外的清理，建议单独一步做 |
  | `tokenhive/cloudtest/remote/run-all.sh:76`（同一脚本跑 simulated 与 sevsnp） | 恒 `-mtls-ca` | 需按 `TEE_PLATFORM` 分支：sevsnp ⇒ `-tee-verify attestation`，simulated ⇒ 保持 pin（sim 证书没有 attestation 扩展，attestation 模式必然拒绝） |
  | `tokenhive/harness/harness.sh:804/814` | `-mtls-ca` | **保持 pin**：faketee 是 simulated |

- 切到 attestation 后，`fetch`（TOFU `/v1/init-cert`）与 `tee-cert.pem` 的分发不再是信任链的一部分，可作为后续简化（也可留作人工核对）。
- `docs/TokenHive 真实 TEE 部署与测试手册（AWS SEV-SNP）.md` §393/§406/§426 把 TOFU→`-mtls-ca` 写成信任建立主路径，切换后需同步改写。
- 刷新失败的重试只有 10min 下限；若 `Refresh` 连续失败（如 `/dev/sev-guest` 卡死导致 `healthy` 永久为 false），进程没有自愈手段（见 7.3-4）。要么在部署层加重启策略，要么后续接 `AttestationHealth`。

⇒ **(ii) 不是方案 A 的替代品，而是它的配套**：A 负责让证据保持新鲜（解决 3h/24h），(ii) 负责让 hub 不再需要重新钉证书（解决换叶即失效）。

---

## 8. 实施记录（三）：证书有效期与三件套一致性（2026-09-17）

> 仍然**只改本地代码**，没有动 AWS 上的 TEE 与 hub（没有重新部署、没有重新生成 `.certs`）。
> 分支 `fix/tee-ratls-refresh-attestation-verify`，已 force-push 到 fork（`2245fee → df0c1a1`，因为把本文撤出提交必然重写该提交）。

### 8.1 先回答"实例中间 CA 和 RA-TLS 叶"里哪些是我们的

| 证书 | 归属 | 能不能改 |
|---|---|---|
| Nitro **实例中间 CA**（24h） | **AWS NSM 签发**，在 NitroTPM document 的 `cabundle` 里 | **改不了。** 它的 `NotAfter` 是 AWS 给的，我们只能"在它到期前重新出证整份 document"（= §5 方案 A，已实现） |
| **RA-TLS 叶**（24h） | **自己签**（`shared/ratls_manager.go` `Refresh()`） | **已改**：24h → **5y** |
| 仿真 mTLS fixtures（24h） | **自己签**（`mtls.GenHubClientCerts` / `GenMockProviderCerts` / `shared.GenCerts`） | **已改**：CA 10y / 叶 5y |

所以"两个 24h"里只有 RA-TLS 叶和 fixtures 是我们的；实例中间 CA 那张属于 §4.5-B 的结论 —— 对它的正确动作是**重新出证**，不是改有效期。

### 8.2 为什么 24h 窗口该去掉

RA-TLS 的**新鲜度**由证据负责（AWS 侧 hours 级）与刷新节奏负责，X.509 窗口从来不是新鲜度机制：

- 做 attestation 校验的一方（`VerifyRATLSPeer`）根本不读它 —— 它读的是证书里的证据。
- 读它的一方（hub 的 cert pin、标准 TLS 客户端、跨多天的 cloudtest fixtures）则**只**受它约束。

于是 24h 的实际效果是：**一个没跑（或跑不起来）刷新的部署，会在启动后正好一天停止认证**，而这个信号与"证据是否新鲜"无关，只会误导排障（§4.5-A 的"连带风险"就是这么来的）。fixtures 同理：一次跨天的实验不该被证书窗口打断。

### 8.3 改了什么（3 个提交）

| commit | 内容 |
|---|---|
| `0994c8f` | （amend 自 `2245fee`）方案 A + 选项 (ii)。本文撤出提交、文件保留在工作区（untracked）；提交信息里对本文的引用改成自述，避免指向一棵不含它的树 |
| `eb8a029` | 证书有效期：`shared/ratls_manager.go` 自签 RA-TLS 叶 24h → 5y；`tokenhive/internal/mtls/mtls.go` 新增 `FixtureCACertLifetime=10y` / `FixtureLeafCertLifetime=5y` 并用于两组 fixtures；`shared.GenCerts()` 复用同一对常量 |
| `df0c1a1` | `EnsureMTLSCerts` 改成"三件套要么全部复用、要么全部重生成"，并删掉已无调用者的 `writePEMIfAbsent` |

CA 比它签的叶活得久，是为了"重签叶不动已 pin 该 CA 的部署"；这也是磁盘上 `.certs`（`hub-ca` 2036 / `hub-cert` 2031）一直在用的划分 —— 这次是把代码对齐到它。

### 8.4 验证

| 验证 | 结果 |
|---|---|
| `go build ./tokenhive/... ./shared/...`（含 `-tags sevsnp`） | 通过 |
| `go vet ./shared/... ./tokenhive/...` | 干净 |
| `go test ./shared/... ./tokenhive/...` | 全绿 |
| `go run ./tokenhive/cloudtest/snp/gencerts <tmp>` + `openssl x509` | `hub-ca`/`mp-ca` → **2036-09**（10y）、`hub-cert`/`mp-cert` → **2031-09**（5y），与磁盘 `.certs` 一致 |
| harness 环境里的 `.sim/hub-ca.pem` / `hub-client.pem` | 2036 / 2031 —— `EnsureMTLSCerts` 路径也确认了 |
| `TestEnsureMTLSCertsWritesTheIdentityAsASet` | 新测试；**在旧实现上会失败**（`the stale certificate was kept beside a freshly generated CA`），新实现通过 —— 已用 `git stash` 实测旧实现确认非空转 |
| `TestFixtureCertsAreLongLivedAndChain` / `TestRATLSLeafWindowIsLongLived` | 新测试：fixtures "多年 + 真的链到旁边的 CA"、RA-TLS 叶窗口 > 1 年 |
| `bash tokenhive/harness/harness.sh`（`/tmp` git worktree @ `df0c1a1`） | **0 FAIL**（场景 1–18） |

### 8.5 你之前要我定的"两件后续"：一件纯部署，一件是代码 bug（已修）

1. **切换四个部署调用点 —— 主要是部署/脚本，不是代码逻辑**
   - `crosshost.sh:383`：只是把 `-mtls-ca mtls/tee-cert.pem` 换成 `-tee-verify attestation`（同行组里已有 `-expected-app`）。
   - `cloudtest/remote/run-all.sh:76`：需要按 `TEE_PLATFORM` 分支——sevsnp 用 attestation，simulated 保持 pin（sim 证书没有 attestation 扩展，attestation 模式必然拒绝）。
   - `harness.sh:804/814`：**保持 pin**（faketee 是 simulated），不动。
   - `cmd/single/main.go:219`：改旗标后 `fetchTEECert()` / tee 的 `-init-addr` 自举失去消费者，是**可选清理**，建议单独一步。
   - ⇒ 结论：**没有"必须改代码"的部分**；这一步是 rollout 时的配置动作。
2. **`EnsureMTLSCerts` 三件套错配 —— 是代码 bug，值得修**（症状是延迟且远离根因的 `tls: private key does not match public key`），已在 `df0c1a1` 修掉并配了会失败的回归测试。

### 8.6 仍未做

- **没有重新部署**：AWS 上那台 TEE 仍在服务部署时签出的 24h 叶（换叶要靠重新部署 + §8.3 的刷新循环）。所以 §3.1/§3.2 的**实测值依然是那台机器的现状**，§8 说的是"代码从此以后会签什么"。
- **没有重新生成 `.certs/`**（本就是 10y/5y），`ensure_certs()` 的"见到 `hub-ca.pem` 就复用"也没变 —— 现有 AMI 不受影响。这次改的是"将来万一需要重生成"时的行为。

---

## 9. 实施记录（四）：把 §7 之外新发现的问题全部修掉（2026-09-17）

> 仍然**只改本地代码与脚本**：没有在 AWS 上重新部署、没有动正在运行的 TEE / hub，也没有重新构建镜像。
> 分支 `fix/tee-ratls-refresh-attestation-verify`，四个提交（`604911f` → `a2433e2` → `7559e53` → `d5aa723`）。

这一轮先做了一次复查（"有没有逻辑漏洞 / 能不能再简化 / 部署后证书有效期够不够"），把发现的东西记在 §9.1，然后按"全都修"逐条落地。

### 9.1 处置清单

| # | 严重度 | 问题 | 处置 |
|---|---|---|---|
| ① | **部署阻塞** | hub 默认 `-tee-verify=pin` 与 TEE 的**无条件轮换**互斥：pin 模式在启动时读一次 `mtls/tee-cert.pem`，而 sevsnp 的实例每个 epoch（≤2h）重签一次叶，于是首个刷新周期后握手必然失败 | 三个真实部署调用点全部切到 `-tee-verify attestation`（§9.2） |
| ② | 中 | TOFU 的两条导出路径都是**启动快照**：`/v1/init-cert` 缓存启动时的 `tls.Config`；`WriteTEECert` 只在启动时写一次 | 两条都改为跟随轮换（§9.3） |
| ③ | 中 | **发布失败不缩短重试**：`Refresh` 已经成功、但 epoch 没落到 service 时，节奏仍按证据的新鲜度退到 2h 上限 | `nextRefreshDelay` 增加 `published` 形参，未落地即返回 `minRefreshFloor` |
| ④ | 低 | `EnsureMTLSCerts` 只判断"三个文件都在"，**看不出错配**（丢了其中一个文件的目录、或两个进程竞争创建的目录会带着一套从未属于彼此的证书通过检查） | 改为"整套是否还能用"：CA 能解析、私钥属于证书、证书是 CA 签的 client 证书；否则整套重建，并写回后复核（§9.4） |
| ⑤ | — | ~~`crosshost.sh` 给 agent 传的 `-ca "$SIM/ca.pem"` 在部署链里无人创建，起不来~~ | **误报，已撤回**：`mockprovider` 即使收到显式 `-ca/-cert/-key`，也会把 CA 复写到 `shared.CAPEMPath()`（`tokenhive/cmd/mockprovider/main.go:216`），该文件必然存在 |
| ⑥ | 低 | 刷新 goroutine 用 `context.Background()`，不可取消 | **不改代码，判定为设计取舍并写明理由**（§9.5） |
| 简化 | — | `serviceRuntime.includeEvidence` 与 `template.Signer.IncludeEvidence` 是同一事实的副本 | 删掉字段，`adopt` 直接从 template 读 |
| 简化 | — | hub 身份路径在 `hubClientIdentity` 与 `EnsureMTLSCerts` 里各写了一遍 | 新增 `shared.HubIdentityPaths()` 作为唯一出处 |

### 9.2 ① 部署调用点：改了什么

| 位置 | 改前 | 改后 |
|---|---|---|
| `tokenhive/cloudtest/snp/crosshost.sh`（跨机 AWS，主路径） | `-mtls-ca mtls/tee-cert.pem`，并把 `.certs/tee-cert.pem` 推到主机 | `-tee-verify attestation`（同行已有 `-allowed-platforms aws-sev-snp -expected-app 'snp-app:${app_hash}'`、`-mtls-cert/-mtls-key` 保留）；**不再分发 `tee-cert.pem`** |
| `tokenhive/cloudtest/remote/run-all.sh` | 恒 `-mtls-ca "$SIM/tee-cert.pem"` | 按 `TEE_PLATFORM` 分支：sevsnp ⇒ `-tee-verify attestation`；simulated ⇒ 保持 pin（sim 叶没有 attestation 扩展，attestation 模式必然拒绝） |
| `tokenhive/cmd/single/main.go`（单机密实例） | `-mtls-ca teeCert`，且 supervisor 先经 `/v1/init-cert` 把叶拉回本地再交给 hub 固定 | `-tee-verify attestation`；删掉 `fetchTEECert()`，改为等 tee 自己写出的 `tee-cert.pem`（§9.3 末） |
| `tokenhive/harness/harness.sh:804/814` | `-mtls-ca` | **不动**：faketee 是 simulated，epoch 固定，pin 就是完整信任声明 |

`crosshost.sh fetch` 保留，但语义从"建立信任"变成"人工核对"：hub 不再固定它取回的证书，端点返回什么都不会改变 hub 的判定。`TEE_INIT_ADDR`/`TEE_INIT_TOKEN` 因此从信任链降级为无 sshd 实例上的只读窗口。

### 9.3 ② 的两条路径都改为跟随轮换

轮换会同时换掉监听器的密钥、receipt signer 与证据，但"给外部看的东西"当时漏了两处：

1. **`/v1/init-cert`**：`serveInitCert` 捕获的是启动时的 `*tls.Config`，返回的是启动叶。改为每个请求现取 `leafCertPEM(mTLSConfig)`——这个端点的契约就是"监听器**现在**所持的那张叶"，而它恰好是唯一一个目的就是学习当前叶的调用方。
2. **`tee-cert.pem`**：只在启动时写一次，之后永远描述一张没人再服务的证书。改为在 `publishEpoch` 里，紧跟证据落盘之后、`adopt` 之前重写；来源是 `epochRefresher.ServerTLSConfig()`（= hub 侧同一个 accessor，sevsnp adapter 的 `GetCertificate` 读的是 `a.current`，而 `Refresh` 在返回前已发布新 epoch，所以拿到的就是轮换后的叶）。取不到 server TLS config 时**拒绝整次轮换**，与其它半失败一致：宁可继续用上一套自洽状态（文件仍准确描述它），也不留一个"监听器与实际发布物互相否认"的窗口。

`cmd/single` 的自举因此完全失去消费者：它拉回来的字节，tee 子进程本来就已经写在了同一个路径（`ConfigDir() == TOKENHIVE_SIM_DIR`）。改为 `waitForTEECert()` 只等这个文件出现——保留原本由自举顺带提供的**启动顺序**（不要在 tee 能服务之前让 hub 去拨），去掉那次多余的 HTTP 往返与令牌依赖。tee 的 `-init-addr`/`-init-token` 仍原样传给子进程（与双机形态保持一致的 flag 面，且 loader 本就会注入这两个 env）。

### 9.4 ④ 与两处简化

`EnsureMTLSCerts` 由"三个文件是否都在"改为"这套是否还能一起用"：走 `loadHubMTLSIdentity(ca, cert, key)`，要求 CA 可解析、`tls.LoadX509KeyPair` 能配出一对、且叶是**由该 CA 签发的 client 证书**；不满足就整套重建，**写完再读回复核一遍**，让"目录写不进去 / 有并发写者"在启动时以启动失败暴露，而不是以后变成一次没有可见原因的握手失败。回归测试 `TestEnsureMTLSCertsRebuildsAMismatchedSet` 放一份 staleCA + freshCert + freshKey，断言整套被重建、旧 CA 不被复用。

同时把 hub 侧解析同一批默认路径的逻辑收敛到 `shared.HubIdentityPaths()`：路径只有一处拼写，避免"写在一个地方、读在另一个地方"。hub 在操作者显式给了 cert+key 时也不再多余地跑一次 `EnsureMTLSCerts`。

### 9.5 ⑥ 为什么不去改成可取消的 context

结论是**不改**，理由是取消这件事在这里只有坏处和风险，没有好处：

- 刷新循环应当**恰好与监听器同寿**。`RunRATLSRefresh` 在 ctx 被取消时的行为是"再 adopt 一次当前快照然后返回"——于是循环停了、epoch 不再更新，而监听器继续用那份正在老化的证据应答，这是比不取消更糟的状态。
- 两条服务路径的结尾都是 `log.Fatal(...)`，**不会**沿 defer 栈退回：任何 `defer cancel()` / `defer stop()` 都执行不到，接一个可取消 ctx 在今天的结构里是纯装饰。
- 用 `signal.NotifyContext` 让它"响应 SIGTERM"会**改掉默认语义**：注册信号处理会屏蔽默认的"收到信号即终止"，除非同时实现一套 graceful shutdown；一个部署脚本按 SIGTERM 停不下来的 enclave 是实实在在的部署隐患。

所以代码里保留了 `context.Background()` 并把这三点写进了注释（`cmd/tee/main.go`）。如果将来真的引入优雅关停（比如接 `AttestationHealth` 一起做），届时再把 ctx 挂到那条关停路径上，才是对的做法。

### 9.6 验证

| 验证 | 结果 |
|---|---|
| `gofmt -l tokenhive/cmd/` | 干净（本次触及的文件均不在列表内） |
| `go build ./tokenhive/...` / `go build -tags sevsnp ./tokenhive/...` | 均通过 |
| `go vet ./tokenhive/...` | 干净 |
| `go test ./tokenhive/...` | 全绿（含 `cmd/tee`、`cmd/hub`、`cmd/internal/shared`、`internal/mtls`） |
| 新增 `TestRunEpochRefreshAdoptsAndPublishesRotatedEpoch` 的叶断言 | 通过；**在临时移除发布逻辑的实现上会失败**（实测 `read published RA-TLS leaf: ... no such file or directory`），非空转 |
| 新增 `TestRunEpochRefreshRefusesARotationItCannotPublishATleafFor` | 通过；同一实验下失败（`runtime adopted an epoch whose RA-TLS leaf could not be published`） |
| `TestEnsureMTLSCertsRebuildsAMismatchedSet` | 通过（`staleCA + freshCert + freshKey` 被整体重建） |
| `bash tokenhive/harness/harness.sh`（`/tmp` git worktree @ `d5aa723`，场景 1–18） | **0 FAIL**，exit 0（45 项 OK 断言；在 `/tmp` 跑以绕开本机删除护栏导致的 `.sim` 清理失效，见 §7.5） |
| `grep -c FAIL` on 完整 harness 输出 | 0 |

### 9.7 仍未做

- **没有重新部署，也没动 AWS 上那台 TEE / hub**：`crosshost.sh` 与 `cmd/single` 的改动是"下次部署会怎么跑"。现有实例仍在用 pin 语义的旧 hub 参数，若要保持在线超过一个刷新周期，需要按新脚本重新 `deploy`（或手工把 hub 换成 `-tee-verify attestation` 并去掉 `-mtls-ca`）。
- **没有重新构建 AMI**：AMI 里的 bundle 未变，本次改动只影响主机侧脚本与单机 supervisor 的行为；单机 AMI 若要生效需重建。
- **pin 模式保留**：它没有被删掉，但只对"epoch 不变"的平台成立（simulated / harness）。真机上一旦用 pin，就回到了 §7 的 2h 失效问题。
- **刷新彻底失败仍无自愈**：若 `Refresh` 连续失败（例如 `/dev/sev-guest` 卡死使 `healthy` 永久为 false），进程只会持续以 `minRefreshFloor` 重试并记录日志，没有重启手段（见 §7.6 末与 §9.5）。

---

## 10. 实施记录（五）：每 2h50m 一次的 RA-TLS 准入黑窗（2026-09-22）

> 分支 `fix/tee-diagnostics`（基于 `tokhive`），三个提交。**只改 TEE 侧判据与节奏**，不改线协议、不改 Hub。

### 10.1 问题

§7 接上刷新循环之后，TEE 不再出现 §4 那种"启动 3 小时后彻底失效"，但出现了一种**周期性**的整机不可握手：

- Hub 每 10 分钟告警一次 `WARN TEE inbox key unavailable; Hive will keep asking  error="Get \"https://<tee>:18090/v1/credential-key\": remote error: tls: internal error"`。
- TEE 串口控制台同一节奏地记 `TEE listener not ready; refusing new handshakes`，每条间隔 10 分钟。
- 每次持续约 20 分钟，然后自己恢复。作者第一次遇到时以为与"刚重启 Hub"有关（重启时刻恰好落在窗口内），实际无关。

`tls: internal error` 是 Go 把 `GetCertificate` 返回的错误转成的 **alert 80** —— 也就是说握手在 TEE 这一侧就被**主动拒绝**了，根本没走到 Hub 的证书校验（Hub 侧 `mtls.ClientMTLSConfig` 走标准 `leaf.Verify`，对这张叶没有额外 margin，叶有效它就接受）。所以现象里的 `internal error` 不是"证书不能验"，而是"TEE 不肯出示"。

### 10.2 排查方式

TEE 实例没有 sshd，现场通道只有两条，这次两条都用上了：

1. **串口控制台**：`aws ec2 get-console-output --instance-id … --latest`。注意 **`Latest=True` 不能省** —— 默认返回的是一份延迟的旧快照，会让人误以为"启动后就再没输出过"（本次就先把判断带偏了一次）。
   拿到后按 JSON 逐行解析（`level`/`msg`/`time`），把 25 小时里的 150 条记录排成时间线：**周期恒定 2h50m12s**，误差 ±1 秒，没有任何例外 —— 这就排除了"偶发失败"。
2. **从 Hub 主机抓 TEE 的 RA-TLS 叶**（Hub 持 `hive-client.pem`）：
   ```bash
   echo | openssl s_client -connect <tee>:18090 \
       -cert /etc/tokhive/hive-client.pem -key /etc/tokhive/hive-client-key.pem \
       -CAfile /etc/tokhive/hub-ca.pem -showcerts 2>/dev/null \
     | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' > leaf.pem
   ```
   交给 `tokenhive/cloudtest/probe_ratls` 读出叶里 NitroTPM 证据的 `notBefore`/`notAfter`。
   实测：**叶子寿命正好 3h**，且 `notBefore` 恰好等于上一次轮换成功的时刻 —— 说明 AWS 是**按需**签发的，
   只是在到期前约 **9m48s** 才肯换新（两次重签间隔恒为 2h50m13s）。
3. **对照代码**：TEE 侧准入判据（`sevsnp.Adapter` 的 epoch 截止时刻）与 Hub 侧的校验（`internal/mtls`）逐行对照，
   确认两侧对"这张叶还能不能用"的答案不一致，且差异正好是配置里的那个 margin。

### 10.3 根因

一个 margin 同时承担了两件事，而其中一件是错的：

```text
旧: admission deadline = NitroTPM 叶 NotAfter − SNPRefreshMargin(30m)
    Hub 接受这张叶到           NotAfter（不含 margin）
    AWS 重新签发这张叶于       NotAfter − 9m48s

⇒ 黑窗 = margin − 重签提前量 = 30m − 9m48s = 20m12s
```

黑窗内**重试是无效的**：`Refresh` 每次都成功，但 AWS 还没到重签点，拿回来的是**同一片叶**；新 epoch 的截止时刻由那片叶自己的 `NotAfter` 决定，与何时轮换无关，于是新 epoch 一建出来就已经过了 margin，`GetCertificate` 继续拒绝。叠加当时的重试下限 `10m`（比 9m48s 的重签窗口还宽），重试网格可以整窗跨过重签点 —— 本次恢复纯属运气：那一次重试落在重签点前 5 秒，TPM 调用本身跨过了它。

### 10.4 修复（3 个提交）

| commit | 内容 |
|---|---|
| `a126328` | **拆开两个截止时刻**。`SNPAdmissionDeadline = 叶 NotAfter`（与验证方逐字一致）、`SNPSigningDeadline = NotAfter − SNPSigningMargin(5m)`。准入用前者，出收据用后者，轮换节奏瞄准后者。 |
| `205ca4a` | **刷新不得倒退**。新 epoch 只有把准入截止推得更远才替换当前 epoch；同叶/更旧叶的轮换是 no-op（不写 identity/evidence、不重建 service、不 retire 活连接），同时保留"发布失败可重试"。 |
| `9380da0` | **重试下限 10m → 2m**。2m 窄于 9m48s 的重签窗口，重试网格不可能整窗跨过。 |

三者合力后的稳态：`T+2h` 那次是**同叶空转**（无错误日志、无连接 churn），`T+2h55m`（签名截止 = 重签点
`+4m48s`）**第一次排定尝试就命中新叶**。黑窗消失。

### 10.5 影响

**功能**

- 周期性整机不可握手（每 3 小时约 20 分钟）消失。
- 最坏情况从"**任何**握手都被拒 20 分钟"退化为"握手照常、**收据停发**不超过 5 分钟"：只有
  `[NotAfter−5m, NotAfter]` 这 5 分钟内，TEE 会以 `ErrAttestationStale` 拒绝新任务（不分配序号、不花 provider 额度）。
- 轮换不再因"证据没变"而 retire 所有活连接 —— 之前每次空转轮换都会打断在途连接做无用功。

**信任语义（需要知情的取舍）**

- 一张**新签发**收据的最小可验证余量由 30 分钟降到 **5 分钟**：`SNPSigningMargin` 是"签出时距叶到期至少还剩多久"的
  承诺，它现在更小。代价是收据在极端情况下（签发后 5 分钟内叶到期）可验证窗口更短；收益是准入判据与验证方
  完全对齐，不再有"验证方接受、TEE 自己拒绝"的错位。这属于信任策略选择，改动处已在代码注释里写明理由。

**兼容性**

- 无线格式变更，Hub 侧无需改动（Hub 从未使用过这个 margin）。
- `tee_k` / `tee_t` 仅跟随函数改名：它们的 `attestationExpiry` 一直是"缓存重新出证期限"，现在等于
  `NotAfter − 5m`（原来 `−30m`）⇒ 缓存命中时间变长、按请求重新出证的窗口变小，行为不变。
- 本仓库其余引用点（`probe_ratls`、部署手册）已同步。

**验证**

- 新增/反转的测试：10 分钟到期的叶**应当被准入**（旧断言是"必须拒绝"，已按新语义反转）；叶真过期才 fail-closed；
  签名边界用 6m / 4m 夹住 5m；同叶与更旧叶不替换、更远叶替换；空转 tick 断言**没有** retire 连接。
- `go build ./...` + `go vet` + `go test ./shared/... ./tee_k/... ./tee_t/... ./tokenhive/...` 全绿，
  且**逐个提交**单独验证过（每个提交自身可编译、测试通过）。
- `bash tokenhive/harness/harness.sh` 在 `/tmp` 的干净 worktree 里 A/B（基线 `tokhive` vs 本分支尖）：
  **18 场景 / 45 OK / 0 FAIL，断言逐行相同**。

## 11. 实施记录（六）：证书轮换的影响面 —— 买家与卖家分别会看到什么（2026-09-22）

> 本节只做**核对与记录**，不改代码。判据全部来自本分支尖的源码（位置随行标注）。生产 Hub 跑在独立仓库
> `tokhive-mvp`，其 `Verify` 实现不在本仓库，凡依赖它的结论都已单独标注。
>
> **写于 `1508332`；其后的 §12/§13 改掉了本节的两处结论，保留原文以便看出"当时以为的边界"与"实际边界"的差**：
> - §11.2 第 3 条说"Hub 侧没有针对 503 的重试"——**现已加上**（§12.3，`f774d23`），同 listener 上的
>   `/v1/credential-key`、`/v1/evidence` 亦然（`865cd2c`、`0be5771`）。
> - §11.2 第 2 条末尾关于"会话终端收据故意用轮换后的新 key 签"的语义**依然成立**，但会话现在会在
>   live signer 进入签名 margin 前被主动切断（§13，`1a9ee05`），所以"跨 epoch 不一致"的实际发生面比当时描述的窄。
> - §11.3 B 档说"所有 `Execute`/`OpenSession` 被 `ErrAttestationStale` 拒"——`Execute` 侧现在多了一条
>   "余量不足亦拒"的入口检查（§12.2），语义相同、位置更早；`OpenSession` 仍不因余量不足而拒（有意的不对称，见 §13.4）。

### 11.1 轮换换什么、不换什么

轮换要解决的是"证据会过期"，所以它只动**与证据绑死的那两样**：

| 身份 | 轮换时 | 代码位置 |
|---|---|---|
| TEE 服务端 RA-TLS 叶（Hub→TEE 握手用） | **换** | `tokenhive/platform/sevsnp/adapter.go`（`Refresh` 换 epoch） |
| receipt 签名 key（`KeyID`） | **换** | `tokenhive/cmd/tee/ratls_refresh.go`（`adopt`） |
| credential inbox key | **不换**：进程启动生成一次，注释写明 deliberately untouched | `ratls_refresh.go:189-192`、`tokenhive/cmd/tee/main.go`（`GenerateInboxKey`） |
| relay 通道（TEE 拨 Hub 去接 provider） | **不换**：WebSocket + `RelayKeyHeader` 共享密钥，不用客户端证书 | `tokenhive/cmd/tee/main.go:87-92`、`relayHeaders()` |
| Hub 侧信任根 | **不换**：AWS NitroTPM root 在 measured bundle 里 | `tokenhive/internal/mtls`（`LoadCAPath`） |

结论：**凭据平面（卖家的一切）与证书轮换完全解耦**；唯一会让 provider 重新注册 token 的是 **TEE 进程重启**
（inbox key 换），不是轮换。

### 11.2 AWS 正常时

**卖家：无影响。** 卖家的在线通道是 agent ↔ Hub（Hub 自己的 WS），不经 TEE TLS；与 TEE 的唯一接触是
注册/续期时经 Hub 取 inbox key（`CredentialKey` → `/v1/credential-key`，Hub→TEE mTLS）。inbox key 不变，
已经封给它的 envelope 继续可用（`tokenhive/hub/tee.go` 的 `CredentialKey` 每次现取、不缓存，正是为了不吃旧 key）。

**买家：三条窗口，前两条无感，第三条才是"毫秒级"的那一个。**

1. **空闲连接被退役**：`rotate()` 只 close `idle` 连接（`rotated_connections.go:140-157`），在途连接留给
   `track`（`:102-130`）在它落回 idle 时关。Hub 侧连接池是 `&http.Transport{}`（`cmd/hub/main.go:139`），
   下次请求重新握手拿新叶即可 —— Hub 对叶的判据是标准 `leaf.Verify`，对轮换后的新叶没有额外 margin，
   所以这一步无感。
2. **在途请求 / 流式会话不被打断**：`Service.perform` 把本次交换的 signer **pin 住**（`tee/service.go:464-473`），
   收据与它所在连接的叶同属一个 epoch；WebSocket session 的连接是 `hijacked`，`track` 明确不 close 它，
   会话跨轮换继续跑。注意一个语义点：**session 的 terminal receipt 故意用轮换后的新 key 签**
   （`tee/service.go:876-884`），所以"收据 KeyID 与其所在连接的叶"在长会话里可以不一致。本仓库 Hub 不把
   两者交叉校验（`Verify` 是注入的 verifier，只验链 + app + policy；`hub/hub.go:513`），但若将来有验证者
   做这种绑定，需要知道这是有意的。
3. **复用竞态（唯一可能被买家看见的失败）**：Hub 恰好在 TEE close 的空隙里复用了那条连接 → `guard`
   回 `503 connection belongs to a retired attestation epoch; reconnect`（`rotated_connections.go:76-89`）。
   Hub 侧没有针对 503 的重试，只有 `executeForProviders` 的候选循环（`hub/schedule.go:362-390`），
   而**所有候选共用同一个 TEE** —— 它靠重连建立新连接来成功；若此时已 relay 过字节或 start 帧，则不 fallback，
   买家直接看到一次失败。窗口是毫秒级、每个真轮换一次。

另外，只有**真轮换**才有连接 churn：每 2h 的空转 tick（同叶）被 `publishEpoch` 的 `serving()` 早返回
（`ratls_refresh.go:236-243`）与 adapter 的 `supersedes`（`adapter.go:247-249`）双重挡掉，不建文件、不 retire 连接。

### 11.3 AWS 不正常时（三档）

| 档 | 触发 | 买家 | 卖家 |
|---|---|---|---|
| A | `Refresh` 失败，但叶未到期 | **无感**：准入跑到叶自己的 `NotAfter`（`adapter.go:240`），只是节奏延后 | 无感 |
| B | 进入 `[NotAfter−5m, NotAfter]` 仍拿不到新叶 | 所有 `Execute`/`OpenSession` 被 `ErrAttestationStale` 拒（`service.go:317`、`:679`），**先于**分配 `ProviderSeq` ⇒ 不缺号、不花费额度；上限 5 分钟 | 无感（inbox key 没变） |
| C | 叶到期后 AWS 仍不恢复 | **握手全拒**：`GetCertificate` 返 `ErrNotReady`（`adapter.go:147-151`）→ alert 80 → Hub 侧读到 `tls: internal error`；已建立的长连接也救不了（`guard` 放行，但 service 仍拒） | 新 agent 注册失败；在线 agent 的隧道还在但没有任务可跑 = **零收入**，不是坏账 |

C 档只能等 AWS 恢复或重启 TEE。刷新循环的 health tracker 传的是 `nil`（`ratls_refresh.go` 注释：
本进程没有可驱动的恢复路径），**不会自重置**。而**重启 TEE 会换 inbox key ⇒ 所有 provider 必须重新注册凭据** ——
这是唯一需要卖家动手的场景，且由重启引起，与轮换无关。

### 11.4 账务面

拒发发生在分配序号之前 ⇒ 不会在 provider 的序列里打洞、不对买家计费；已 relay 字节而收据拿不到时
Hub 无法结算（收据是计费前提，`hub/hub.go` 的 `Execute` 注释）。异常期只会"少收"，不会"错账"。

### 11.5 运维约束

- Hub 侧 `-tee-verify` 必须是 `attestation`。`pin` 模式信任的是部署时分发的那张叶，而轮换会换叶，
  第一次重拨就失败（`internal/mtls/mtls.go:133-139` 有专门文案提示这两种原因需要相反的处置）。
  线上证据支持生产用的是 attestation：§10 的黑窗在没有任何重新分发的情况下自愈。
- 换 TEE（新 AMI / 新 digest）与**轮换**是两回事：前者要同步 `HIVE_TEE_EXPECTED_APP` 并让 provider 重新注册；
  后者什么都不用做。逐步流程见 **§15**（先建、再切、最后删，不必等旧机终止），两个已知的静默坑与修法见 **§15.1 / §16**。

## 12. 实施记录（七）：交易所的硬边界，与"轮换还能伤到谁"的复查（2026-09-22）

§11 把轮换的影响面按买家/卖家列了一遍，并指出**唯一可能被买家看见的失败**是"复用了一条刚被退役的连接"那个
503。当时留了一句话没兑现：那不是唯一的窗口。这一节把第二个窗口关掉，并把"还有没有第三个"照着代码查完。

### 12.1 第二个窗口：在 deadline 之前开始、在它之后结束

`perform` 会把收据签名者**钉在**请求到达时的那一个（这是必要的：收据里的 KeyID 必须与承载它的连接所呈现的
epoch 一致），而入口处的 `signerStaleAt` 只在**请求开始时**判一次新鲜度。于是：

- `RequestTimeout`（`-request-timeout`，默认 2m，**设 0 就是无界**）是**从交易所自己的起点**算的窗口，
  不是"必须在签名 deadline 前结束"的约束；
- 一个在 `[deadline − RequestTimeout, deadline)` 之间被受理的请求，会在 `deadline` 之后才走到签名。

后果不是"收据不好看"，而是**结算失败**：收据 cite 的是已经在签名 margin 之外的叶，Hub 在入库前验收据
（`hub/hub.go` 的 `Execute` → `attest.Verifier.Check` → 链校验末端 `shared/snp_combined_aws.go:380` 的
`leaf.Verify`，**没设 `CurrentTime`**）⇒ `x509: certificate has expired` ⇒ 买家 5xx，而 provider 已经跑完、
Hub 无法结算。按 170 分钟的轮换周期、`RequestTimeout` 非零时有流量的情况下约 1% 以上的轮换会命中一次；
设 0 则没有上界。

### 12.2 修复（提交 `d4d8fb2`）：把签名截止变成交易所的硬边界

| 机制 | 位置 | 作用 |
|---|---|---|
| `signingHandoff = 1s` | `tee/service.go:283` | 交易所结束点到签名 deadline 之间留的余量。签名本身是微秒级，这 1s 是给调度抖动与秒级时钟粒度的地板，不是要花掉的预算 |
| `signingDeadline` / `signingBudget` | `tee/service.go:295`、`:314` | 从钉住的 signer 读出 `SNPSigningDeadline`；budget = 剩余时间 − `signingHandoff`。**没有可读叶的证据（模拟、测试假件）返回 bounded=false**，否则钉住的测试钟会被当成故障 |
| 受理时的拒绝 | `tee/service.go:393` | budget ≤ 0（余量不足 `signingHandoff`）⇒ 直接 `ErrAttestationStale`。**与"epoch 已 stale"同一位置、同一代价**：在分配 `ProviderSeq`、解开凭据之前拒绝，不给 provider 的序列打洞 |
| 交易所的硬边界 | 同上 | 否则给整个执行套一个 `context.WithTimeout(ctx, budget)`。被切断的交易所产出的是 **truncated 收据**：`Price` 对这种收据只按已交付字节收 volume（`hub/pricing.go:69-72`），于是 **provider 拿到它已做的那部分钱**，而不是整单结算不了 |
| 签名前复查（fail-safe） | `tee/service.go:701` | deadline 不是保证：忽略 context 的 transport、或跳变的时钟，仍然会走到签名。这时**拒绝而不是签**。这是唯一"provider 已经干了活却什么都结算不了"的路径，所以它的存在本身就意味着上面那条边界失效了 |

两点需要写清楚：

1. **拒绝放在受理处而不是交易所里**，是为了不产生 ProviderSeq 空洞（一个花掉却没收据的序号，provider
   无法与"被隐藏的执行"区分——见 `hub` 里那段关于 gap 的注释）。
2. **bound 总是取更紧的那一个**。它由受理时的 signer 算出，而 `perform` 钉住的 signer 在中间发生轮换时
   只会换成**更晚到期**的叶，所以这个 bound 永远不会比实际的更松；`Request.Timeout` 仍然原样传给 transport，
   两者取 min。就实际影响范围而言，需要它起作用时（`deadline − now < RequestTimeout`）切点一定落在 Hub
   `-attempt-timeout`（默认 3m）之内，所以收据总能被 Hub 读到。

### 12.3 复查发现的同类缺陷：同一个 listener 上的另外两条路径

`epochConnections.guard` 挂在 `mux` 外层，**覆盖该 listener 的所有路由**（`cmd/tee/main.go` 的
`Handler: svcRuntime.conns.guard(mux)`）。因此'退役连接 503'不只 `/v1/execute` 会遇到。逐一查过：

| 路径 | 谁在用 | 后果 | 处置 |
|---|---|---|---|
| `POST /v1/execute` | Hub 派发任务 | 买家可见的失败 | 已修（上一节，`f774d23`）：带标记的 503 重试一次 |
| `GET /v1/credential-key` | **每个** provider agent 每次重连都拉一次（经 Hub 转发） | 卖家侧：agent 注册失败，且失败原因对它完全不可见 | 已修（`865cd2c`）：把拒绝收敛成协议包里唯一的 `tee.ErrEpochRetired`，由两边共用的客户端 helper 重试一次 |
| `GET /v1/evidence/<hash>` | Hub 验收据时解析 `EvidenceHash`（**生产是 hash-only 收据**，且 `attest.Verifier` 不缓存，**每张收据都取一次**） | 三者中最重：任务跑完了、provider 付过上游了、TEE 也签了收据，Hub 却因为读不到收据自己点的证词而**把整单丢掉** | 已修（`0be5771`）：重试一次。这条不需要标记就安全——取回的是按自身哈希寻址的只读字节，且下面还会比对哈希，重试能重复的东西为零；对端真不可用则两次都失败，如实报错 |
| `GET /v1/session`（WebSocket 升级） | Hub 开流式会话 | 升级本身见 12.4（不走池，微秒级竞态）；会话自身的终端收据见 §13 | 升级不加代码；终端收据由 `relaySession` 观察到 deadline 时主动切断（§13） |

三条修复的**安全论证是同一个**：`guard` 在 handler 之前返回，所以那次拒绝没有分配序号、没有花凭据、没有碰
provider。差别只在"能不能证明这一点"：`/v1/execute` 上必须靠标记（无标记的 503 可能是在任务已执行之后才
回的，重试会重复执行并重复计费），`/v1/evidence` 上请求本身就是只读，规则自然满足。

### 12.4 会话的终端收据（当时未修，已在 §13 修掉）

会话是**故意无界**的（`rotated_connections.go` 里 `track` 对 `StateHijacked` 的解释），终端收据用**结束那一刻
的 live signer** 签（`tee/service.go:989`）。如果那时 live signer 已经进了签名 margin，`Receipt()` 直接返回
`ErrAttestationStale` ⇒ `relaySession` 回一条 `{"error":...}` ⇒ Hub 侧 `sessionTunnel` 拿到的不是收据 ⇒
`ErrNoReceiptForSession`。**整个会话的字节全部无证、不可结算**，而 provider 已经把它们转发完了。

什么时候会发生：需要在**会话结束**那一刻 live signer 已过期，也就是"轮换连续失败到过了 deadline"。健康的
轮换会提前约 4m48s（AWS 在叶到期前 9m48s 重签，而 signature deadline 只提前 5m）就把新 epoch 换上，所以正常
情况下不会命中——这一条只由 AWS 侧故障触发，但**每次命中的损失是一整个会话**，不像 §11 B 档那样有 5 分钟上界。

为什么 A/B 覆盖不了它：B 的形态是"在 deadline 之前把交易所切断"，而会话的问题是**它结束的时刻由 provider
决定**，那一刻已经不能签了。唯一修法是在 live signer 距 deadline 还有 `signingHandoff` 时就**主动切断隧道**，
让收据在 margin 内签出（收据照样按已转发字节计费）。代价是这个 deadline 必须**跟着轮换走**（不能用会话开始
时那一张），需要在 relay 循环里按当前 signer 判一次——不是一行，但也不大。

三种选择：(i) 按上面实现；(ii) 接受并只留记录（它只在 AWS 已故障时出现）；(iii) 会话也加绝对长度上限
（但那会改掉"unbounded work"的设计意图，与其它部分不一致）。我倾向 (i)，但它不属于"毫秒级窗口"这一类，
所以先摆出来。

### 12.5 已确认不受影响 / 不值得改的

- **WebSocket 会话拨号（`/v1/session`）**：`hub/session.go:37` 用 `websocket.Dialer` 直拨，
  gorilla 每次自己建 TCP 连接，**不走 `http.Client` 的连接池**。所以"退役连接被复用"这个前提不成立，
  只剩 accept→请求 之间的微秒级竞态（`guard` 在轮换落在这一瞬时会拒升级，Hub 的会话循环会 `continue`
  到下一个候选后整体失败）。概率约 1e-8/天量级，低于值得加代码的门槛。**如果将来把 `Dialer.NetDial`
  指到共享 transport，这条会立刻变成真问题。**
- **空转 tick 不产生 churn**：`publishEpoch` 对已在服务的 KeyID 早返回，`adapter` 的 `supersedes` 也挡一层；
  `conns.rotate()` 只在**真的换 epoch** 时被调用一次（`ratls_refresh.go:179`，只在 `adopt` 里）。
- **Hub 候选循环的空转**：一个 stale epoch / 余量不足的拒绝会让**每个候选各打一次**（它们都指向同一个 TEE），
  N 次往返后 5xx。只是浪费，不重复计费：拒发都在分配序号之前或（fail-safe 那条）根本不出收据。
- **凭据面与轮换解耦**：inbox key 进程启动生成一次、轮换不换（`ratls_refresh.go` 的注释）；provider 的在线
  通道是 agent↔Hub 的 WS，不经 TEE TLS。真正要卖家重新注册的是**重启 TEE**，与轮换无关。
- **账务不会错**：截断收据只按已交付字节计 volume；拒发不产生收据因而无计费；`CompletionFailed` 计 0
  （`hub/pricing.go:80`）。异常期只会少收。

### 12.6 相邻但不属于轮换的两点（记录，不改）

- **TEE 侧时钟没有自检**。enclave 用的是宿主提供的 `time.Now`，而 signing deadline 来自 AWS 签发的叶的
  `NotAfter`。宿主钟若落后 AWS，TEE 会按自己的钟继续签、Hub 用真钟拒收（`certificate has expired`）——
  这是唯一**系统性**而非边界性的失效面。真要做，可以在刷新循环里用新叶的 `NotBefore` 与本地钟做一致性检查
  （AWS 只在旧叶最后几分钟才重签，所以"刚签发的叶的 NotBefore 应该接近现在"是个可判据）。
- **evidence store 是单实例磁盘、append-only**（`evidence/store.go` 的包注释）。轮换只是往里加文件（每
  ~2h 一个，几 KB）；真正会丢历史的是**换 TEE 实例**，那时 hash-only 收据的证词只能靠别处的副本解析。
  与轮换无关，与"换机/重新部署"有关。

### 12.7 验证

- `go vet ./shared/... ./tokenhive/...`：无输出。`go test ./shared/... ./tokenhive/...`：全绿。
- harness A/B（`/tmp` 干净 worktree，基线 `f774d23`）：`d4d8fb2` 与 `865cd2c` 都是
  **18 场景 / 31 OK / 0 FAIL，断言逐行相同**。
- 新增测试：`tee/exchange_bound_test.go` 5 个（bound 的取值与 `RequestTimeout` 并存；被切断仍出可结算的
  truncated 收据；余量不足时在 transport 与序号之前就拒；逃出 bound 的交易所不签名；无可读叶时不设 bound）；
  `hub/tee_test.go` 2 个（credential-key 的标记重试一次 + 不循环）；`evidence/store_test.go` 2 个
  （evidence 抓取重试一次 + 持续拒绝则报错）。

## 13. 实施记录（八）：会话的终端收据（2026-09-22）

§12.4 把会话末尾的收据列为「未修」，并给了三个选项。这一节按选项 (i) 修掉它：**在 live signer 距 deadline
还有 `signingHandoff` 时就主动切断隧道**，让收据在 margin 内签出。

### 13.1 问题

会话是**故意无界**的（`SessionIdleTimeout` 是防「对端消失」的看门狗，不是时长上限），所以它可能跨过自己
开启时那个 epoch 的签名 deadline。交易所没有这个问题：`Execute` 用 §12.2 的 bound 把它的**结束**压进
deadline 之内。但会话的结束**不由服务决定**——上游流多久它就多久——所以同一个 deadline 没法用「给会话套一个
context」实现，只能**从外面把它切断**。

旧行为因此是：epoch 在会话还转发时进了 margin ⇒ `Session.Receipt`（`tee/service.go:1003`）返回
`ErrAttestationStale` ⇒ `relaySession` 回一条 `{"error":...}` ⇒ Hub 侧 `ErrNoReceiptForSession`
⇒ **整场会话的字节全部无证、不可结算**，而 provider 已经把它们转发完、上游也已经计过费。触发条件是
「轮换失败到过了 deadline」（健康轮换在 deadline 前约 4m48s 就换上了新 epoch），但每次命中的损失是
**一整场会话**，不像 §11 B 档那样有 5 分钟上界。

### 13.2 修复（提交 `1a9ee05`）

| 机制 | 位置 | 作用 |
|---|---|---|
| `watchSigningDeadline(stop)` | `tee/service.go:351` | 每会话一个观察者：反复算 live signer 的 `signingBudget`，为它设一个定时器；budget 耗尽时 close 一个 channel。**每次醒来都重读 `activeSigner()`**（见下第 2 点）|
| 切断 | `tee/session.go:185`（`relaySession`）| channel 关闭 ⇒ `ss.markTruncated()`（`:194`）然后 `ss.Close()`：结束 provider 侧隧道。pump 本就阻塞在那个 Read 上，于是照常签名，并把收据作为终止 Text 帧送出 |
| **标记先于关闭** | 同上 | 不是顺手：`ss.Close()` 才是解除 pump 阻塞的动作，而 provider 若以「干净读完」结束，`Session.Read` 不会把转录标成截断——收据就会声称一份少了这个瞬间之后全部字节的「完整」转录 |

两个设计要点：

1. **切的是 provider 侧，不是 Hub 侧。** 空闲看门狗可以直接 `conn.Close()`（对端已经走了，收据送给谁都没有
   意义）；deadline 观察者不行——收据正是这场会话的价值所在，而它由 pump 在隧道关闭**之后**才签、才发。
   所以先 `ss.Close()`，让 pump 完成收尾。收据仍然由「唯一写者」签出，仍然以终止帧的形式到达。
2. **deadline 跟着轮换走。** 观察者不锁定会话开启时那一张 signer，而是每次醒来重读。轮换发布的是**更晚到期**
   的叶，deadline 只会往后推，所以正确语义就是「按旧预算醒来 → 发现还有余量 → 重新武装」：**提前醒来是无害
   的**，只是多一次唤醒，不需要任何锁。反过来说，若锁定开局那张 signer，一个本可以在新证据下自然结束的会话
   会被无故切断——那才是真正的 bug。

### 13.3 为什么不选 (ii)/(iii)

- (ii)「只留记录」：它确实只在 AWS 已故障时出现，但代价是整场会话不可结算，而这正是「轮换期买家/卖家受影响」
  这一类问题里损失最大的一种（§11 表里 B 档有 5 分钟上界，会话没有）。
- (iii)「会话也加绝对时长上限」：与「unbounded work」的设计意图冲突，会杀掉合法的长会话。观察者切的是
  **证据的期限**，不是会话的长度——这个区别正是选 (i) 的理由。

### 13.4 影响

- **正常轮换下完全不触发。** 健康轮换在 deadline 前约 4m48s 已发布新 epoch，观察者醒来时 budget 重新变成
  小时级，重新武装，会话继续。它只在轮换落后时起作用，也就是 §11 B/C 档已经发生的那些时刻。
- 触发时：会话提前结束，收据是 **truncated**，`Price` 只按已交付字节收 volume（`hub/pricing.go:69-72`）
  ⇒ **provider 拿到它已经转发的那部分钱**，buyer 只为实际收到的字节付费。比「整场无证」严格更好。
- **无叶证据（模拟、harness）没有任何 deadline 可切**：`signingBudget` 返回 `bounded=false`，观察者直接
  等到会话结束。模拟与 harness 的行为一字不变。
- `Session.Receipt` 里的 `ErrAttestationStale`（`tee/service.go:1048`）降级为纯 fail-safe：切断失效、或不
  经 relay 直接驱动 `Session` 的调用者。注释已同步。

### 13.5 验证

- `go vet` 无输出；`go test ./shared/... ./tokenhive/...` 全绿；`go test -race ./tokenhive/tee/` 干净。
- 新增 `tee/session_deadline_test.go` 3 个：
  - provider **永不停流**时会话在 deadline 内被切断，并送出**可解码**的 truncated 收据，KeyID 指向被切的那个
    epoch，`ResponseBytes` 等于已交付字节。「能解码」本身就是「签得及时」的证明——`Receipt` 在 margin 内会拒绝；
  - 会话中途轮换到更晚到期的 epoch 后，跨过开局 epoch 原本的 deadline（睡 3s，长于其全部剩余余量）也**不被
    切断**，最终在 provider 自己的 EOF 上以 **complete** 收据结束，KeyID = 新 epoch；
  - 无可读叶的证据不产生任何切断（模拟/harness 的保证）。
- harness A/B（`/tmp` 干净 worktree，基线 `f86e511`）：18 场景 / 31 OK / 0 FAIL，断言逐行相同。
  **方法上的坑**：两次 harness 之间要留几秒间隔。背靠背连跑时上一轮的进程还没退净，场景 17/18 会出假 FAIL
  （session 被记到另一个 provider 名下、随后 `receipt sequence already stored`），与本类改动无关——单跑与
  留 8s 间隔重跑都是 31 OK / 0 FAIL 且断言逐行相同。

## 14. 恶意买家能否借轮换白嫖 token；AWS 故障时的止损现状（2026-09-22）

> 前提（题设）：**Hub 与 TEE 可信**。所以攻击面只剩一条——买家能不能让「收到了 token」与「记了一笔账」
> 脱钩。本节全部结论都对码验证过，行号以本节所引提交为准，定位请以函数名为准。

### 14.1 白嫖面 = 「拿不到可用收据」的出口集合

计费完全由收据驱动：请求路径 `hub/hub.go:544` 的 `Price(card, model, relayed, res.Receipt.Receipt)`，
会话路径 `hub/realtime.go:316`。两者都要求**先有一份验过的收据**，否则不结算。所以白嫖只有一种形态：

> **买家已经收到了字节，而 Hub 手里没有可用的收据。**

于是把代码里所有「拿不到收据」的出口列全，就穷尽了白嫖面。下面这张表就是穷举结果。

| 出口 | 位置 | 买家是否已收到字节 | 是否计费 | 谁能触发 |
|---|---|---|---|---|
| 退役连接 503 | `cmd/tee/rotated_connections.go` 的 `guard`，在 handler **之前** | 否 | 不计费（也无损失） | 轮换 |
| `ErrNoReceipt`：流结束但无收据帧 | `hub/tee.go:320` | **是** | **不计费** | 见 14.2 |
| `ErrTEERefused`：错误帧 | `hub/tee.go:318` | **是**（先到的 chunk 已写出） | **不计费** | 见 14.2 |
| 到 TEE 的 HTTP 请求被 abort | `hub/tee.go:191`（`ctx`）→ `:204` | **是** | **不计费** | 见 14.2 |
| 会话拿不到收据 | `hub/realtime.go:281-284` | **是** | **不计费** | 见 14.2 |
| `ErrSessionLimitExceeded` | `hub/realtime.go:272-278` | 是 | 不计费（注释明说是故意的：Hub 的计数与收据的摘要不可能对上） | — |
| 收据验证失败 / 流不匹配 / 价格溢出 | `hub/hub.go:513-556` | 是 | 不计费 | TEE 可信 ⇒ 不可达 |
| `MaxJobMicros` 超限 | `hub/hub.go:557-570` | **是** | **不计费**（有意政策） | 见 14.2 |
| `CompletionFailed` | 收据本身 | 否 | 不计费 | **正确**，见下 |
| 截断收据 | 收据本身 | 是 | **按量计费**（`pricing.go:94-105`） | **正确**，见下 |

**先说好消息，因为它把最重要的一格堵死了**：收据里的完成状态判得很干净——
`completion = CompletionFailed` 只在 `err != nil && !started && hasher.BytesWritten() == 0` 时成立
（`tee/service.go:685`），也就是「响应头没到、一个字节都没送出」；任何中途出错都落进
`case err != nil, truncated:` ⇒ `CompletionTruncated`（`:687-688`）⇒ `Price` 按已交付字节收 volume
（`pricing.go:94-105`）。**所以「收据在、金额却为 0」这条路是堵的**——除了 `delivered == 0` 那种真的
什么都没送到的情况。

**剩下的每一条，都是 Hub 这一侧主动放弃收据。** 所以问题变成：买家能不能触发那些放弃。

### 14.2 买家能触发的（真实白嫖面）

#### F1｜半途挂断 —— 最便宜的一条，`/v1/chat` 等所有 SSE 路由

链路（全部对码确认）：

1. `cmd/hub/serve.go:321` / `:326` 把 **`r.Context()`** 交给 `ExecuteForProvider/ExecuteForModel`；
2. `hub/hub.go:505` 用它派生 attempt ctx，`:508` 又把它交给 `h.tee.Execute`；
3. `hub/tee.go:191` 用它建到 TEE 的 HTTP 请求 —— **买家的连接与 Hub→TEE 的请求共享同一个取消源**；
4. 买家断开 ⇒ Go 的 `net/http` 取消 `r.Context()`（这是文档保证的行为：客户端连接关闭即取消）⇒
   **Hub 主动 abort 到 TEE 的请求** ⇒ `readSSE` 读到错误 ⇒ `receipt == ""` ⇒ `ErrNoReceipt`（`tee.go:320`）；
5. `hub/hub.go:509-511` 带着错误返回 ⇒ `serve.go:359` 那处注释自己写着 **"nothing settles"** ⇒ 不结算。

而 `onChunk` 早就把 chunk 写给了买家（`serve.go:310-318`，逐块 `Flush`），且 `readSSE` **故意忽略**
`onChunk` 的错误（`hub/tee.go:291` 的 `_ =`）——那是为了让 TEE 自己把流标成 truncated 并照常出收据。
**TEE 那边确实出了收据，只是这一侧已经没人读了。**

- **攻击**：读到自己想要的内容就掐断连接。**不需要抢在收据帧之前**——因为放弃收据的是 Hub 自己，不是竞态。
- **收益**：断点之前收到的**全部** token 免费。对长回答，前 90% 通常已经含全部有用内容；买家可以反复做。
- **成本**：一条 TCP 连接，外加放弃回答的尾巴。
- **与轮换无关**，且**不需要任何运气**。

#### F2｜把一次派发拖过 `-attempt-timeout`（默认 3 分钟）—— 同一条机制的第二个触发器

`hub/hub.go:505` 的 attempt ctx 超时 ⇒ 同样 abort ⇒ 同样「不计费但已交付」。`cmd/hub/main.go:88` 默认 3m，
**可设 0（无界）**。买家只要挑一个**流超过 3 分钟**的请求（长文生成、推理模型的思考期），就能白拿这 3 分钟
里的 token。完全由买家控制、可重复、无竞态。**F1 与 F2 是同一个根因的两种触发**：

> **Hub 把自己的请求生命周期与买家的连接绑死了。**

#### F3｜会话半途挂断 / provider 静默 —— WS（Realtime）路径

- `hub/realtime.go:261-267`：`ctx.Done()`（买家断开、或 `-session-timeout`，默认 10m）⇒
  `conn.Close()` 关掉到 TEE 的 WebSocket ⇒ `:281` 的 `conn.Receipt()` 必然拿不到 ⇒ `ErrNoReceiptForSession`
  ⇒ `SessionOutcome{}` 空返回 ⇒ **整场会话不结算**，而已转发的字节早就写给了买家。
- `hub/realtime.go:391`：Hub 自己的 `-session-idle`（默认 **30s**，比 TEE 侧的 5m 短、先打）也会
  `tunnel.Close()` ⇒ 同一路径 ⇒ **收据永远拿不到**。
  ⇒ **「让模型先吐几百 token、再长时间沉默」**（推理模型的常规行为）就是买家一个 prompt 能安排的事；
  那几百 token 免费。

#### F4｜会话跨过签名截止（**唯一与轮换有关的那条**）

§13 之后，会话在 live signer 进入签名 margin 前被主动切断 ⇒ **truncated 收据 ⇒ 按量计费**。
所以它**不再是白嫖，但变成了「免单」**：`pricing.go:94-105` 对 truncated 只收 volume，
**免掉 `PerRequestMicros + Premium`**（`:111-120` 只在 `CompletionComplete` 时才加）。

能不能被恶意利用？需要**会话活着跨过 deadline**。而 §13.2 第 2 点说明健康轮换会把 deadline 往后推，
所以窗口只在**轮换失败**时存在——而那时新请求已经在 `Execute` 入口被 fail-closed（`:445-452`），
被切的只可能是已经在跑的会话。**结论：最多是「轮换故障期间的一次性折扣」，不构成轮换期的白嫖。**
仍然值得记一笔：`Premium` 是模型溢价，对高价模型这一格不小。

#### F5｜`MaxJobMicros` 超限（只在配了该 flag 时）

`hub/hub.go:557-570`：买家应付超过单笔上限时，收据**照样存下来**（为了 provider 审计序列不断），
**但什么都不动**——不扣费、不计佣金、不结算，而 `Outcome.Chunks` 已经交付给买家。注释明说这是政策选择。
与「止损」直接冲突：**买家主动构造一个超过上限的请求就能免单**。而超上限本可以在派发前就算出来拒掉
（`BuyerPrice` 在调度里已经算过一次）。**建议改成派发前拒绝**，把「已执行但不计费」这条路彻底去掉。

### 14.3 轮换本身新增了白嫖面吗？——**没有**

把「有轮换」与「没轮换」的差异逐条列出来：

| 轮换带来的变化 | 是否新开白嫖面 |
|---|---|
| 退役空闲连接 → 503 | **否**。`guard` 在 handler 之前返回：没有 `ProviderSeq`、没有解凭据、没有 provider，`onChunk` 一个字节都没到（§12.3 已论证） |
| 换 receipt 签名 key | **否**。在途请求 pin 住自己的 signer；`ErrAttestationStale`（`tee/service.go:426`、`:447`）在序号与凭据之前拒 |
| 换 RA-TLS 叶 | **否**。Hub 侧 `-tee-verify attestation`，不 pin 具体叶，轮换后第一次重拨不会失败 |
| `signingBudget` 收紧交易所的结束时刻（§12） | **否，方向相反**：它把「执行完了却出不了收据」换成「早一点截断、出 truncated 收据、按量计费」 |
| §13 会话截止 | **否，同上**（按量计费），且只在轮换失败时触发 |
| （反例）签名前 fail-safe | `tee/service.go:753` 确实「执行完了、不出收据 ⇒ 不计费」。但它**只在 bound 失效时**才会响（transport 无视 ctx，或时钟跳变），而 bound 失效本身才是 bug —— 健康轮换永远走不到那一行 |

**所以：白嫖面在 Hub 侧，不在轮换侧。** §12/§13 这一串改动全部是在**减少**「执行了但结算不了」的窗口
（§12.1 的 deadline 窗口、§13 的整场会话），只是它管不到 Hub 自己放弃收据的那几条。上表的差异也说明，
**与其在轮换侧再收紧，不如把 F1–F3 修掉**——后者是买家随时可复现的，前者只在 AWS 已经故障时才出现。

### 14.4 AWS 故障时的止损：现在的边界在哪、缺在哪

| 故障 | 现状（对码） | 止损评价 |
|---|---|---|
| 轮换失败、叶未到期 | `Refresh` 失败但准入跑到叶自己的 `NotAfter`，照常服务 | 无损失（证据仍有效） |
| 轮换进 margin（§11 B 档） | `Execute` 拒（`service.go:445-452`，在序号之前）；会话被切但**按量计费** | **fail-closed ✓**：不产生「执行了却无凭据」的单 |
| 叶过期（§11 C 档） | `GetCertificate` 返 `ErrNotReady` ⇒ 握手全拒 | **fail-closed ✓**：连不上就没人能白嫖。代价是卖家零收入，不是漏钱 |
| **TEE 卡死**（进程活着但不响应） | 每条派发在 `-attempt-timeout` 后 abort；已 relay 的字节按 **F1 免费**；**没有任何熔断**，下一条请求照发 | **✗ 这里在漏**。漏的口径 ≈ `并发 × 3 分钟 × token 速率`，**在人工介入前不衰减** |
| **Hub 卡死** | 不服务 | 无漏钱 |
| TEE 到 fd/goroutine 上限 | 表现为慢与超时 | ✗ 同「卡死」行 |

**三个缺口，都不需要大改**：

1. **把「收据的采集」与「买家连接」解耦**（一处改动同时消掉 F1/F2/F3，且**不用碰 TEE**）：
   - SSE 侧：到 TEE 的那次调用不要挂在 `r.Context()` 上——`context.WithoutCancel(r.Context())`
     再只叠 `AttemptTimeout`（本仓库 `go.mod` 已是 go 1.27，`WithoutCancel` 可用）。买家走了就停止写给他
     （`onChunk` 返回错误，TEE 会把流标成 truncated），但**把收据读完并按已交付字节结算**。
   - 会话侧：`realtime.go:261-267` 的 `ctx.Done()` 分支改成**只关用户侧、不关隧道**，等收据到了再结算。
   - 这条的收益是**把「买家断开」从「免单」变成「按已交付字节计费」**，与轮换无关，但比轮换侧的任何收紧都值钱。
2. **加失败率熔断**：`hub/ledger.go:14-16` 已经有 `dispatched / verified / settled` 三个计数，但**没有出口**
   （`Hub.Ledger()` 只在进程内可读，没有 HTTP 端点、没有指标）。把 `dispatched − settled` 做成指标并设阈值
   （例如「最近 N 分钟结算率 < X% 就拒绝新派发」），这是「TEE 卡死」那一档**唯一能自动止损**的手段。
   注意它只反映「有没有结算」，不反映「有没有泄露字节」，阈值要按业务定。
3. **`MaxJobMicros` 改派发前拒绝**（见 F5），去掉「执行了但不计费」这条政策性口子。

> 有个方向性提醒：`AttemptTimeout`（Hub 3m）与 `-request-timeout`（TEE 2m）都改不了 F1/F2，
> 因为根因不是超时太短，而是**超时之后 Hub 丢掉收据**。把超时调长只会让漏得更多。

### 14.5 一个必须写下来的账务口径

上面所有白嫖路径的共同后果是：**provider 的上游额度被消耗，Hub 记为 0 收入，provider 记为 0 应收。**
也就是说**损失落在卖家与 Hub 的应收上，而不在买家的预付余额上**——买家的余额在这些路径上完全不减。

所以 **prepaid-only 不构成防线**：它防的是「没钱还想用」，防不了「用了不记账」。要真正止损，
必须让**记账不依赖买家是否还在线上**（这正是 14.4 第 1 条）。

### 14.6 建议优先级

1. **F1/F2/F3 一起修**（Hub 侧一处改动，三个洞）：收据的采集与买家连接解耦。
2. **F5**：`MaxJobMicros` 改派发前拒绝。
3. **止损可观测性**：`dispatched/settled` 变成指标 + 熔断阈值（对付 TEE 卡死）。
4. 轮换侧：无需再动。

## 15. 换 TEE 的标准流程（双机拓扑实测，2026-09-22）

滚动记录，不是提案。拓扑：TEE 是 `tokenhive/cloudtest` 起的 SEV-SNP 实例（无 sshd），Hub 在**另一台普通主机**
上跑 `tokhive-mvp` 的 `bin/hive`（tmux 会话 `tokhive`）。Hub 侧**不改代码**，只改 `/etc/tokhive/hive.env`。

```bash
# 0. 前提：Docker daemon 要在跑（AMI 构建用）
docker info >/dev/null || open -a Docker

# 1. 从当前工作树重建 AMI（约 13–17 分钟）
cd tokenhive/cloudtest/snp && ./crosshost.sh build

# 2. 读新 digest —— 必须每次重新读，不能沿用上一次的值
grep SNP_T_DIGEST ../../../deploy/snp-digests.env

# 3. 核对待部署的代码真的进了包（digest 变了不代表代码进去了）
tar -xf ../bin/tokenhive-app-bundle.tar -C /tmp/chk app
strings /tmp/chk/app | grep -o '<本次改动引入的符号名>' | sort -u

# 4. 起新 TEE（--host-ip 是 Hub 的私网地址，即 TEE 眼中 relay 的目标）
#    --new = 另起一台，旧的那台**继续跑**，只把它的记录挪到 `superseded`
./crosshost.sh up --tee-only --host-ip 10.0.1.151 --new
cat ../crosshost.json          # 取新 private_ip 与 app_hash（tee 键始终是新的那台）

# 5. 等新 enclave 起来（旧 TEE 此时仍在服务，这段等待不占停机窗口）
./crosshost.sh verify          # dump 记录里那台 tee 的串口（已带 Latest=True）
#    期望：policy hash bound / 146 anchors / listening on https://0.0.0.0:18090
#          / next refresh in 2h

# 6. 改 Hub 的三项并重启（见下）—— 到这里服务才切过去，旧 TEE 全程活着
ssh -i ssh-key.pem ubuntu@52.215.235.214 'sudo -e /etc/tokhive/hive.env'   # 只改这三行
#   HIVE_TEE_ENDPOINT=https://<新私网 IP>:18090/v1/execute
#   HIVE_TEE_EXPECTED_APP=snp-app:<新 digest>
#   HIVE_RELAY_ALLOWED_CIDRS=<新私网 IP>/32      ← 收窄到 TEE，换 TEE 必改，否则 relay 拒绝拨入
kill $(pgrep -x hive)                          # Ctrl-C 无效
tmux send-keys -t tokhive:0.0 "set -a; . /etc/tokhive/hive.env; set +a; HIVE_DEBUG=1 ./hive" Enter

# 7. 启动判据三行齐（下一步）之后，才退役旧 TEE
./crosshost.sh down --superseded --dry-run     # 只列，不删
./crosshost.sh down --superseded               # 只删 `superseded` 里记录的那几台
```

**为什么不再需要「先 down、等 terminated、再 up」**：`up --new` 从不终止任何实例，只把旧的记录
从 `tee` 挪到 `superseded`（见 §16）。所以新 TEE 的启动（约 2–3 分钟 attest）和旧 TEE 的退役之间
没有任何耦合，操作者也不必等 EC2 的 termination（实测约 4 分钟）——那 4 分钟是纯等待，现在并进了
新机的启动时间里。旧 TEE 在 Hub 被重指之前一直能服务，因此**不存在两台都不可用的窗口**。

严格说这不是「请求零中断」：重启 Hub 那一瞬仍在飞行中的请求会断（§14.4 fail-closed，不漏 token），
且在旧 TEE 上尚未结束的会话也不会迁到新 TEE。被消除的是**操作者的等待**与**无 TEE 可用的窗口**。

**启动成功的判据（三行齐 = mTLS 通且 attestation 校验通过）**：

```
INFO TEE deployment configured endpoint=… expected_app=snp-app:<新 digest>
INFO TEE inbox key key_id=<新 key id>            ← 出现这行就说明 RA-TLS 握手 + 证据校验都过了
WARN Relay serves plaintext address=…:18085 sources=<新私网 IP>/32
```

若第二行变成 `WARN TEE inbox key unavailable … tls: internal error`，见 §10 / §11.3 C 档。

### 15.1 本次踩到的两个坑（都会静默产出错误状态）

1. **`crosshost.sh down` 之后必须等实例真的 `terminated` 才能 `up`。** 在 `shutting-down` 期间跑的 `up`
   会把它判成「可复用」，于是**不启动新实例**，而是把**新 digest 盖到死实例的记录上**并打印一行看起来
   完全正常的 `reusing confidential tee i-…`（本次实测）。后果是 `crosshost.json` 里留着死实例 id + 新 digest。
   处置：`down --tee-only` → 轮询到 `terminated`（本次约 4 分钟）→ `up`；若已经中招，先备份并把
   `crosshost.json` 里的 `tee` 键删掉（变成 `{}`）再 `up`，强制走启动路径。
   **已由 §16 修掉**：可复用状态收窄为 `pending`/`running`，`shutting-down`/`stopping`/`stopped`
   一律不采纳（会打印实际状态并另起一台）。同时 §16 的 `--new` 让「先 down 再 up」这个顺序本身
   不再是必需动作。
2. **`deploy/snp-digests.env` 里的 `COMMIT=` 在 crosshost 流程里不可信。** `crosshost.sh build` 是先用
   `pack.sh` 从**工作树**打出 bundle，再以 `SNP_EXTERNAL_BUNDLE` 交给 `deploy/snp-build.sh` 原样采用；
   而 `snp-build.sh` 的 `record_digest_env` 记的是它自己认定的 `BUILD_COMMIT`（来自
   `deploy/image-history.json` 里最后一条 `app_images`），在 crosshost 路径下与产出 bundle 的工作树
   **无关**（本次它写着 `COMMIT=cfe3720`，而 bundle 里明明是 `cfe3720` 之后 7 个提交的代码）。
   ⇒ **判断"代码有没有进包"只能靠 `strings <bundle>/app | grep <符号名>`**，digest 与 COMMIT 都不行。
   （`SNP_T_DIGEST` 本身是可信的：它是从 AMI 的 `snp-app` tag 读回来的。）

### 15.2 换 TEE 的连带影响（必读）

- **inbox key 会换**（进程启动时生成一次，见 §11.1）⇒ 所有 **provider agent 必须重新注册凭据**；
  Hub 里那些封给旧 key 的信封对新 TEE 无法打开。agent 每次重连都会经 Hub 重新拉 inbox key
  （`hub/tee.go` 的 `CredentialKey` 每次现取不缓存），所以**等它自然重连即可**，不必手工干预。
- 换 TEE **不是**轮换：轮换什么都不用做（§11.5）。
- 换 TEE 期间 Hub 处于 fail-closed（连不上 TEE）⇒ 无服务、无收入，但**也不漏 token**（§14.4）。
  这段窗口现在只剩「重启 Hub 到它连上新 TEE」这一小段：旧 TEE 在退役前一直可用（§16）。

## 16. 实施记录（九）：换 TEE 不必等旧机终止（2026-09-22）

§15 的旧流程是「`down --tee-only` → 轮询到 `terminated`（实测约 4 分钟）→ `up`」。那 4 分钟是纯等待：
它既不提供服务，也不提供新代码，只是 AWS 回收网卡的时间；而 §15.1 那个「在 `shutting-down` 期间 `up`
会被判成可复用」的坑，正是这种「先删后建」顺序逼出来的。本次把顺序反过来：**先建、再切、最后删**。

### 16.1 改动清单

| 位置 | 改动 |
| --- | --- |
| `snp/crosshost.py` | 新增 `--new`：即使 `tee` 记录里的实例仍在跑，也另起一台，并把旧记录**移**到 `state["superseded"]`（附 `superseded_at`），旧实例保持运行。 |
| `snp/crosshost.py` | 可复用状态从「`!= terminated`」收窄为 `REUSABLE_STATES = ("pending","running")`，决策函数 `adoptable(record, state)` / `recorded_state(ec2, record)` 独立出来，可离线单测。 |
| `snp/crosshost.py` | `describe()` 现在吸收 `InvalidInstanceID.NotFound/Malformed` 为 `{}`（超过 AWS 保留窗口的实例不是「空结果」而是报错），其余错误照旧上抛。 |
| `snp/retire.py`（新增） | 只终止 `superseded` 记录的实例。`down --superseded` 调它。 |
| `snp/crosshost.sh` | `up --new` 透传；新增 `down --superseded [--dry-run]`（与 `--tee-only` 互斥）；`dump_tee_console` 补 `Latest=True`（§15 第 5 步的串口检查此前拿的是旧缓冲，会把「起来后没日志」误判成「启动失败」）。 |
| `cloudtest/tests/test_unit.py` | +4 组（`OwnershipTest`/`DescribeAbsenceTest`/`SupersedeTest`/`RetireSafetyTest`）；cloudtest 套件 30→34 个测试。 |
| `snp/tests/test_crosshost.py` | +`SwapWiringTest`：`up --new` 真的把标志透传下去、`down --superseded` 走 `retire.py` 且那条路径上不可达 `delete.py`、串口 dump 带 `Latest=True`；snp 套件 27→31 个测试。 |

### 16.2 两条不变量（这是「不会误删机器」的落点）

1. **`crosshost.py` 永不终止任何实例。** 它只 `run_instances` 与写状态文件；`from aws import` 里没有
   `terminate`。有一条测试直接读源码断言这一点，所以这不是承诺，是被 CI 钉住的形状。
   推论：任何 `up`（含 `--new`）都不可能毁掉它正在替换的那台机器。
2. **`retire.py` 的目标集合只能来自 `superseded` 记录。** 它不按 tag 枚举、不把 `tee`/`host` 当候选，
   因此坏掉的状态文件只能让它**少删**，不能让它多删。逐个候选再查一遍：实例存在 → 同时带两个
   cloudtest tag → 不等于当前 tee / 当前 host；任一不满足就 `Refused` 并**整体停下**。`--dry-run`
   与真实运行走同一组门（所以 dry-run 能提前暴露拒绝理由），只是不删也不清记录。

### 16.3 退役的前置条件：先有活着的接替者

`down --superseded` 要求当前 `tee` 有记录**且状态为 `running`**，否则拒绝执行。这是把
「新 TEE 正常启动完成、Hub 指向新 TEE 之后再删旧 TEE」从口头纪律变成机器检查——否则「新机悄悄死了，
操作者照样退役旧机」会以「一台 TEE 都不剩」收场。

能看见的部分到此为止：**Hub 是否真的重指过，这一侧看不见**（Hub 在别人的机器上，接口在
`crosshost.sh` 之外），所以程序在输出里明说这一点，而不是假装检查过。仍未消除的残余风险只有
「Hub 还指着旧 TEE 就把旧 TEE 删了」——那是可用性事故，不是数据事故：Hub 立刻 fail-closed，不漏 token
（§14.4），重新 `up --new` 一次即可。

### 16.4 换机失败时怎么退回去

顺序换过来之后，回退也是对称的：Hub 不重指（或指回旧私网 IP），然后删掉新那台——

```bash
./crosshost.sh down --tee-only     # 删的是 crosshost.json 里的 tee，也就是新那台
```

`down --tee-only` 只按记录删当前 tee，不碰 `superseded`，所以仍存活的旧 TEE 不受影响、继续服务。
代价是状态文件里「正在服务的那台」此刻被记在 `superseded` 下（名字确实反了）：把它手工挪回
`tee` 键（顺手删掉 `superseded_at`）即可。这只是让下一次 `up` 的判断准确，不影响正在跑的机器。

### 16.5 实测（本机，无 AWS）

`tests/test_unit.py` 34 个测试全绿。另外用一个假 EC2 客户端把状态机整条走了一遍
（脚本在 /tmp，未入库）：

- 连续两次 `--new`：`superseded` = `[i-new1, i-new2]`，两台都仍 `running`，`tee` = 最新那台；
- 记录里的实例处于 `shutting-down` 时 `up`（无 `--new`）：打印
  `recorded tee i-new3 is shutting-down; not adoptable, launching fresh` 并**另起一台**，
  §15.1 那个静默坑不再成立；
- `retire.py`：dry-run 只列不删；真实运行只把 `i-new1`/`i-new2` 置为 `terminated`，
  当前 tee 与另一个 operator 的实例（tag 的 user 不同）都保持 `running`，随后把两条记录清掉
  → 再跑一次是空操作。

**尚未在真实 AWS 上验证**：`--new` 走完真实 `run_instances`、以及 `down --superseded` 打到真实实例。
两者都是纯参数/权限路径的第一次实战，下次换 TEE 时按 §15 走一遍即可覆盖。

## 17. 决策记录：「只在对话结束时证明」能达成什么，不能达成什么（2026-09-22）

> 本节是**复核记录，未改代码**。它回答的是"能不能撤掉请求侧的证明，只在收尾时签名"，以及这样做的
> 代价落在哪里。四条判据都对着代码查过，行号写本节时是准的。

### 17.1 先把"证明"分四处，它们撤掉的后果完全不同

| # | 落在哪 | 代码 | 撤掉会怎样 |
| --- | --- | --- | --- |
| ① | 连接建立 | Hub 侧 `VerifyRATLSPeer`（`cmd/hub/main.go:513`），握手完成**前**校验叶证据 + `-expected-app` | **不能撤**：`ExecuteRequest.Body` 就是买家 prompt 明文，而 `h.verify` 在字节交付**之后**（`hub.go:508→513`，chunk 经 `onChunk` 边收边转）⇒ 冒充者可交付内容却签不出收据 |
| ② | 请求受理 | `service.go:426` `signerStaleAt` + `:445-452` `budget<=0`/`context.WithTimeout`；`OpenSession` 同款 | 撤掉能让健康轮换零感知，但打开 17.4 的洞 |
| ③ | 请求落在已退役连接 | `epochConnections.guard` 503 + `EpochRetiredHeader` | 撤掉**不改善买家感知**：Hub 已在这个标记上重试一次（`hub/tee.go:180`），且受理时会 pin 那条连接的 epoch（`rotated_connections.go:44-48`）|
| ④ | 响应开头 | `EventStart` + `ResponseHeadersHash` + `receiptMatchesStart`（`hub.go:530`） | **不能撤**：Hub 在拿到收据**之前**就把买家的 HTTP 状态提交了（`schedule.go`，`serve.go:352`），撤掉"给买家看的 200"与"计费依据的状态"不再可证同源 |

### 17.2 「不一致」到底是哪两半不一致

不是"开头的证明"与"结尾的证明"，而是 **收据上署名的 epoch** 与 **承载这份收据的那条 TLS 连接在握手时证明的 epoch**。
连接一直都在，不会因为你不在开头检查就消失。今天交换路径上这两半是**一致的**，而且不是靠 ②，是靠：

1. `epochConnections.guard`（`rotated_connections.go:95`）比较"连接盖的 epoch 计数器"与 `current`，所以通过它的请求，
   其连接 epoch 必等于 `current`；
2. `Service.Execute`（`service.go:422`）pin 的 `signer := s.activeSigner()` 于是必然就是那个 epoch 的 signer。

`identity.KeyID` 与连接证书的 SPKI 是同一个值：`buildEpoch` 断言 `sha256(PublicKeyDER) == snapshot.SPKIHash()`
（`adapter.go:255-263`），而 SPKI 就是 `RATLSManager` 每次 `Refresh` 现生成、写进证书的那把钥匙（`ratls_manager.go:94-98`）。

### 17.3 两端各自压着一条要求，而它们会在跨轮换时打架

- **收据可结算** ⇒ 署名 epoch 的叶在 **Hub 验证时**仍未过期。`verifyNitroChain` 的 `leaf.Verify`
  （`shared/snp_combined_aws.go:380`）没传 `CurrentTime`，Go 用 `time.Now()`。
- **配对成立** ⇒ 署名 epoch 必须等于连接握手时的那个 epoch。

一个跨过轮换的在途请求同时压着这两条：**不换手**（用旧 epoch 签）⇒ 旧叶可能已过期 ⇒ Hub 拒收 ⇒ 免费；
**换手**（用 `activeSigner()`）⇒ 新叶有效 ⇒ 可结算，但配对为假。这就是今天的二选一，也是 §12 的
`signingBudget` 与 §13 的会话切断存在的原因——它们把"两条都不满足"变成"提前截断、按已交付字节可结算"。

### 17.4 「只在结尾证明」字面上的结果

| 目标 | 结论 |
| --- | --- |
| 健康轮换下买家无感 | **达成**——但对"把轮换瞄准点挪到重签窗口"（§B-1）的边际收益为 **0**：门限读的是 `activeSigner()`，轮换在重签窗口内落地后，那道门永远不会触发 |
| 不出现"开头与结尾证书不一致" | **不达成**，而且这正是制造不一致的那个动作（见 17.2 的图） |
| 轮换失败时"某些对话免费 + 发不起新对话" | **不达成**：得到的是**无限期免费服务**，理由见下 |

最后一条的三个代码事实：

1. `guard` 只比 **epoch 计数器**（`rotated_connections.go:95`），而 `current` 只在 `rotate()`（`:159`）里 +1；
2. `rotate()` 只从 `serviceRuntime.adopt`（`ratls_refresh.go:179`）调用，而 `adopt` 只在平台给出**更新**的
   epoch 时才会走到（`adapter.go:217` 的 `supersedes`）；
3. ⇒ **轮换一直失败 ⇒ `rotate()` 从不调用 ⇒ 门恒开**；而 `Adapter.ServerTLSConfig().GetCertificate`
   （`adapter.go:147-157`）的 `ErrNotReady` **只在新握手时生效**，已建立的连接不再经过它。Hub 的传输层是
   `&http.Transport{TLSClientConfig: teeTLS}`（`cmd/hub/main.go:135`），**没设 `IdleConnTimeout`**，Go 零值语义是
   "no limit" ⇒ 池里那条连接不会被空闲回收。

于是"后续买家无法发起新对话"恰好不成立：新握手确实失败，但 Hub 手上那条老连接继续被服务，
**每一条都是完整交付、永不结算**，条数与时长都不封顶。

### 17.5 三个附带洞（与钱无关，但都是真实的）

1. **"已交付但未签名"在线上没有类型。** 它只能靠 `ErrTEERefused` 之类的字符串匹配被识别；任何验签回归都会
   静默变成赠送。顺带一个独立缺陷：`serve.go:352-378` 的 `truncated` 判定要求 `err == nil`，所以 `h.verify`
   失败时反而会走到 `:368` 补一个 `data: [DONE]`——**错误帧之后还有终止符**，只看 `[DONE]` 的客户端会把半截
   答案当成完整答案。
2. **provider 的序号账本。** `service.go:436-438` 自陈：一个领了号却从未执行的作业，是 provider **无法与
   "Hub 隐藏了一次执行"区分**的缺口。撤掉 ② 之后，整个故障期都是这种缺口。
3. **provider 白干。** 收款以收据为凭，所以不结算的损失落在 provider 与 Hub 应收上，买家的预付余额并不减少。

另外会话不能顺手一起撤：会话无自然结束点（`SessionIdleTimeout` 是看门狗不是时长上限），撤掉
`watchSigningDeadline` 之后故障期会话可免费跑到任意长，且没有止损点。

### 17.6 要同时达成三件事的形态

方向是对的，落点要换：**不要撤"受理时的证明"，要撤"签名侧的新鲜度门限"，把那唯一的一道门放到连接上。**

- **方案 S（不改 Hub）**
  1. 退役条件从"轮换成功"改成"**证据过期**"（按 `epoch.admissibleUntil`，且只在连接空闲时关——`track` 已经是
     这个形状）。这一条同时买下"轮换失败 ⇒ 新对话发不起来"与"没有无限期免费服务"。
  2. 收据用**承载它的那条连接的 epoch** 签（`accept` 已经把 epoch 盖进连接上下文，现在只存了计数器，
     改成存 epoch 本身）；`pin` 从"受理时的 `activeSigner()`"换成"连接 stamp 的 epoch"，配对由构造保证。
  3. 轮换瞄准 `SNPAdmissionDeadline − 重签窗口`（`ratls_refresh.go:287`），否则 `[D, N]` 这 5 分钟内签出的收据
     注定过旧 ⇒ **每周期 5 分钟固定免费**。
  4. 删掉请求级 `signerStaleAt` / `signingBudget` / `:450` 那个把 deadline 装在 `D−1s` 的 `context.WithTimeout`。
  - 残余：跨过 NotAfter 的在途交换会产出 Hub 拒收的收据 ⇒ 免费。有界（只在途、只在跨线那批），这正是
    "允许不计费"能买到的边界。健康轮换下它接近于零（轮换落在重签窗口后，在服务的 epoch 总有 ≳9m 的余量）。
- **方案 C（= S + 改 Hub）**：Hub 比对 `receipt.AttestationRef.KeyID` 与**连接证书的 SPKI**，并且不再对收据里的叶
  按 `now` 判（新鲜度只在握手判 + 连接寿命上限）。于是 17.6 的残余也消失。
  注意今天 `hub.Hub.verify` 的签名是 `func(proof.SignedReceipt) error`（`hub.go:232`）——**结构上拿不到连接**，
  所以配对不是"没人想查"，是"没人能查"。
- **方案 C 的代价**：收据不再能脱离连接自证（第三方要查配对，本来也需要保留连接证据）；需要给 Hub 的连接
  加寿命上限，让"多久重新证明一次"重新有个节拍。

结论：**如果短期不动 Hub，就做 S；S 删掉的机制比它加的多，而且三条目标都达成。C 是终局形态。**

## 18. 决策记录：Hub 自己计费，能否取代 TEE 的受理证明（2026-09-22）

> 复核记录，**未改代码**。问题：「Hub 是我自己部署的，我把 Hub 的计费规则改成'TEE 证明缺失时也照常计费'，
> 这时能撤掉请求受理（交换开始）的证明吗？」

### 18.1 结论

**能，而且只有当你同时放弃"按次计费"时才自洽。** 真正的分界线不是签名，而是收据里的 `Completion`——
它是唯一一个 Hub 无论怎么观察自己都得不到的字段（18.3）。因此：

| 形态 | 收据是否必需 | ② 能否撤 |
| --- | --- | --- |
| 保价目（flat fee + premium 仍在） | **必需**（`Completion` 只此一处） | 不能 |
| 纯字节计价（只算 volume） | 不需要 | 能，且 `guard`/`rotate`/Hub 重试一族也可一并撤 |

撤 ② 单独做、不改计费口径，则回到 §17.4 的判词（无界免费 + 唯一健康信号消失）。

### 18.2 今天的结算链是"收据形状"的

`Hub.Execute`（`hub/hub.go:508-600`）依次做六件事，**没有一步可以跳过收据**：

| 步骤 | 位置 | 输入 |
| --- | --- | --- |
| 验签 + 度量 pin | `:513` `h.verify(res.Receipt)` | `proof.SignedReceipt` |
| 字节绑定 | `:518` `MatchesStream(res.Chunks)` | 收据的 `StreamHash` |
| 响应头绑定 | `:530` `receiptMatchesStart(...)` | 收据的 `ResponseHeadersHash` + `StatusCode` |
| 定价 | `:544` `Price(card, model, relayed, receipt)` | 见 18.3 |
| 落库（provider 的对账凭据） | `:587` `store.Put(provider, receipt)` | `ProviderSeq` |
| 幂等结算 | `:597` `claimSettlement(receipt.JobID)` | 收据的 `JobID` |

而 `readSSE` 的收尾（`hub/tee.go:315-322`）已经把"没有收据"当成硬错误：`receipt == ""` ⇒ `ErrNoReceipt`。
所以「允许证明缺失时计费」不是改一条规则，是**再建一条结算通路**。

### 18.3 定价的四个量里，Hub 手里有三个

`Price`（`hub/pricing.go:79-121`）只用四个量，前三个 Hub 都能自己观测：

| 量 | 收据里的来源 | Hub 能否自证 |
| --- | --- | --- |
| `relayed`（交付的响应字节） | —（收据不提供） | **能**：Hub 自己累加收到的 chunk（`hub.go:540-543`），并用它给 `Price` |
| `RequestBytes` | 收据字段 | **能**：body 就是 Hub 自己构造并发出去的（`len(body)`），`MatchesBody` 已在校验它 |
| `StatusCode` | 收据字段 | **能**：`res.Status` 来自 start 帧，Hub 已经用它提交了自己的响应（`receiptMatchesStart` 就是拿它去对） |
| `ResponseBytes` | 收据字段 | **能**（近似）：真值是 `min(ResponseBytes, relayed)`（`:90-93`），而 TEE 会整块丢弃越过 `MaxResponseBytes` 的 chunk ⇒ `relayed ≤ ResponseBytes` 常态成立 |
| **`Completion`** | 收据字段 | **不能** |
| `AttestationRef` / `PolicyHash` / `ProviderSeq` | 收据字段 | **不能**、**不能**、**不能** |

#### 为什么 `Completion` 不可自证（这是本节的落点）

`Completion` 是 TEE 自己的裁决（`tee/service.go:683-689`）：

- `CompletionFailed`（`err != nil && !started && 零字节`）——Hub 也能看出（没 start 帧、没字节）；
- **`CompletionTruncated`（`err != nil` 或 relay 侧被截断）**——provider 已经答了 200、body 中途死掉；
- `CompletionComplete`。

关键在于：**provider 中途死亡时，`Service.Execute` 返回的是 `err == nil` 的 Result + 一份
`CompletionTruncated` 的收据**（`:761-776`）。也就是说，在线上**没有 error 帧**，Hub 的 `readSSE` 只看到流结束。
"答了 200 然后死在 body 中间"与"正常完成"在 Hub 眼里完全同形，**唯一能区分它们的证人就是收据里那一个字段**
——`cmd/hub/serve.go:352-353` 正是这么用的，`Billable`（`pricing.go:34-42`）与 `Price` 的 flat fee/premium
（`:111-120`）也都以它为门。

反过来，**轮换造成的切断在线上是可见的**：`ErrAttestationStale` 是 `Execute` 明确记录的例外
（`service.go:407-412`），`ServeExecute` 会写出 `event: error` 帧（`rpc.go:182-185`），Hub 收到
`ErrTEERefused`（`hub/tee.go:318`）。所以——

> **「按观察计费」的过度收费风险并不来自轮换，而来自你扔掉了 `body 中途截断` 的唯一证人。**

这条很重要，因为它把"撤 ② 的代价"和"改成观察计费的代价"彻底分开了：前者是止损问题（§17.4），后者是
**计费正确性**问题，且与轮换无关，今天就在。

唯一朴素的绕法是让 Hub 嗅 SSE 终止符（比如 OpenAI 的 `data: [DONE]`）。三个理由说它不行：三种 wire format
各要一份解析；mock upstream 本来就不发 `[DONE]`（`serve.go:369-370` 的注释自己写着）；而且这恰恰是收据
存在的目的——用**被执行方签署的裁决**取代**客户端启发式**。

### 18.4 两种自洽形态

**形态 1（保价目）**：`Price` 的 `PerRequestMicros` + `Premium` 需要 `CompletionComplete` 才成立 ⇒ 必须有收据
⇒ ② 必须留。**今天的形态，无需改动。**

**形态 2（纯字节计价）**：只保留 `volumes × PerMegabyteMicros`（`pricing.go:101-109`），停用 flat fee/premium。
此时定价只用 `relayed` 与 `RequestBytes`，两者 Hub 都有 ⇒ **收据可以完全不要** ⇒ ② 可撤，
`guard`/`rotate`/Hub 重试一族（§11–§13 那批）也可一并撤，因为不再有任何东西要求"签名时的新鲜度"。

形态 2 必须显式接受的代价：

1. **provider 失去对账锚。** `ProviderSeq` 的全部价值就是让 provider 发现"Hub 藏了一次执行"
   （`hub/store.go:130-139` 的注释：持有 1 与 3 就知道至少被用了三次）。不收据 ⇒ 这个能力消失，
   provider 只能信 Hub 的账本。
2. **买家失去"这次交付来自被度量镜像"的可查证性。** 注意**本仓库里买家本来也拿不到收据**：`cmd/hub/serve.go`
   全文没有暴露收据的出口，收据只出现在 Hub 内部与 provider 侧的 `-audit`（`cmd/hub/main.go:95,139,363-395`）。
   所以对买家而言，这次改动只是把"Hub 能证明"降级为"Hub 这么说"。
3. **每周期固定损失 flat fee/premium**（轮换窗口内那批），这与 §12 已记录的情况相同。

### 18.5 建议

- **只想让买家无感** ⇒ 做 B-1（把轮换瞄准重签窗口）。② 读的是 `activeSigner()`，届时永不触发；
  收据仍有效、配对不破、产品不变。这是最省的一条。
- **真想不再要求 TEE 证明** ⇒ 走形态 2，但要显式承认"计费 = 运营方自己的仪表，证明是尽力而为的证据"，
  并把收据 store/audit 的故事一并收掉。留着一套不再被任何东西信任的机器，是 §17.5 说的守一半。
- **不要做的**：留着收据、又允许缺收据时计费。那是两边的成本都付——既要维护签名/证明链，又已经放弃了
  它要买的东西（计费正确性与可对账性）。

## 19. 实施记录（十）：方案 B —— 把轮换挪进重签窗口，并在签名处换手（2026-09-22）

> 本节是**实施记录**，对应提交见 `git log` 本条消息。改动只落在两个文件：
> `tokenhive/cmd/tee/ratls_refresh.go`（节奏）与 `tokenhive/tee/service.go`（受理门与签名）。
> 计费口径、Hub、Policy 一律未动。

### 19.1 三条改动

| # | 改动 | 位置 | 消掉 §11 的哪一格 |
| --- | --- | --- | --- |
| **B-1** | 轮换瞄准点从 `SNPSigningDeadline`（= NotAfter − 5m，记为 D）移到 `SNPAdmissionDeadline − snpRotationLead`（NotAfter − 9m） | `nextRefreshDelay` | ③ 洞期新请求 502、④ 会话被切 |
| **B-2** | `perform` 末尾的复查从"越线即拒签"改成"越线则换手到 `activeSigner()`，两个都越线才拒" | `Service.perform` | ① 在途交换被切断、② 该交换结算不到 |
| **B-3** | 删掉 `Execute` 里贯穿整个交换的 `context.WithTimeout(budget)`（受理处的 `budget <= 0` 拒绝保留） | `Service.Execute` | ① 的那把刀本身 |

同时把 `snpReissueWindow = 9m48s` 抽成一个具名常量：它原来只在 `minRefreshFloor` 的注释里以散文形式出现，
现在 `snpRotationLead`、`minRefreshFloor` 两条不变量与一条测试都以它为参照，写一次而不是抄三遍。

### 19.2 为什么 B-1 让 ③④ **消失**，而不是只变窄

关键在于这两个判定读的都是**当前活着的** signer，而不是启动时固化的常数：

- `signingBudget` = `signingDeadline(activeSigner()) − now − signingHandoff`；
- `activeSigner()` 读 `signerCell`，而 `serviceRuntime.adopt` 的顺序是**先写 cell、再换 service 指针、最后 `conns.rotate()`**。

所以"一次轮换落地"等于这两个判定用的坐标系整体后移一个叶寿命。轮换若落在 D **之前**，D 到来时活着的 signer
已经是新的，`budget ≈ 2h50m` ⇒ **③ 那个洞根本没有形成**。

④ 更直接：`watchSigningDeadline` 每轮醒来都**重读 `activeSigner()` 并按新的 budget 重新睡**（它的注释自己写明了
这个意图）。旧代码之所以会切会话，唯一原因是 `nextRefreshDelay` **故意把轮换排在 D 那一刻**——比 watcher 的
唤醒（D−1s）晚一秒。B-1 取消的是这个错误排序，`watchSigningDeadline` 一行没动。

**为什么旧方案必然给自己挖这个洞**：AWS 的 NitroTPM 叶由平台按自己的节拍重签。实测周期恒定 2h50m13s、叶寿命 3h
⇒ 重签时刻落在 `NotAfter − ~9m47s`，我们只能在"平台已经换过"之后才拿得到新叶。旧方案偏偏在 `D = NotAfter − 5m`
才去问——**它把自己唯一的轮换机会排在了平台重签点之后 4m47s**，而新的 epoch 落地必然还要一个 attestation 往返，
于是每周期稳定出现一段"活着的 signer 已越线"的时间。瞄准 9m 之后，第一次尝试落在平台重签点之后约 47 秒（即
`9m48s` 这个窗口的内侧 ~48s 处），**余量正是留给测量本身的秒级粒度**；2m 的 floor 让重试落在 N−7m、N−5m，
其中前两次在 D 之前，后一次刚好压在 D 上。

### 19.3 为什么 ①② 必须靠换手（提前解决不了）

在窗口左端之前受理的请求，它的 pinned signer 的余量天生就短（受理于 `N−12m` ⇒ 只有约 6m59s），这一点**不随瞄准
点改变**。所以即使 B-1 落地，"跨过 D 的在途交换"依然存在——只是从"每个周期都有"变成"轮换失败时才有"。
于是两条改动缺一不可：只删 timeout ⇒ 末端的复查仍然拒签；只换手 ⇒ 那把刀仍然会在 D−1s 把交换切成半截。

换手不能解决的那条硬约束是：**收据必须能被 Hub 接受**，而 Hub 的叶链校验按**验证者自己的时钟**判
（`verifyNitroChain` 的 `leaf.Verify` 不传 `CurrentTime`，Go 用 `time.Now()`）。换手挑的是"尚未越线"的 signer，
即其叶至少还有 `SNPSigningMargin` 有效期，所以这条约束自动满足。

"两个都越线才拒"保留下来，正是**轮换失败**的情形：pinned 与 live 是同一把 key，fail-closed 与旧行为一致。

### 19.4 代价：跨轮换那一批收据的配对失效（唯一一条）

跨过轮换的交换，其 **`AttestationRef.KeyID` 与承载它的那条 TLS 连接证书不再是同一把 key**。

**为什么今天没有任何验证方会因此拒收**（这三条都是对码复核过的）：

1. `hub.Hub.verify` 的类型是 `func(proof.SignedReceipt) error`（`hub/hub.go:232` 的字段、`:91` 的 `Config.Verify`）
   ——**结构上拿不到连接**，所以"配对"不是没人想查，是没人能查。
2. Hub 对**握手**与**收据**用的是同一个 `-expected-app` pin（`cmd/hub/main.go` 的 `buildTEEClientTLS` 与
   `buildVerifier`）：比的是"这是不是那个被度量的镜像"，不是"这与连接是不是同一个 epoch"。
3. `tokenhive/hub/` 与 `tokenhive/cmd/hub/` 全目录里**没有一处**出现 `KeyID`、`PeerCertificates`、
   `ConnectionState` 或 `SPKI`（`grep -rniE` 复核，唯一命中的 `epoch` 是 `ErrEpochRetired` 与 `-tee-verify` 的
   帮助文本，都与配对无关）。

⇒ **"Hub 不要求一次对话开始与结束使用同一张 TEE 证书"是已经成立的现状，Plan B 不需要改 Hub。**
本轮把这句话钉进测试：`TestExchangeOutlivingItsEpochIsSignedByTheLiveOne` 断言 TEE 会产出署**新**叶的收据，
并且该收据的结构（completion / status / 字节数）完整。
（**本仓库侧已核**；生产 Hub 是另一个仓库 `tokhive-mvp`，不在本机，需在那边做同一次 grep——见 19.6。）

留下的两笔账：

- **时间倒置**：换手之后 `StartedAt` 可以早于所引证据那张叶的 `NotBefore`（交换在旧叶下开工、在新叶下签名）。
  今天没有任何东西检查它：`proof.Receipt.Validate` 只要求 `StartedAt > 0 && FinishedAt >= StartedAt`；
  `attest.Verifier.Check` 走 `proof.Verify` 时既不传 `Now` 也不传 `MaxAge`；平台侧只按自己的时钟判叶。
  后果是"同一份收据在不同验证方手里可能判决不同"，形式上与伪造不可区分——这正是 RA-TLS 配对存在的理由，
  现在只在"跨过轮换的那一小批交换"上放弃了。
- **不再守配对这件事写进了代码**：`epochConnections` 的注释已改。它现在守的是"没有请求被服务在一条已经停止
  为它签名的连接上"，不再是配对。`guard` / `rotate` / Hub 重试三者保留——它们的作用降级为"让新请求落到新连接"，
  成本很低，而 Hub 的 `EpochRetiredHeader` 重试路径依赖它们。

### 19.5 审计：Plan B 没有打开新的白嫖面，但把一条旧边界换成了另一条

1. **在途交换现在会被计费，而不是免费**——这是收益。旧代码在 D−1s 切断 ⇒ 半截字节 + 签不出收据 ⇒
   `serve.go` 那条注释说的 "nothing settles"；新代码跑完并拿到可定价收据。
2. **轮换失败时的免费面缩小了**：旧的是"每个周期 D 之后的全部在途交换"，新的是"轮换失败期间跨过 D 的在途交换"。
3. **新的边界：交换长度的上界从"signer 的剩余 margin"变成 `RequestTimeout`。** 旧代码隐含的上界是当前叶的
   剩余寿命（≤ ~2h50m）；B-3 之后只剩 `RequestTimeout`（默认 2m，`TEE_REQUEST_TIMEOUT`）与调用方的 ctx。
   **`RequestTimeout=0` 会让一个交换无界**，而 B-2 意味着只要平台还在轮换它就总能被签出收据 ⇒
   无界但不免费。**⇒ 运维约束：`TEE_REQUEST_TIMEOUT` 必须非 0（默认已是 2m）；这条要进部署清单。**
4. **boot 落在窗口内的残余**：`nextRefreshDelay` 的 floor 是 2m，所以一台在 `[N−9m48s, D)` 之间启动、
   且距 D 不足 2m 的 TEE，第一次轮换可能落在 D 之后 ⇒ 一个 ≤2m 的洞。旧代码在**每个周期**都有更长的一个，
   所以这是残余、不是回归。要消掉它需要让 floor 也服从 `until(D)`，本轮没做。
5. **signer 新鲜度不变差**：换手挑的 signer 满足 `now < D`，即叶至少还有 5m 有效期；不换手时 pinned signer
   满足同一条件。所以每份收据的证据剩余寿命 ≥ `SNPSigningMargin`，与旧代码相同。
6. **"新旧两把 key 属于同一个 enclave"是 B-2 成立的前提。** `activeSigner()` 只能来自 `serviceRuntime.adopt`，
   其 epoch 只来自本进程的 platform adapter（`refresher.Snapshot()`）⇒ 两把 key 属于同一个被度量的镜像，
   Hub 的 `-expected-app` 对两者都会通过。**若哪天 Hub 前挂多台 TEE、或轮换来源不再是本机平台，这条不再成立，
   B-2 会升级成跨机器收据替换**——这是它成立的条件，不是可以忘掉的细节。
7. **与 §17/§18 的关系**：本轮只做 B，不动计费口径、不动 Hub、不动受理门本身。所以 §18 的结论
   （保价目 ⇒ 必须有收据 ⇒ 受理门必须留）依然成立，而且**本轮是它更强的版本**：受理门现在同时是
   "轮换失败"的唯一止损点——而按 §19.2，健康轮换下它永远不会开火。

**一条 Plan B 之外的独立缺陷（读码确认、未端到端实测）**：`hive -audit` 复用同一个 `attest.Verifier`，
而 `verifyNitroChain` 的 `leaf.Verify` 不传 `CurrentTime`（`shared/snp_combined_aws.go:380`），Go 用 `time.Now()`。
⇒ **NitroTPM 叶过期（3h）之后，历史收据在 `store.Audit` 里会被判 `Invalid`，`runAudit` 退非 0。**
结算路径（即时验证）不受影响；受影响的是"provider 事后拉收据对账"这条路径。与 Plan B 无关，今天就在。

### 19.6 测试与未验证项

**单测**：`go test ./tokenhive/... ./shared/...` 全绿（`-count=1`）。

- 新增 `TestRotationIsAimedInsideTheReissueWindow`：把三个常数之间的**关系**钉住——lead 在 `snpReissueWindow`
  之内（否则第一次尝试会被交回正在服务的那张叶）、floor 短于窗口（否则重试网格会整窗跨过）、
  `aim < signingDeadline`（否则 D 必然先到）、`aim` 与 D 之间放得下一次 floor 重试——再用真实 snapshot 的叶
  算出 cadence 确实指向那个 aim。
- `exchange_bound_test.go` 三分：`TestExchangeIsGivenNoDeadlineOfItsOwn`（服务不再给交换装 deadline）、
  `TestExchangeOutlivingItsEpochIsSignedByTheLiveOne`（换手，收据署新叶且内容完整）、
  `TestExchangeIsRefusedWhenNoFresherEpochExists`（两个都越线才拒）。
- **删掉了** `TestExchangeCutAtTheBoundStillSettles` —— 它测的正是被取消的行为（在 D 处切断仍可结算）。
  该文件里的 `waitForDeadline` 模式也一并删掉：没有服务端的 bound，等它的传输会永远阻塞。

**harness**：scenarios 1–18，`45 OK / 0 FAIL`，与 HEAD 基线一致（A/B 都在 `/tmp` 的干净 worktree 里跑）。
但要说清楚它**测不到**什么：harness 用的是仿真证据，没有 NitroTPM 叶 ⇒ `snpLeafDeadline` 读不到 ⇒
`tracked=false` ⇒ **B-1/B-2/B-3 三条路径在 harness 里都不会被触发**。它证明的是"其余一切没被带坏"，
三条的目标行为由上面的单测覆盖。

**未验证**：

1. **真实 AWS 上"轮换落在重签窗口内"**。需要一台真 TEE 看一个完整周期（约 2h51m）：`next RA-TLS attestation
   refresh scheduled` 里的 `at` 与当前叶的 `NotAfter` 之差应当 ≈ 9m，而不是 ≈ 5m。
2. **生产 Hub（`tokhive-mvp`）是否也"不要求首尾证书一致"**。本仓库侧已由 19.4 的三条 grep 复核；那边需要跑一次
   同样的 `grep -rniE "peercertificate|connectionstate|spki|keyid"`，并确认它的 `Verify` 仍是
   `func(proof.SignedReceipt) error` 形状。
3. **`hive -audit` 叶过期**那条（19.5 末）——机制读码确认，端到端没跑。
