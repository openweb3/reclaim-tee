# TEE 执行失败：把原因从 enclave 里带出来

## 1. 问题

一次执行失败时，TEE 内部知道原因，Hub 只知道失败了。

`perform` 从 `transport.Do` 拿到的 err 带着具体原因：拨号失败、TLS 握手失败、超时、连接被断开。这个 err 只用来决定回执的 `Completion` 取三个值中的哪一个，然后就没了。它进不了回执，也进不了 SSE 帧；能看到的只有 TEE 的计时日志，而计时默认关闭。

Hub 于是只能从回执的形状反推：没有状态码就是"上游连接失败"，2xx 但没收完就是"上游不完整"。两个真实后果：

- 10-15 那 5 次 `upstream_connection_failed`，从记录上看不出断在 Relay、Bee 隧道、Bee 出口还是 TEE 到上游这四段里的哪一段。当时先怀疑了最后一段，对照 Hub 的 `bee disconnected` 日志才确认是隧道卡死（#93）。
- `TEE_REQUEST_TIMEOUT` 默认 2 分钟时，约 30 次长回复在第 120 秒被 TEE 自己切断，全部记成 `upstream_incomplete`。`providerSideFailure` 把它归给供给方，`beewire.ReasonExplanation` 让供给方去查网络。TEE 自己超时，账单上却是供给方的问题。

## 2. 结论：发一帧，不签进回执

新增 `event: failure` 帧，位置在 `receipt` 帧之前，内容是 `{"class","stage","cold"}`。

不放进回执有三个理由。

**回执字段一被签名覆盖就冻结。** 现在这套分类还在积累：哪些类别真的会出现、Hub 该对每一类做什么，都靠后面的故障去校准。把还在变的语义写进签名域，改一次就要连着 TEE 和 Hub 一起发布。

**加字段会强制两边同时升级。** 回执走 canonical CBOR，读取端解完会重新编码再比字节。旧 Hub 不认识新键，重编码后字节不等，`ErrNonCanonical`，整张回执作废。也就是说，不签名的帧让两边可以分别发布：旧 Hub 忽略它，行为回到今天；新 Hub 读到它，多一个字段。

**今天没有结算消费者。** `Billable` 和 `Price` 只看 `Completion`、状态码和字节数，一行都没动。等哪天要按原因决定"TEE 超时不该让供给方吃亏"，再加回执字段，那时候该签哪几类已经清楚了。

这一帧走的是同一条经过远程证明的 TLS 连接，来源和回执一样是那个被度量的 enclave。它不是可携带的证据，仅此而已。

## 3. 类别

`class` 是封闭集合。判断只看错误类型和发生在哪一段，不带任何报文内容。

| `class` | 条件 |
| --- | --- |
| `request_timeout` | `Request.Timeout` 到期（拨号阶段除外，那算 `dial_failed`） |
| `caller_gone` | 向 Hub 写 chunk 失败，或交换的 context 被取消 |
| `response_too_large` | `ErrResponseBodyTooLarge` |
| `dial_failed` | 到 Provider 的流没建立起来，含拨号阶段超时 |
| `tls_handshake_failed` | 到上游的 TLS 握手被拒（证书、信任库）；握手只是超时的算 `request_timeout` |
| `upstream_closed` | 状态行之前或正文中途连接结束 |
| `read_timeout` | 读超时，且不是 `Request.Timeout` 造成的 |
| `other` | 以上都不是 |

判断顺序是有讲究的，因为几种条件会同时成立：

relay 抛出的错优先于 transport 返回的错。买家先走，transport 的 `i/o timeout` 描述的是后果，不是原因。

调用方结束的交换优先于阶段判定。取消是调用方的动作，会落在当时正在做的任何事上，包括还没返回的拨号；调用方自己设的 deadline 到期同理。transport 只给自己的 `Request.Timeout` 打 `ErrRequestTimeout` 标，所以 context 到期却没带标记，就是调用方的 bound。

阶段优先于超时，但有一个例外。拨号超时说明隧道根本没打开，所以留在 `dial_failed`；TLS 握手超时不是握手被拒，它跟证书、信任库无关，所以不能留在 `tls_handshake_failed`：那是没等到答案，不是被拒绝。

`Request.Timeout` 优先于普通读超时。剩下的、停在写/等头/读正文三个阶段的错误，一定是连接提前结束，不需要再按错误类型匹配，因为中继流的 deadline 是以 `io.EOF` 的形式报出来的。

`Request.Timeout` 到期这件事，还要按**时钟**判一次而不只看 context：连接超时和 context 超时是对同一时刻的两个定时器，socket 可能先报出超时、context 的 goroutine 还没醒。只看 `ctx.Err()` 会把这一微秒判成"上游断了"，正好是本节的初衷要消灭的错判。

## 4. `stage` 从哪来

不读计时记录。计时默认关闭，恰好是生产上最需要它的时候没有。

由 transport 在出错点包装 `tee.StageError`：`dial`、`tls`、`write`、`ttfb`、`body`，外加 `acquire`（等连接池槽位，属于 TEE 自己的容量问题）。阶段名复用计时的那套常量，日志、指标和 Hub 收到的诊断不会各说一套。同一个结构里带 `cold`，只有 transport 知道这次是否新建了连接。

`Request.Timeout` 由 transport 自己施加，所以"是不是 TEE 自己的时限到了"也只有它能判断：那个时刻调用方的 context 还是健康的，底下的错误只是一个普通 socket 超时。transport 用 `tee.ErrRequestTimeout` 标记，service 读回来。

## 5. `dial_failed` 要不要再细分成两类

结论：错误类型上做不到，阶段上已经区分了。

`Relay.Dial` 最终走 `tunnel.Dial`，它做的是把 KindOpen 帧写出去就返回，不等对端确认。对端拒绝的唯一表达方式是关闭这条流（Hub 的 `relayStream` 在 Agent 不在线、Dial 失败、以及 bridge 结束时都只是 `Close`）。所以：

- 流打不开：写 KindOpen 卡住，或隧道本身已经关了。停在 `dial`。
- 流开了但一直没有数据：停在 `ttfb`，读到的是 EOF（Hub 立刻关流，例如 Agent 未接入），或者一直读不到直到 `Request.Timeout` 到期。

要把它变成两种错误类型，得给 tunnel 协议加一个同步的 open-ack。为诊断改协议不值得；`stage` 已经把这两种情况分开了。

`upstream_closed` 因此是最宽的一类：上游关闭、线路重置、Hub 关掉一条接不上 Agent 的流，从 TEE 这边看是同一件事。想知道"当时到底有没有 Agent 在线"，Hub 自己就有答案。

## 6. Hub 侧要做的

`hub.Result.Failure` / `hub.Outcome.Failure` 已经能读到这一帧。生产 Hub（`tokhive-mvp` 的 `hive/`）需要按同样口径落到 `attemptFailure`：

| `class` | 归属 | 是否 `providerSideFailure` / `SupplyFailures` |
| --- | --- | --- |
| `request_timeout` | `tee_execute`（TEE 自己的问题） | 否，排除 |
| `caller_gone` | Hub 或买家断开 | 否，排除 |
| `response_too_large` | Hub 自己的响应上限 | 否，排除 |
| `dial_failed` | Bee 隧道 / 出口 | 是 |
| `tls_handshake_failed` | TEE 到上游，先查 TEE 的信任库 | 否。握手失败不是供给方能靠查网络修好的事，这个仓库里历史上它多半是 CA bundle 的问题 |
| `upstream_closed` | 上游或线路 | 是。注意 Hub 自己知道当时有没有接上 Agent，接不上时它也会关流 |
| `read_timeout` | 上游慢或线路卡住 | 是 |
| `other` | 无法归类，保持现状 | 保持现状 |
| 不认识的 `class` | 更新的 TEE 发明的 | 按 `other` 处理，绝不当成"供给方有错"。Hub 的客户端在解析处就折叠成 `other`（`FailureClass.Known`），不把无法解释的 token 往下传 |

`failure_detail` 用 `Failure.String()` 的形式：`completion failed: dial_failed (cold, stage=dial)`。

## 7. 没做什么

- **会话 `/v1/session` 不回这一帧。** 会话本来就以上游关闭结束，截断是常态，归因的意义不同。
- **结算逻辑没动。** `Billable`、`Price`、回执格式、验签路径一行未改。
- **回执里的 `Completion` 三态不变。** 这一帧是附加信息，不是新的执行结果。
