# TokenHive 充值与余额体系最小化设计

## 现状与问题

TokenHive（TH）已经具备完整的**计价**能力：模型定价、平台佣金（`hub/commission.go`）、单任务价格封顶（`Config.MaxJobMicros`）、请求次数配额（`hub/quota.go`）。买家侧有**预付余额**：按上限预授权（hold）、结算扣减、余额落盘。

资金账目已经落到**一个 SQLite 数据库**里，三角色齐全（`hub/accounts.go`、`hub/order.go`、`hub/ledgerdb.go`）：买家余额、卖家应付款、平台佣金是同一张表里的三类账户，每次结算在**一个事务**里完成「买家出账 + 卖家入账 + 平台入账」。每笔扣款由**订单事务 id**（Hub 在分派前生成的 JobID 的十六进制）命名，订单行同时是幂等记录：同一笔扣款重复提交不会再扣一次，重启后依然如此。

仍未实现的是**外部资金进出**：

- 没有 `deposit` / `withdraw_*` / `adjust` 入口，买家余额只能靠启动时的 `-tenant-deposits` 播种（只在账本为空时生效）。
- 没有面向支付模块的管理监听器，也没有渠道对接；`hub/ledger.go` 的 `Ledger` 仍然只是内存观测计数器（dispatched/verified/settled/revenue/commission），不具资金语义，重启归零——它记录「这笔任务该扣多少钱」，不记录「这个账户现在还有多少钱」。
- 只有单机：SQLite 是单写者数据库，账本由 Hub 进程独占。

本次设计保持最小化：**Hub 侧只做纯内部记账**（支付宝/微信/银行卡的接入全部外置到独立模块，见「支付渠道接入」一节），并明确「外部资金如何安全、事务化地进入账本」这一接口与落地顺序。

## 核心设计原则

1. **不破坏现有分层**：资金账本与 `Quota`（次数配额）、`MaxJobMicros`（单任务封顶）并列叠加，均可独立启用。**只做预付**（D1-A）：余额门是必过项，不存在「跳过余额检查」的信用旁路；配额与封顶只在前者之上再加约束。
2. **单一写者，事务化**：账本数据库是余额的唯一真相来源，只被 Hub 进程写入。资金从不「先改内存、后落盘，中间用一把锁串行」——那样崩溃窗口不可控；改为**引擎提供的事务**：一次扣款 = 一条 `BEGIN IMMEDIATE`→若干条 SQL→`COMMIT`，要么整体生效，要么整体不生效。SQLite 的 WAL 模式保证写者不阻塞读者、读者不阻塞写者；进程内的写者连接被限制为一条（`SetMaxOpenConns(1)` + `_txlock=immediate`），因此两条资金事务在构造上不可能交错，代码里不需要任何余额锁。
3. **先冻结后结算，而非先检查后扣款**：余额不足的判定必须与扣款的原子性一致。任何「先查余额、执行完再扣」的形状在并发下都会透支：并发的在途任务数 × 单任务金额，就是「检查」与「扣款」之间凭空多出的敞口。做法见「预授权」一节。
4. **每一笔资金变动都是一条可审计的记录**：账户行只保存「现在是多少」，`journal` 表保存「怎么变成这样的」。记录与它描述的余额变动写在**同一个事务**里，因此不存在「改了余额但没记账」的中间态。日志分两类：**内部转账**（`hold` / `settle` / `charge` / `release`）逐条零和；**外部资金进出**（`seed`，将来是 `deposit` / `adjust`）天然单边，只能靠全局恒等式校验（见「对账」一节）。
5. **不变量写进 schema，而不是写进注释**：SQLite 支持 `CHECK` 约束与 `STRICT` 表，能表达的约束就不要留给代码自觉。见「持久化策略」的建表语句：余额非负、冻结不超过余额、订单两侧借贷相抵、全局已入账总额与外部注入总额相等，全部由数据库拒绝违反的写入。

## 数据模型

三种角色，账户主键为 `(role, name)`：

| 角色 role | 账户 name | 增加来源 | 减少来源 |
|---|---|---|---|
| `buyer` | tenant | 充值 `deposit`（未实现，当前为 `seed`） | 结算扣款 `settle`/`charge`、退款/拒付 `adjust`（未实现） |
| `seller` | provider | 结算 `settle`/`charge`（seller 价） | 提现 `withdraw_*`（未实现） |
| `platform` | 常量 `''`（单一账户） | 结算 `settle`/`charge`（佣金） | 提现 `withdraw_*`（未实现） |

每个账户维护两个量，避免把「预授权」和「真钱」混为一谈：

- `balance`：账面余额（充值 − 已消费 ± 调整）
- `held`：预授权冻结额（在途任务的金额上限；卖家侧将来是未决提现）
- `available = max(0, balance − held)`：真正可动用的额度，服务放行只看它。

结算的借贷关系与现有计价一致：买家扣 `buyer = charged + commission`，卖家加 `charged`，平台加 `commission`。三者**在同一个事务内**完成，不存在跨账户的中间态。

**订单是每笔扣款的名字。** `orders.id` 是 Hub 在分派前生成的 JobID 的十六进制（`orderIDFor`），它与 TEE 签进回执的 JobID 是同一个值，所以「买家被扣的这笔钱」「卖家收到的这笔钱」「provider 手上的这份回执」可以互相指认。订单状态机（`held → {settled | released | charged}`）就是资金的生命周期：

| 状态 | 含义 |
|---|---|
| `held` | 已冻结，任务在途 |
| `settled` | 任务计费，冻结被消费成账单 |
| `released` | 任务未计费结束，冻结原额退回 |
| `charged` | 冻结已先行退回、之后仍按回执出账（看门狗掐断会话的形状） |

## 预授权：金额上限必须在分派前可知

**这是本设计的关键约束。**

分派前不存在「本次请求的总价」：

- 计价按**实际交付字节**（`hub/pricing.go` `Price`：`ceil((RequestBytes + 交付响应字节)/1MiB) × perMB`，再加完成态的 per-request 与模型加价），而分派前只知道字节上限；
- 会话（`RunRealtime`）的总价要到连接关闭才结算；
- `bookPrice`（`hub/schedule.go`）只是**排序用下限**（per-request + premium + 1 MiB 的 volume），实际账单可以远高于它。

若按 `bookPrice` 预检、执行后按实际价扣款，结果只有两种：买家余额被扣成负数，或「执行已完成但扣不出来」→ 白送服务。两种都不可接受。

正确做法是**按上限预授权**（hold），上限在分派前是精确可知的：

```
ReqMax  = 请求路由：len(body)（Hub 已持有请求体）
          会话路由：Config.SessionMaxUpBytes
RespMax = spec.MaxResponseBytes（请求路由来自 -max；会话路由来自 boundSession 收紧后的 min(caller, -session-max)）
ceiling = ceil((ReqMax + RespMax)/1MiB) × card.PerMegabyteMicros
        + card.PerRequestMicros + card.Premium(model)      // 按完成态取上界（请求路由 2xx、会话 101）
buyerMax = ceiling + CommissionOn(ceiling)
hold     = MaxJobMicros 已配置时 min(buyerMax, MaxJobMicros)，否则 buyerMax
```

上限假设「完成态交付」，因此只高不低；`Price` 对非 2xx / 未交付的截断返回 0，都在上界之内。当 `MaxJobMicros` 已配置时 `min` 是精确的：超过 `MaxJobMicros` 的账单会被现有逻辑整体拒绝（`ErrJobPriceExceeded`，0 计费），所以按 `MaxJobMicros` 冻结已足够，不会欠扣。

**当前实现取的是上式中最简单的一个可用截面**：`hold` 恒为 `MaxJobMicros`（`hub/flight.go` 的 `beginJob` 传入 `h.maxJob`），而 D3 要求启用账本时 `-max-job-micros > 0`。因为超过封顶的账单整体不计费，`MaxJobMicros` 冻结恒 ≥ 实账，无需按路由计算 ceiling。按路由精确计算 ceiling 是**额度效率**的改进（会话押金不必一律等于封顶），不是正确性的前提，可后续叠加。

**三态生命周期**（`hub/accounts.go`）：

1. `Hold(orderID, tenant, amount)`：`available ≥ amount` 才从 `available` 转入 `held`，否则拒（`ErrInsufficientFunds`，**这就是「余额为 0 停止服务」，且是原子的**）。同一个 `orderID` 以相同条件重复调用是 no-op；已终结的订单不可复用（`ErrOrderConflict`）。被拒的调用**不留下任何状态**（订单行、账户行都不创建），因此攻击者编造的租户名无法撑大表。
2. `Settle(orderID, provider, buyer, seller, commission)`：把冻结转为出账。`held -= hold`、买家 `balance -= buyer`、卖家 `balance += charged`、平台 `balance += commission`，四件事在**一条 UPDATE + 两条 upsert + 一条订单 UPDATE**里一次写完。落记录前校验 `buyer ≤ hold`、`charged + commission == buyer`、`provider` 非空；任一违反即整体拒绝（`refusal`），既不改余额也不动订单——**绝不能用 `balance -= (buyer − hold)` 这类写法**：那样会把冻结额加回余额，等于少扣钱（买家白嫖）。断言失败的唯一现实来源是费率在途调高（A6 残留的目录价/结算价 TOCTOU），处置方向是「宁可少收、不多收」：拒绝 + 审计记录，不追账。
3. 订单终态由账本自己判定，不由调用者的标志位决定：`Settle` 看到订单仍是 `held` 就消费冻结（记 `settle`），看到订单已 `released` 就直接出账（记 `charge`）；`Release(orderID)` 只对 `held` 生效，对已出账的订单是 no-op——**释放永远不会退还已经动过的钱**，这条由账本保证，而不是靠调用者的记性。

**押金语义**：预授权按上限冻结，买家必须至少持有上限对应的钱才能发起任务——一个只想跑 1 MiB 的会话若上限是 100 MiB，就要先有 100 MiB 的钱。这与酒店押金同构，缓解手段是让调用方把 `-max` / `-session-max` 调小（上限是请求侧可控的），而不是取消预授权。

## 已确认决策（D1–D3）

### D1-A 纯预付（已选）

`hold ≤ available`，上限备款不足即拒。零透支，实现最简单。**信用混合（D1-B）明确不选**——它会使「余额为 0 仍能跑若干笔」重新出现，并需额外定义信用额度公式。

### D2 运行时拒绝该会话（已选）

- 响应侧 `RespMax` **恒有界**：请求路由取 `-max`，会话路由取 `boundSession` 收紧后的 `min(caller, -session-max)`；`Spec.MaxResponseBytes == 0` 是非法 spec（`jobs/spec.go`），policy 侧亦强制 `> 0`（`policy/policy.go`）。
- 请求路由 `ReqMax` **恒有界**：用户面 body 硬编码截到 16 MiB（`cmd/hub/serve.go`）。
- 会话路由 `ReqMax = Config.SessionMaxUpBytes`，而 **`-session-max-up 0` 意为「不限制上行」**。

**唯一让 `ceiling` 无界的组合是「会话 + `-session-max-up 0` + `-max-job-micros 0`」**。按 D2，运行时应直接**拒绝该会话**（fail-closed）。由于 D3 要求启用账本时 `-max-job-micros > 0`，该组合在正确配置下不会到达运行时；D2 作为兜底防御保留。只要 `-max-job-micros > 0`，上行无界也安全：`hold = Min(buyerMax, MaxJobMicros) = MaxJobMicros`，超封顶的账单会被整体拒绝、0 计费，故 `hold` 恒 ≥ 实账。

### D3 启用账本时 fail-closed 要求 `-max-job-micros > 0`（已实现）

启用账本而封顶为 0 时，hold 会退化成完整 ceiling，押金量级只由字节上限决定且失去封顶保护。故 **`-serve` + `-accounts` 且 `-max-job-micros ≤ 0` 时，Hub 拒绝启动**（`cmd/hub` 的 `requireServeKeys`）。同一处 fail-closed 校验还要求：agent 网关密钥、TEE relay 密钥齐全，且 `-ledger-sync` 不是 `off`——**服务面对真实资金时不允许「不 fsync 也能收钱」**。

## 持久化策略

要求余额落盘、重启不丢失，且**扣款具备支付级的事务性与并发安全**。物理形态是**单个 SQLite 数据库文件**（`-accounts <path>`），通过 `modernc.org/sqlite` 这个纯 Go 驱动访问（无 cgo，与仓库其余部分一样可交叉编译到 SNP 镜像）。

选择数据库的理由是：资金代码需要的每一样东西——原子提交、崩溃恢复、并发读写、用唯一约束做幂等、可查询的历史——都是数据库**已经实现并经过大量验证**的能力。资金路径最不该承担的，就是把 WAL、回放、断点截断这些保证重新实现一遍的风险。

### 连接与 pragma

每个连接在 DSN 上带 pragma（`_pragma=`），因为 `database/sql` 随时可能新开连接，而一个没有 `synchronous` 或 `busy_timeout` 的连接会让落在它上面的提交悄悄变弱：

| pragma | 值 | 理由 |
|---|---|---|
| `journal_mode` | `WAL` | 写者与读者互不阻塞；文件级属性，设一次即记住 |
| `synchronous` | `full`（默认）/ `normal` / `off` | 提交的强度，见下 |
| `busy_timeout` | 10000 ms | 写锁被别的进程（运维的 sqlite3、备份）占用时等待重试，而不是当场丢单 |
| `foreign_keys` | `ON` | 为将来的提现单/资金单外键做准备 |
| `_txlock` | `immediate`（仅写者） | 事务开始即取写锁；延迟升级可能在做了工作之后失败，那在资金路径上等于丢单 |

**两个句柄，一个文件**：

- **写者**：`SetMaxOpenConns(1)` + `_txlock=immediate`。一条连接、每个事务 IMMEDIATE，写事务因此被构造性串行化，代码里不需要余额锁。
- **读者**：独立句柄、连接池 8 条。WAL 下读者取一致快照，既不阻塞写者，也不被写者阻塞；余额查询、对账、`Order()` 幂等查询都走这里，不进写锁。

### 提交强度（`-ledger-sync`）

- `full`（**默认**）：每次提交 fsync 日志。已提交的扣款能扛断电。持有他人资金的 Hub 只应运行在这个模式。
- `normal`：提交不 fsync。已提交事务能扛进程崩溃，但断电可能回滚最后几次提交。只适合没人真的付钱的压测机器。
- `off`：由操作系统决定何时落盘。**仅限本地仿真**；`-serve` 下直接拒绝启动（见 D3）。

### 建表（`hub/ledgerdb.go` 的 `ledgerSchema`）

```sql
CREATE TABLE accounts (
    role    TEXT    NOT NULL CHECK (role IN ('buyer', 'seller', 'platform')),
    name    TEXT    NOT NULL,
    balance INTEGER NOT NULL CHECK (balance >= 0),
    held    INTEGER NOT NULL DEFAULT 0 CHECK (held >= 0 AND held <= balance),
    PRIMARY KEY (role, name)
) STRICT;

CREATE TABLE orders (
    id         TEXT    NOT NULL PRIMARY KEY,          -- JobID 的十六进制 = 扣款事务 id
    tenant     TEXT    NOT NULL,
    provider   TEXT    NOT NULL DEFAULT '',
    state      TEXT    NOT NULL CHECK (state IN ('held','settled','released','charged')),
    hold       INTEGER NOT NULL CHECK (hold >= 0),
    buyer      INTEGER NOT NULL DEFAULT 0 CHECK (buyer >= 0),
    seller     INTEGER NOT NULL DEFAULT 0 CHECK (seller >= 0),
    commission INTEGER NOT NULL DEFAULT 0 CHECK (commission >= 0),
    opened_at  INTEGER NOT NULL,
    closed_at  INTEGER NOT NULL DEFAULT 0,
    CHECK (buyer = seller + commission)               -- 已出账订单必然借贷相抵
) STRICT;

CREATE TABLE journal (
    seq    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind   TEXT    NOT NULL CHECK (kind IN ('seed','deposit','hold','settle','charge','release')),
    tx     TEXT    NOT NULL,
    tenant TEXT    NOT NULL DEFAULT '',
    provider TEXT  NOT NULL DEFAULT '',
    hold       INTEGER NOT NULL DEFAULT 0,
    buyer      INTEGER NOT NULL DEFAULT 0,
    seller     INTEGER NOT NULL DEFAULT 0,
    commission INTEGER NOT NULL DEFAULT 0,
    funded     INTEGER NOT NULL DEFAULT 0,            -- 该记录净注入账本的外部资金
    at INTEGER NOT NULL
) STRICT;

CREATE UNIQUE INDEX journal_tx ON journal (kind, tx);  -- 幂等屏障

CREATE TABLE ledger_state (
    id     INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    booked INTEGER NOT NULL CHECK (booked >= 0),      -- Σ 账户余额
    funded INTEGER NOT NULL CHECK (funded >= 0),      -- Σ 外部注入
    CHECK (booked = funded)                           -- 守恒，由数据库在写入时就拒绝破坏
) STRICT;
```

`PRAGMA user_version` 记录 schema 版本；打开一个版本比自己更新的数据库**直接失败**，不自动升级——资金 schema 变更需要运维在场。

### 重启路径

- **孤儿冻结释放**：hold 只在任务在途时存在，而任务与进程同生共死。因此打开账本时，把所有仍为 `held` 的订单逐条结清为 `release`（并写日志）。这不是「内存回滚」，而是一条真实的 `release` 记录：否则日志里会永远留下一条无人闭合的 `hold`，下一轮审计既算不平，也看不出这笔冻结何时退的。
- **启动自检**：`Reconcile()`，三项读数必须一致（见「对账」）。不一致则拒绝启动，宁可停机也不在算不平的账上继续做生意。

### 与 `ReceiptStore` 的关系（避免误读）

`hub/store.go` 是**一笔回执一个文件 + 写临时文件后 rename**，不做 fsync、不做回放——它是审计档案，不是账本。资金记录不能沿用那种强度：这里的每一次提交都经过数据库的日志与锁协议。

## 交易记录类型

`journal` 的每一行 = 一次原子写。`hold` / `settle` / `charge` / `release` 是**内部转账**（逐条零和，`funded = 0`）；`seed` /（将来）`deposit` / `adjust` 是**外部单边**记录（`funded ≠ 0`）。

| 记录 | 幂等键 | 语义 | 状态 |
|---|---|---|---|
| `seed` | tenant | 首次建库的播种余额：买家 `balance += amount`，同时 `ledger_state.booked/funded += amount` | 已实现 |
| `hold` | orderID | `available → held`，不足即拒 | 已实现 |
| `settle` | orderID | `held -= hold`；买家 `balance -= buyer`；卖家 `balance += charged`；平台 `balance += commission` | 已实现 |
| `charge` | orderID | 同 `settle`，但不消费冻结（冻结已先行退回） | 已实现 |
| `release` | orderID | `held → available` 全额退回 | 已实现 |
| `deposit` | 外部 tx id | 外部资金已确认到账，买家 `balance += amount`；与 `seed` 走同一条「单边入账」代码路径 | 设计 |
| `withdraw_reserve` | 提现 id | 卖家/平台 `available → held`，不足即拒（**balance 不变，仅重分类**）；此处的 `amount` 即该提现 id 的**唯一权威金额** | 设计 |
| `withdraw_confirm` | 提现 id | 按 reserve 记下的金额 `balance -= amount`、`held -= amount`，并计入「累计已提现」。reserve 只做重分类，故 confirm **必须在此刻真正扣减 balance**，否则卖家余额不降却已拿到外部付款，可无限重复提现（漏钱）。**回调不另传金额**：若允许传更大值，`held` 会被扣成负数，`available = balance − held` 随之虚高 = 凭空铸钱 | 设计 |
| `withdraw_void` | 提现 id | 按 reserve 记下的金额 `held → available`；金额同样锁定为 reserve 值 | 设计 |
| `adjust` | 外部 tx id | 退款/拒付等外部驱动的单边调整 | 设计 |

`withdraw_*` 落地时需要一张 `withdrawals(id, role, name, amount, state, at)` 表（状态 `reserved → {confirmed | voided}`），因为一次提现的金额必须被 reserve 钉住、并被 confirm/void 各应用一次。

`adjust` 落地时还需要放宽买家的非负约束：**买家可以为负的唯一合法来源是 `adjust`**（拒付形成对平台的应收），此时 `available` 归零、服务自然停止。当前 schema 对三者的 `balance >= 0` 一律要求，因此落地 `adjust` 时要把这条 CHECK 改成「卖家与平台恒非负，买家允许为负」。**卖家/平台账户永不为负必须是机制而不是约定**：`adjust` 打向它们时若会使 `balance` 变负，必须拒绝并记审计事件（差额由平台作为应收线下处理）。

## 幂等性

- **结算幂等由订单 id 保证，且是持久的**。一个用户请求一个 JobID，`beginJob` 用它在账本里开一张订单；`Settle` 发现订单已是终态且金额一致时返回成功而不动钱，金额不一致则拒绝（`ErrOrderConflict`）。因此「同一笔扣款提交两次」在任何一层都不会扣两次：内存里的 `claimSettlement` 是**快**的那一半（在进入资金路径之前就拒掉重放，其容量上限仍受 `maxSettledJobs` 约束），数据库里的订单行是**权威**的那一半（跨重启、跨内存表重置依然有效）。
- **幂等键必须与余额变动写在同一条 SQL 事务里**。`journal` 的 `UNIQUE (kind, tx)` 就是屏障：重复的外部 tx id 会让 **INSERT 冲突、整笔事务回滚**，而不是「先改余额、再单独写幂等表」——后者在两步之间崩溃，重试就会重复入账。
- **幂等键按 record kind 分命名空间**（`journal_tx` 的唯一索引是 `(kind, tx)`，`kind` 就是命名空间），否则同一串 id 用于充值和调整时会互相误判为重放。
- **订单行不随缓存淘汰**：`claimSettlement` 会因为满表而整表重置（JobID 由 Hub 随机生成、攻击者不可选，所以它敢这么做），订单行不会——它随账本永久保留，这正是资金层需要的强度。订单表因此随交易总量线性增长，这是本设计的**已知磁盘代价**（可按时间归档已终结且无争议的订单，见「扩展性考虑」）。
- **终态互斥**：同一 `orderID` 上 `hold → {settle | release}` 只能走一次，先到的终态生效；重放同一终态幂等返回成功，提交**另一种**终态则被拒——否则「已 release 的任务再 settle」会双份扣款、「已 settle 的任务再 release」会白退冻结。提现 id 同理。
- **入账路径不需要「先查询再写入」的两次往返**：唯一约束 + 事务使单次写入即可判定重放，调用方无需先 `Order()` 再决定（`Order()` 是给支付模块和管理面用的查询接口）。

## 外部接口与信任边界

需求要求「外部模块处理多渠道支付与提现」，因此必须明确部署形状。**单写者原则下只有三种可能**：

1. 支付模块与 Hub **同进程**（把账本当库用）；
2. 支付模块**独立进程**，通过 Hub 的**独立管理监听器**（独立端口 + 独立密钥，形如现有 `-relay-key` / `-agent-keys` 的 fail-closed 校验）调用受信入口；
3. 两个进程共享同一个数据库文件（**排除**：SQLite 的多进程并发写需要额外的锁与恢复协议，违背最小化）。

推荐 **(2)**，接口设计如下（已实现的部分直接是可用的 Go API；未实现的部分是同构的写路径）：

- `Deposit(txID, role, id, amount)` —— 调用者**已完成**真实资金确认（支付回调、链上确认）。落地方式：与 `seed` 共用一条「单边入账」路径（账户 upsert + `ledger_state.booked/funded` 同增 + `journal` 一行），新增 `kind = 'deposit'`。
- `WithdrawConfirm(txID)` / `WithdrawVoid(txID)` —— 外部服务对**已由 Hub 冻结**的提现请求付款成功/失败后的回调；金额取 `withdraw_reserve` 记下的权威值，回调不得另传。
- `Adjustment(txID, kind, role, id, amount, ref)` —— 退款/拒付；`ref` 指向原交易或原 job。
- `Balance(role, id)` / `Order(orderID)` / `Reconcile()` —— **已实现**的只读查询：`Available`、`SellerBalance`、`PlatformBalance`、`Order`、`Reconcile`。
- 管理监听器本身（HTTP 封装 + 独立密钥）尚未实现。

硬约束（与既有 B4 同类）：

- **资金入口绝不出现在用户面监听器上**。用户面（买家请求、卖家登录）永不出现「增加余额」（`deposit`）或「真出账」（`withdraw_confirm`）的路径；用户面唯一允许的资金操作是**冻结**（`withdraw_reserve`，本身既不入账也不出账）。
- 卖方提现是**两阶段**：卖家在用户面 `POST /v1/accounting/withdraw` 只做 `withdraw_reserve`（冻结），钱只有在外部服务付款并经 `WithdrawConfirm` 后才真正出账。同步单阶段扣款不安全：外部付款与本地记账之间任一崩溃，都会导致「已付款但未扣账」（卖家可重复提现）或「已扣账但未付款」（欠卖家），二者都无补偿记录。
- **充值可以单阶段**（外部已收款 → 记账），因为失败方向偏向买家：崩溃后由外部服务用**同一 tx id** 重试 `Deposit` 即可幂等补齐。这个不对称是有意的：充值的错误必须偏向「少记给平台」，提现的错误不能偏向「多付给卖家」。

## 落地：接入外部充值的代码形状

单边入账的唯一路径**已经在代码里**，就是 `hub/funding.go` 的 `fund`（首启播种 `seed` 走的就是它）：账户余额与 `ledger_state` 的守恒量一起增长，`journal` 记一行，全部在同一个事务里；`(kind, tx)` 的幂等判定与唯一索引也已就位。因此新增「充值」**不需要碰 `hub/flight.go`、`hub/hub.go`、`hub/realtime.go` 或任何结算路径**，只多两样东西：

1. **一个约三行的导出方法**（`hub/accounts.go` 或 `hub/funding.go`）：

   ```go
   // Deposit credits a buyer for an external payment the operator has already
   // confirmed. txID is the payment module's own reference and is the
   // idempotency key: retrying it credits the buyer exactly once.
   func (a *Accounts) Deposit(txID, tenant string, amount uint64) error {
       return a.fund(kindDeposit, txID, tenant, amount)
   }
   ```

   `kindDeposit` 已在 `hub/order.go` 预置。**千万不要在监听器里自己写那三条 SQL**：那样总有一天会漏掉守恒量的另一侧，或者漏掉幂等查询 —— `fund` 存在的意义就是把这两件事变成不可能写错。

2. **一个独立的管理监听器**（新文件 `cmd/hub/admin.go`）：

   - 独立端口 `-admin-addr`（默认空 = 不启用）与独立密钥 `-admin-key`，并像 `-relay-key` 那样 fail-closed：**给了 addr 就必须给 key**，否则拒绝启动；监听地址建议只绑 localhost/内网。
   - `POST /v1/accounting/deposit`，body `{"tx_id":"…","tenant":"…","amount_micros":N}`；把 `Accounts.Deposit` 的错误直接映射成状态码：`ErrTransactionConflict` → **409**（请求格式对、但那个交易 id 已按别的金额入过账）、参数不合法 → **400**、`ErrAccountsBroken` → **503**、成功 → **200**。
   - 顺带把只读接口挂在这里（都不改账本）：`GET /v1/accounting/balance?tenant=…`、`GET /v1/accounting/order?id=…`（即「幂等查询」）、`GET /v1/accounting/reconcile`（把 `Reconcile()` 的 `Report` 原样输出为 JSON，给运维与对账任务用）。
   - 这个监听器**不碰数据库**，只持有 `*hub.Accounts`，与用户面监听器共用同一个句柄：账本没有进程内状态，因此共享是天然安全的；唯一的耦合是有意为之的 —— 一次失败的写会把账本标记为 broken，于是管理面的一次异常会连带让用户面停止接单（这就是 fail-closed 应有的方向）。

**支付模块侧仍需自己负责的事**（Hub 不重复实现）：先落自己的库再调 Hub；回调与主动查单共用同一条入库→调用路径；重试一律用**同一个 tx id**。幂等由账本提供，所以模块的重试逻辑可以做到极简：超时就重试，不用先问「到底成没成」。

**落地顺序**（每一步都可以独立上线）：

| 步骤 | 需要新写的代码 | 不需要动的代码 |
|---|---|---|
| 1. 充值 | `Deposit`（3 行）+ `cmd/hub/admin.go` + 两个 flag + 一处 fail-closed 校验 | 结算路径、调度、TEE、schema（`deposit` 已在 kind 白名单里） |
| 2. 提现 | 新表 `withdrawals(id, role, name, amount, state, at)` + `WithdrawReserve/Confirm/Void`：**不复用 `fund`**，它要下扣余额、且 reserve 金额必须被 confirm/void 钉住 | 充值路径（两条路径互不干扰） |
| 3. 退款/拒付 | 有符号的入账路径（`adjust`），并把 `accounts` 对买家的 `balance >= 0` 放宽（见「交易记录类型」） | 充值/提现路径 |
| 4. 多机 | 「向多机迁移」一节的三件事 | 接口与幂等键（它们本来就不依赖单机） |

## 支付渠道接入（支付宝 / 微信 / 银行卡）

Hub 保持**渠道无感知**：账本只认统一接口签名 `(txID, kind, role, id, amount)`，接口与日志里不出现任何渠道名词。渠道差异全部收敛在独立支付模块：

| 关注点 | 做法 |
|---|---|
| 验签 | 支付宝 RSA2、微信支付 V3 平台证书、银行电子回单核验，全部在模块内完成；Hub 只信任管理监听器密钥，不重复验签 |
| 回调会丢 | 模块必须「**回调 + 主动查单**」双通道：收到回调先落自己的库再调 Hub；超时未收到回调的订单轮询渠道查单接口 |
| 订单状态机 | 充值单 `CREATED → PAYING → PAID → DEPOSITED / FAILED`、提现单 `RESERVED → PAYING → CONFIRMED / VOIDED`；状态与渠道流水先落模块自己的存储，再调 Hub |
| 金额单位 | 渠道以「分」计价，Hub 为 micros；**`1 分 = 10_000 micros`，纯整数换算**，无浮点、无舍入。多币种同理：每种币定义最小单位到 micros 的精确整数倍率，不整除的倍率不支持该币种 |
| 手续费/差错 | 渠道手续费**不动买家余额**（买家按实付金额入账），费用与对账差额以平台侧 `adjust` 记录（带渠道对账单引用） |
| 提现打款 | `withdraw_reserve` 后模块创建提现单，走支付宝转账/微信商家转账/银行代付；打款成功回调 → `WithdrawConfirm`，失败或退票 → `WithdrawVoid` |
| 日终对账 | 下载支付宝/微信对账单与本地流水比对，兜底发现丢单漏单（后续项，不阻塞首版） |

新渠道 = 模块内加一个 adapter 或再部署一个模块实例，**Hub 零改动**——这是本设计「最简架构」的验收标准：Hub 侧不存在任何 `if channel == "alipay"`。

信任代价要说透：管理监听器密钥的持有者等于可以**铸钱**（`Deposit` 直接入账），因此监听器只绑定 localhost/内网接口，密钥 fail-closed（与 `requireServeKeys` 同类）；模块自身被攻破的风险等同于 Hub 被攻破，这是有意的信任收敛，不再额外设防。

## 可用性与一致性取舍

- **资金一致 > 服务可用（fail-closed）**：一次写事务失败（磁盘满、IO 错误、数据库不可用）后，`Accounts` 会置位 `broken`，此后拒绝一切新的 `hold`（`ErrAccountsBroken` → **503**），在途任务让其自然结束。事务本身已经回滚，账本是一致的；不确定的是「下一次扣款还能不能落盘」，而**已经交付的服务无法回滚**，所以宁可停服、由人工介入后重启，也不在不确定的账本上继续放行。重启即重新打开账本，`broken` 自然清零（并重新跑启动自检）。
- **「请求被拒」与「记账自相矛盾」是两件不同的事**，代码里也分成两条路径（`refuse` / `latch`）：
  - **请求被拒**（`ErrInsufficientFunds` / `ErrUnknownOrder` / `ErrOrderConflict` / `ErrTransactionConflict`，以及已出账订单上的重复扣款）：账本一个字节没动，继续服务。余额不足是预付模式的**正常稳态**，绝不能让它停服。
  - **记账自相矛盾**（结算不零和、`provider` 为空、金额超出列范围、账单超过它自己冻结的上限、冻结的金额超过余额、冻结额不足以覆盖当初的预授权）：一律按 fail-closed 处理，置位 `broken`。这些不是「客户钱不够」，而是**同一套算术的下一笔扣款会以同样方式失败**——继续服务等于白送。
- 唯一一个「看起来像前者实际是后者」的例外是**已释放订单的出账**（`charged`）：它的预授权已经被退回，那笔钱可能已被另一个任务重新冻结并花掉，所以余额不足时是**正经的拒绝**（不动账本、不停服），因为账本本身没有任何不一致。这就是「执行了但扣不出来」那条已知路径，属于可检测的债务。
- **Hub 重启/维护期间不丢单**：支付模块调 `Deposit` 失败 → 按原 txID 指数退避重试（幂等保证安全）；前提是模块**先落自己的库、再调 Hub**，回调处理与轮询查单共用同一条入库→调用的路径。
- **重启成本**：打开数据库 + 一次 `Reconcile()` 全表求和。订单表随交易量增长，因此启动自检与 `Order()` 查询的代价随历史线性增长；靠索引与归档控制（见「扩展性考虑」）。
- **冻结不会在崩溃后僵死**：任何残留的 `held` 订单都会在下次启动被结清为 `release`。唯一不能自动处理的是「回执已落盘、资金未动」那一类（见下），它需要线下对账。

## 与现有模块的交互（精确挂载点）

现有代码只有**两个**准入点与**两个**结算点，改动因此很小：

- 准入：`hub/flight.go` 的 `beginJob(tenant, jobID)`（请求路径 `Execute` 与 `openSession` 共用）。它先取 in-flight 份额，再在有账本时 `Hold(orderID, tenant, MaxJobMicros)`，最后过配额；任一被拒都回滚前面已取的资源。会话的份额与冻结随 `newFlightConn` 挂在连接上，会话结束才释放。
- 结算：`hub/hub.go` 的 `Execute` 与 `hub/realtime.go` 的 `runRealtime`，都在 `store.Put` 成功、`claimSettlement` 通过后调用 `spend.settle(provider, buyer, charged, commission)`。
- 订单 id 的来源：请求路由的 JobID 由调用方在建 spec 时生成（`cmd/hub` 的 `buildSpec`），会话路由由 Hub 在 `openSession` 里先生成再注入 spec（`openSessionFor`），保证「先有订单 id、后有 hold、再有 provider 选择」这个顺序成立。
- 因为 hold 建在 `Execute` 与 `openSession` 内部，所有入口自动覆盖：CLI 一次性模式（无 `-serve`，无账本）、HTTP 请求路由、会话路由、harness 与 `sessiondriver` 的驱动路径都走同一处准入，不存在绕过准入点直接结算的旁路。

**每一条「执行了但不计费」的终止路径都必须 `release`**，否则冻结的资金会被卡到下次启动才退回。现有终止路径清单（全部通过 `defer spend.release()` 或 `flightConn.Close` 覆盖）：

- 派发失败/超时（`h.tee.Execute` 返回错误）
- `verify` 回执失败、`ErrStreamMismatch`、`ErrResponseStartMismatch`
- `Price` 溢出 / 佣金溢出
- 价格超过 `MaxJobMicros`（`ErrJobPriceExceeded`：**执行已完成但不计费**）
- `store.Put` 失败（回执不落盘则不动钱）
- `claimSettlement` 判定重复（`ErrDuplicateSettlement`）
- `withhold` 测试缝：该路径为测试刻意跳过回执落盘，等价于「回执不落盘则不动钱」分支
- 会话被上限/超时/传输错误截断

兜底：**启动时凡未与 `settle`/`charge`/`release` 配对的 `hold` 一律以 `release` 结清**——这类 hold 只可能来自已崩溃的前一进程化身。同时把它记为审计事件：若卖方持有对应回执却无付款记录，即为**可检测的债务**，留待线下对账。

## 错误处理与边界情况

- 金额必须 > 0，否则拒绝；金额一律为整数 micros，**不得出现浮点**。超过 `int64` 的金额被拒绝（数据库列是 64 位整数），不做回绕。
- 消耗类操作（`hold` / 将来的 `withdraw_reserve`）要求 `available ≥ amount`，不足即拒（`ErrInsufficientFunds`）。**各账户不为负靠机制保证**：预付买家由 `buyer ≤ hold ≤ 冻结前 available` 保证；卖家只有进账与受 `available` 约束的提现；`accounts` 的 CHECK 是最后一道。**买家可以为负的唯一合法来源是 `adjust`**（见「交易记录类型」的落地说明）。
- 查询不存在的账户返回 0，不隐式创建空账户；账户在**第一笔资金记录落到它身上**时创建——预付租户就是首次 `seed`/`deposit`。`Hold` / `Settle` 里的 upsert 只对卖家与平台的入账账户生效，买家账户必须已存在（否则是 `ErrInsufficientFunds` / `ErrUnknownOrder`），因此租户名不可被用来撑表。
- 订单 id 无法指认（`ErrUnknownOrder`）：对订单的 `Settle`/`Release` 会拒绝，避免一笔野扣款凭空造出账户。
- 订单被不同条款复用（`ErrOrderConflict`）：拒绝，并把订单上已有的条款报出来供排查。重复提交**相同条款**则是幂等成功（不重复扣款），支付模块可以安全重试。
- 外部交易 id 被以不同条款重复提交（`ErrTransactionConflict`）：拒绝，并把已入账的金额与账户报出来。**相同 id + 相同条款是幂等成功**。两半合起来才完整：事务内的查询给出干净的「成功/拒绝」，`(kind, tx)` 唯一索引则保证将来某个调用方忘了先查也**不会重复入账**（会以唯一约束报错并整笔回滚）。
- 入账参数不合法（空交易 id、空账户名、金额为 0、金额超出 64 位列）：**拒绝**而不是 latch。这是唯一一个条款来自进程之外的入口，一条畸形的请求不能让 Hub 停止给其他人扣款。
- **提现冻结不会自动过期**（设计项）：`reserve` 之后外部服务既没 `confirm` 也没 `void` 时，这笔钱会一直挂在 `held` 上。必须留两条退路：管理面显式 `WithdrawVoid`（幂等，按 reserve 金额退回）＋ 一个按年龄扫描「长期未决提现」的对账告警。**不引入自动过期释放**——自动出账与自动退款都可能出错，钱的事宁可人工介入。
- 余额用**检查型加法**（`hub/pricing.go` 的 `addChecked`）而非饱和加法：饱和只适用于展示型累计（`hub/ledger.go` 的 `saturatingAdd`）；账户余额一旦静默饱和，就与产生它的日志不再相符，正是账本存在的意义所在。
- 余额不足必须与「限流」在状态码上区分：`ErrInsufficientFunds` → **402 Payment Required**，账本无法提交 `ErrAccountsBroken` → **503**，而 `Quota`/`in-flight` 超限保持 429。买家据此区分「该充值」与「该退避重试」。

## 启用与配置语义

- `-accounts <path>` 给出 SQLite 数据库路径即启用资金账本；**启用后没有账户的租户 `available = 0`，会被一律拒绝**。路径不存在则创建（连同父目录，权限 0700）。
- `-tenant-deposits T=M[,...]` 只在**账本为空**（首次创建）时生效；它被记成 `seed` 这一外部注资记录，因此守恒恒等式的起点是「实际投进去多少」而不是「零」。重启不会重新播种。
- **只做预付，不设信用租户**（与 D1-A 一致）：不存在「跳过余额检查」的旁路，任何被放行的请求都必须先有余额。将来若要保留信用租户，必须在本文档之外单独定义「有界信用额度」并证明它不破坏 `buyer ≤ hold` 与全局恒等式——本版明确不做。
- 与 `requireServeKeys` 同类的 fail-closed：`-serve` 下必须同时给出 agent 密钥、relay 密钥、`-accounts`、`-max-job-micros > 0`，且 `-ledger-sync` 不为 `off`，否则拒绝启动。
- **多租户上线前的迁移**：先给所有要保留的租户 `deposit`（或首次建库时播种），否则它们会统一收到 402。

## 对账、不变量与崩溃窗口

- **不变量**：
  1. 内部转账类记录（`hold`/`settle`/`charge`/`release`）逐条零和——由 `orders` 的 `CHECK (buyer = seller + commission)` 在写入时强制；
  2. 逐账户 `balance/held` 非负且 `held ≤ balance`——由 `accounts` 的 CHECK 强制；
  3. 全局 `Σ买家 + Σ卖家 + 平台 = Σ外部注入`——由 `ledger_state` 的 `CHECK (booked = funded)` 在写入时强制。

  `Reconcile()` 再把 (3) 从数据里**重新算一遍**并与 `ledger_state` 比对，返回 `Booked`（重算的 Σ 余额）、`Recorded`（账本记录的总额）、`Funded`（Σ 外部注入）、`Held`、账户数、订单数与在途订单数。不一致即返回错误，`OpenAccounts` 据此拒绝启动。`Booked == Recorded == Funded` 就是「账对得上」的完整含义。
- **崩溃窗口只有两个，且方向已知**：
  1. **回执已落盘、资金未动**（`Execute` 是「先存回执、后结算」，顺序刻意如此）：卖方持有一份未获付款的回执 → 平台欠卖家，**可检测**（回执存在但无 `settle`），不会静默丢钱。补账方式是用同一个 JobID 重放 `Settle`——订单仍是 `held`，扣款照常生效且只生效一次。
  2. **事务未提交**：`hold`/`settle` 要么整体生效要么整体不生效，不存在「冻结已释放、钱还没扣」的中间态。未提交的 `hold` 在下次启动被结清为 `release`。
  反向顺序（先动钱后存回执）**不可取**：会出现「已付款但无回执」，从卖方视角等于 Hub 隐藏了一次执行，正是 `ProviderSeq` 机制要防的事。

## 向多机迁移

单机 SQLite 是**刻意的起点**，而不是终局架构。当前实现为了让迁移便宜，刻意保持了三条纪律：

1. **资金状态全部在数据库里，进程不持有任何余额**。`Accounts` 只有两个 `*sql.DB` 句柄，没有 map、没有缓存、没有「内存是真相、磁盘是副本」的双份状态——因此不存在需要同步的本地状态。
2. **所有余额变动都写成显式事务**。SQL 语句、事务边界、幂等键（订单 id / 外部 tx id）都不依赖 SQLite 的特性；把 `openLedger` 的两个句柄换成连到 PostgreSQL 的连接池、把 DDL 的 `INTEGER` 换成 `BIGINT`、`AUTOINCREMENT` 换成序列，事务体可以原样搬运。
3. **幂等与守恒不依赖进程**。重复扣款的拦截来自唯一约束（订单主键 / `journal(kind, tx)`），守恒来自 `ledger_state` 的 CHECK + `Reconcile()`；多机不会因为多一个进程而多扣一次。

迁移时**必须解决的三件事**（当前实现有意不做，因为单机下不存在）：

- **启动时的孤儿冻结释放必须变成「按占有者与租约」**。现在是「本进程启动 ⇒ 除我之外没有活着的任务 ⇒ 释放全部 `held`」。多机下这会释放别的节点正在用的冻结。落地方案是给 `orders` 加 `holder`（节点 id）与 `lease_until`，释放条件变成「占有者不是本节点且租约已过期」。这是唯一一处**必须**改语义的地方。
- **写者从「一进程一条连接」变成「数据库的串行化隔离」**。SQLite 靠单连接把写事务串行化，PostgreSQL 要改用 `SERIALIZABLE` 事务或对账户行 `SELECT … FOR UPDATE`（按 `(role,name)` 固定顺序加锁避免死锁）。余额的读-改-写在两种实现里都必须发生在持有行锁的事务内。
- **外部资金入口要有稳定的门**。多机下「同一笔 `deposit` 追到不同节点」也会被 `journal` 的唯一索引拦住，但管理监听器的部署形状（每节点都有，还是单独一组）要提前定好；理想形态是资金入口独立于业务节点，只连数据库。

## 扩展性考虑

- **订单归档**：已终结、无争议的订单行可以按期归档到冷表/冷文件，只把「近期 + 争议/未决」留在热表，从而让 `Reconcile()`、`Order()` 与磁盘占用不随历史线性增长。归档只能搬走**已终结**的订单，否则幂等屏障会出现空洞。
- **多币种**：账户主键从 `(role, name)` 扩展为 `(role, name, currency)`，交易记录加币种字段；不做汇率换算。
- **交易记录哈希链**（低成本、可选）：给 `journal` 每行附带前一行的哈希，使篡改或中间截断可被检测。与仓库既有的哈希链习惯一致（收据 `StreamHash` / `ProviderSeq`）。数据库自身已能防止静默损坏，这项加的是**防内部篡改**。
- **不对账的「直接设置余额」接口**：永久不提供。离线修正只能通过 `adjust`（带外部 tx id 与 `ref`）产生**可审计**的变动。
- 平台账户可简化为单一常量账户（现在就是 `(platform, '')`）；若运营方不需要对外提现，其 `withdraw_*` 路径可不启用。
