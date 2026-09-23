# cloudtest：在真实 AWS SEV-SNP TEE 上跑 TokenHive

在 AWS `us-west-2` 启动一台 AMD SEV-SNP 机密计算实例，把编译好的 TEE / Hub /
MockProvider / Agent 二进制传上去，在实例回环地址上跑完整的 mTLS 业务流，再把
收据、证据、日志拉回本地保存。

## 架构

```
cloudtest/
├── config.py          配置（region / user tag / 实例类型），.env → 环境变量 → 默认值
├── aws.py             幂等 ensure 原语 + 启动 + 按 tag 查找/删除（不构造 boto3 client，可单测）
├── create.py          模块一：ensure 基础设施 → 启动实例 → 写 hosts.json（覆盖写入）
├── delete.py          模块二：按双 tag 查找并删除实例（绝不读 hosts.json，支持 --dry-run）
├── delete_infra.py    独立工具：按双 tag 拆掉网络基础设施（VPC/子网/IGW/安全组/密钥对，平时不要用）
├── run.sh             编排器：build / create / test / delete / delete-infra / 全流程
├── lib.sh             SSH/rsync/日志等公共函数（上传用 rsync -zz zstd，优先 homebrew rsync）
├── remote/run-all.sh  在实例上执行的测试套件（装依赖、起服务、跑请求、审计、打包结果）
├── tests/test_unit.py 本地单元测试（fake EC2，不需要 boto3，不碰真实云）
├── hosts.json         生成的实例信息临时文件（gitignored）
└── logs/<时间戳>/      每次运行的日志与拉回的远端结果（gitignored）
```

## 使用

```bash
./run.sh                    # 全流程：create → test → delete（测试失败也会清理机器）
./run.sh build              # 交叉编译 linux/amd64 二进制（tee 带 -tags sevsnp）
./run.sh create             # 只创建（幂等：基础设施不重复建，hosts.json 覆盖写入）
./run.sh test               # 只测试（依赖 hosts.json 提供实例地址）
./run.sh delete             # 只删除实例
./run.sh delete --dry-run   # 列出会删除的实例，不删
./run.sh delete-infra       # 只拆网络基础设施（平时不要用，见下）
./run.sh delete-infra --dry-run   # 列出会拆掉的基础设施，不拆
KEEP_INSTANCE=true ./run.sh # 全流程但保留机器，便于手工排查
```

注意：`./run.sh create` 会**留着机器**（供后续 `./run.sh test` 使用），只有全流程
`./run.sh` 才会自动清理。全流程在中断（Ctrl-C / 崩溃）时也会通过 trap 回收实例。

## 安全与幂等

- **幂等 ensure**：VPC、子网、互联网网关、路由、安全组、密钥对全部「先查后建」，
  重复执行 create 不会产生重复资源，全部资源都带 `tokenhive-TEE=true` 和
  `user=<配置值>` 双标签。
- **严格按 tag 删除**：delete 只按两个标签查找（服务端过滤后本地再逐台复核标签），
  并且 user 值必须等于配置的 `TOKENHIVE_USER`；任何不带完整双标签的机器绝不动。
  delete 从不读取 hosts.json，即使临时文件丢了也能精确清掉自己创建的机器。
- **只开放 22 端口**：安全组只放行 SSH，TEE/Hub/MockProvider/Agent 全部在实例
  回环地址（127.0.0.1）上通信，业务端口不暴露公网。
- **中断也会清理**：全流程（create → test → delete）装了 `trap ... EXIT INT TERM`，
  即使 Ctrl-C 或崩溃中断在 test 之前，也会回收本轮启动的实例，避免持续计费。
  `KEEP_INSTANCE=true` 可跳过。
- **delete_infra 是独立、少用的工具**：它同样只按双标签查找、本地逐台复核，
  但拆的是网络基础设施（不拆不算钱，所以默认留着以便重跑收敛）。只在想彻底
  重置区域或轮换密钥对时才用，且永远先跑 `--dry-run`。

## 配置

复制 `.env.example` 为 `.env` 并填入 AWS 凭证和 `TOKENHIVE_USER`；其余都有默认值。

| 变量 | 默认 | 说明 |
|---|---|---|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | 无 | 必填（不填则创建/删除直接失败） |
| `TOKENHIVE_USER` | **无，必填** | 实例 user 标签值，删除时精确匹配它。这是区分不同操作员机器**唯一**的边界，必须每人一个唯一值，绝不共享默认值 |
| `TOKENHIVE_REGION` | `eu-west-1` | **唯一允许启动的区域（爱尔兰）**，勿改到其他区域 |
| `TOKENHIVE_INSTANCE_TYPE` | `m6a.large` | 必须是 AMD 系列（m6a/c6a/r6a） |
| `TOKENHIVE_TEE_PLATFORM` | `simulated` | 实例上 TEE 的运行平台（见下） |

`TOKENHIVE_USER` 未设置时 shell 层和 Python 层都会直接失败退出（不会退回任何默认值）。

## 注意：SEV-SNP 的区域与实例类型

AWS 官方文档列出 SEV-SNP 支持 AMD 实例（m6a/c6a/r6a），且首批支持区域为
us-east-2 与 eu-west-1 [$TRAE_REF](https://documentation.ubuntu.com/aws/aws-how-to/instances/launch-and-attest-amd-sev-snp-instances/)[$TRAE_REF](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_LaunchTemplateCpuOptionsRequest.md)。
代码默认固定在 **eu-west-1**（运营规定：只允许在此区域启停服务器）；若 AWS
在该区域尚未开放 `AmdSevSnp=enabled`，`run_instances` 会直接返回错误，create
步骤会明确失败并提示。

## 关于 R.key / secure-boot（为什么默认 simulated）

本仓库是 fork，拿不到原仓库的 secure-boot 密钥（`deploy/secure-boot/` 下的
`R.key` 等产物，`deploy/snp-build.sh` 硬性要求）。因此 `cloudtest/snp/` 的
**真实 SEV-SNP attestation** 路径（loader AMI 构建）在本 fork 不可运行。
主流程 `./run.sh` 不受影响：它以 `TOKENHIVE_TEE_PLATFORM=simulated`（默认）在
真实 AMD SEV-SNP 实例上跑完整的 Hub/TEE/MockProvider/Agent mTLS 业务流、收据
与审计，只是不做真实 attestation，也不需要任何密钥材料。将来若拿到 R.key，
把 `.env` 里 `TOKENHIVE_TEE_PLATFORM` 改回 `sevsnp` 并先 `snp.sh build` 即可。

## 单元测试

```bash
python3 -m unittest discover -s tests -v
```

覆盖：ensure 幂等、SEV-SNP 启动参数与双标签、按 tag 精确删除、delete 不依赖
hosts.json、delete_infra 只拆自己带双标签的资源（别人的/缺标签的/无标签的必须
存活）、`TOKENHIVE_USER` 缺失时直接失败，以及换 TEE 的换机路径（`up --new` 只记录
不删除、`shutting-down` 的旧记录绝不被复用、`retire.py` 只删 `superseded` 里记过的
实例且要求接替者处于 `running`）。全部使用内存 fake EC2，不需要 boto3，
也绝不会触达真实云。

## 真实运行前置条件

1. `./setup.sh` 创建 `.venv` 并装好 boto3（脚本会自动优先用项目内 venv 的 python）
2. `.env` 填入有 `ec2:*` 权限的凭证
3. `./run.sh build` 成功（本地交叉编译 linux/amd64，含 `-tags sevsnp` 的 TEE）
4. 实例可用性：目标区域有 SEV-SNP 实例配额

`delete_infra` 在删除实例后会等待实例完全 terminated，并对安全组/子网/VPC 的
删除做短暂重试，避免 AWS 的异步终止导致脚手架残留（漏删）。`create` 失败时全流程
也会尽力拆掉本轮刚建好的脚手架，不留下半成品基础设施。

执行 `./run.sh` 时，远端套件会 `apt-get install ca-certificates curl`（`curl`/`apt`
自身取包需要 CA 证书；静态 Go 二进制本身无运行时依赖）。注意这份**主机**证书包与 TEE
的上游信任根无关：默认的 `simulated` 平台用 mockprovider 写在 `<simdir>/ca.pem` 的测试
CA，`sevsnp` 平台用系统信任根——而那在被度量 bundle 的
`./etc/ssl/certs/ca-certificates.crt` 里，由 loader 经 `SSL_CERT_FILE` 指给飞地；
`-ca`/`TEE_CA` 只是在选定平台的根之上**追加**，不是替换。运行结果以
`logs/<时间戳>/` 保留在本地。
