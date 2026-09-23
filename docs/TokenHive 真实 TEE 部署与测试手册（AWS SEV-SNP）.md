# TokenHive 真实 TEE 部署与测试手册（AWS SEV-SNP）

日期：2026-09-10
状态：已在 eu-west-1 实测通过（自检机 build → up → verify → down；业务闭环双机与单机 build → up → verify → down 全流程）

定位：本文是从零开始部署并测试真实 TEE（Trusted Execution Environment，可信执行环境）的完整操作手册。起点是信任根密钥的创建，终点是在 AWS 上完成一次真实 SEV-SNP（Secure Encrypted Virtualization-Secure Nested Paging，AMD 的安全加密虚拟化-安全嵌套页）机密实例的启动、远程证明（attestation）验证与清理。第 5-8 节描述一次性自检机（`snp.sh`，验证 attestation 链），第 9 节起描述真实业务闭环（`crosshost.sh`，在机密实例里实际运行 TokenHive 业务）。文中给出每一步的精确命令、需要的 AWS 权限、以及实测中遇到的故障与解法。

---

## 0. 术语约定

首次出现时给出全称，后文直接使用缩写。TEE（Trusted Execution Environment）即可信执行环境；SEV-SNP（Secure Encrypted Virtualization-Secure Nested Paging）为 AMD 提供的基于安全加密虚拟化与安全嵌套页的机密计算技术；attestation（远程证明）为 TEE 向外部证明自身代码与配置身份的证据机制；AMI（Amazon Machine Image）为 AWS 的可启动镜像；UEFI（Unified Extensible Firmware Interface）为统一可扩展固件接口；Secure Boot 为基于 UEFI 数字签名的安全启动机制；PK（Platform Key）为 Secure Boot 的顶级平台密钥；KEK（Key Exchange Key）为密钥交换密钥，连接 PK 与签名数据库；db（Signature Database）为签名数据库，列出被信任的签名者证书；UKI（Unified Kernel Image）为统一内核镜像，把内核、initrd（初始内存盘）与命令行打包为单个 UEFI 可执行文件；PCR（Platform Configuration Register）为 TPM（Trusted Platform Module，可信平台模块）内的平台配置寄存器，度量值只能扩展不能回退；RATLS（Remote Attestation TLS，远程证明传输层安全）为把 attestation 证据绑定进 TLS（Transport Layer Security，传输层安全协议）握手的机制；VM Import 为 AWS 提供的把外部虚拟磁盘导入为 EC2 快照与 AMI 的服务；ESL（EFI Signature List）为 EFI 签名列表，Secure Boot 数据库中证书的载体格式；VMDK（VMware Virtual Disk）为 VMware 虚拟磁盘格式；boto3 为 AWS 官方的 Python SDK；IAM（Identity and Access Management）为 AWS 的身份与访问管理服务；S3（Simple Storage Service）为 AWS 对象存储服务；EC2（Elastic Compute Cloud）为 AWS 的云服务器服务。

---

## 1. 全流程概览

TokenHive 的真实 TEE 测试在云上复现了一条完整的信任链：从固件到应用，每一步的测量值都可由远程验证者核验。镜像采用两层 loader 设计，其核心思想是把"引导链"与"应用"分离成两个独立的部分。第一层是一个由信任根 R 签名的基础 UKI（统一内核镜像），它包含内核、initrd（初始内存盘）与 loader 程序，loader 作为 init 进程直接启动；第二层是一个独立的原始分区，里面存放应用的 bundle 归档（tar 包），不参与引导。loader 启动后读取该分区，对原始字节计算 SHA-256 摘要得到 SNP_APP_HASH，把它扩展进 TPM 的 PCR 8，然后以非特权身份执行应用，并把该哈希值注入应用进程的环境变量。应用在运行中调用 SEV-SNP 的 attestation 接口，生成一份由硬件签名的证据，并把 SNP_APP_HASH 绑定进证据的 report_data 字段，再自验证该证据。验证者只需要两样东西：信任根 R 的公钥（用于重放 Secure Boot 日志证明引导链合法），以及 PCR 8 的预期值（用于证明被加载的应用就是预期的那份字节）。

整套流程被编排进一个脚本 `snp.sh`，五个子命令对应五个阶段：

```bash
./snp.sh build          # 打包应用 bundle + 构建 loader AMI（依赖 VM Import）
./snp.sh up             # 启动带 AmdSevSnp 的机密实例（写入 hosts.json）
./snp.sh verify         # 轮询 EC2 控制台输出直到 SNP_TEST_RESULT，保存日志
./snp.sh down           # 严格按双 tag 终止实例（可先 --dry-run 预演）
./snp.sh delete-infra   # 清理带 tag 的网络基础设施（破坏性，慎用）
```

其中只有 `build` 需要本地的 docker、qemu-img 与 AWS CLI 以及 VM Import 全链路；`up`、`verify`、`down` 只需要 boto3 与 EC2 权限。删机永远只按双 tag（`tokenhive-TEE: true` 与 `user: <配置值>`）匹配，绝不依赖 hosts.json 临时文件，这是删除操作唯一的安全边界。

---

## 2. 信任根密钥的创建（最早的步骤）

Secure Boot 的信任体系是三级嵌套：PK（平台密钥）位于最顶层，只有持有 PK 私钥才能修改 KEK（密钥交换密钥）；KEK 授权对 db（签名数据库）的更新；db 中列出的证书是"被信任的签名者"，固件只启动由这些签名者签名的可执行文件。TokenHive 的信任根 R 就是这个体系中的签名者：R 的证书被放进 db，镜像的 UKI 由 R 的私钥签名，于是只要固件在 Secure Boot 模式下启动，未经 R 签名的代码就不可能被执行。

本仓库的 `deploy/secure-boot/` 目录下，PK 与 KEK 的密钥对（含证书、ESL、公钥）是仓库既有资产；R 是本模块的发布信任根，当私钥丢失或需要轮换时按以下步骤重建。所有命令在 `deploy/secure-boot/` 目录内执行。

第一步，生成 R 的 RSA-3072 私钥。SEV-SNP 实例（AMD EPYC 7003 系列）的固件要求 db 签名者使用 RSA 2048 或 3072 位密钥，3072 是当前强度下的稳妥选择：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out R.key
chmod 600 R.key
```

第二步，从私钥派生自签名的 X.509 证书。证书只含公钥与身份信息，是分发物；Common Name 建议用可读的发布者名，它会在验证者的日志与证据中出现：

```bash
openssl req -new -x509 -key R.key -out R.crt.pem -sha256 -days 3650 \
  -subj "/CN=Reclaim Cross-Cloud Release Key"
openssl x509 -in R.crt.pem -outform DER -out R.crt.der
openssl pkey -in R.key -pubout -out R.pub.pem
```

第三步，生成 EFI 签名列表 R.esl。Secure Boot 的 db 变量以 ESL 格式存放证书，需要绑定一个全局唯一标识符（GUID）；仓库的 GUID.txt 提供固定值，避免每次重建改变变量身份：

```bash
cert-to-efi-sig-list -g "$(cat GUID.txt)" R.crt.pem R.esl
```

第四步，同步发布公钥。`shared/secure_boot_release_pub.pem` 是验证方持有的 R 公钥，构建脚本会强制校验它与 `deploy/secure-boot/R.pub.pem` 完全一致（`cmp -s`），两者不一致构建直接失败，这是防止"签名密钥与验证密钥分叉"的护栏：

```bash
cp R.pub.pem ../../shared/secure_boot_release_pub.pem
```

第五步，重建 AWS 的 UEFI 变量存储 `aws-uefi-data.b64`。AWS EC2 的 `register-image --uefi-data` 参数接受一段 base64 编码的 NVRAM（非易失随机存取存储器）变量二进制，内含 PK、KEK、db 三组变量；db 中放入的就是上一步的 R.esl。用 python-uefivars 工具（pip 安装）把三个 ESL 按 UEFI 规范的 NVRAM 布局序列化，再 base64 编码写入该文件。注意这一步替换的是整个变量存储，PK 与 KEK 的内容保持不变，只更新 db 中的 R 证书：

```bash
pip install python-uefivars
# 用 uefivars 把 PK.esl、KEK.esl、R.esl 组装为 NVRAM 变量存储（db ← R.esl）
# 输出二进制经 base64 编码后写入 aws-uefi-data.b64
```

R.key 是唯一的秘密：它必须只存在于本机与构建机，绝不能进入版本库。仓库的 .gitignore 已用 `deploy/secure-boot/*.key` 模式将其排除；其余 R.crt.pem、R.crt.der、R.pub.pem、R.esl、aws-uefi-data.b64 均为公钥/证书材料，是分发物，与 PK、KEK 一样纳入版本管理，保证任何克隆仓库的人都能复现构建与验证。

---

## 3. AWS 权限需求（详细）

### 3.1 区域与实例约束

AWS 的 SEV-SNP 支持区域目前只有两个：eu-west-1（爱尔兰）与 us-east-2（俄亥俄）。其他区域即使启动成功也只是普通实例，没有硬件机密内存，因此区域是硬约束，配置在 `deploy/.env` 的 `AWS_SNP_REGION` 与 `cloudtest/.env` 的 `TOKENHIVE_REGION`，两者必须一致。实例类型限定 AMD EPYC 7003 系列的 m6a、c6a、r6a 家族，默认 c6a.large。

### 3.2 执行身份的最小策略

执行构建与测试的 IAM 身份（用户或角色）需要附加 `tokenhive/cloudtest/snp/iam/aws-snp-policy.json`。该策略按职责分为七个语句（Sid）：

**Identity**：`sts:GetCallerIdentity` 与 `ec2:DescribeRegions`，构建脚本用它解析当前账号 ID 以派生 S3 桶名，属于最小身份探测。

**VMImportBucket**：S3 桶操作，资源限定在 `snp-vmimport-*` 前缀。桶名规则是 `snp-vmimport-<账号ID>`，前缀限定保证该身份只能操作本模块的暂存桶，不能触碰其他业务桶。包含 `s3:CreateBucket`、`s3:ListBucket`、`s3:GetBucketLocation`、`s3:PutObject`、`s3:GetObject`、`s3:DeleteObject`。

**VMImport**：VM Import 核心动作，`ec2:ImportSnapshot` 发起快照导入，`ec2:DescribeImportSnapshotTasks` 轮询导入状态，`ec2:RegisterImage` 把导入完成的快照注册为 AMI，`ec2:DeregisterImage` 覆盖旧 AMI，`ec2:DescribeImages` 查询现有镜像。

**ReadAllEC2**：只读描述权限，覆盖实例、VPC、子网、互联网网关、安全组、路由表、可用区、密钥对、快照与标签，是幂等基础设施逻辑（先查后建）的前提。

**IdempotentInfra**：基础设施的创建与删除动作，包括 VPC、子网、互联网网关、路由表、安全组、密钥对的增删改。这些操作全部由 launch.py 以"存在则复用、不存在则创建"的语义调用。

**Instances**：实例生命周期，`ec2:RunInstances` 启动、`ec2:TerminateInstances` 终止、`ec2:GetConsoleOutput` 读取控制台输出（verify 阶段唯一的数据通道），以及 `ec2:CreateTags`/`ec2:DeleteTags` 维护双 tag。

**VMImportServiceRole**：创建并给 `vmimport` 服务角色附加策略所需的 IAM 动作，资源限定在 `arn:aws:iam::*:role/vmimport`，只允许操作这一个角色名。

下面是这七个语句合并后的完整策略 JSON，也就是 `tokenhive/cloudtest/snp/iam/aws-snp-policy.json` 的原文。按原样保存为 `aws-snp-policy.json` 并附加到执行身份即可：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Identity",
      "Effect": "Allow",
      "Action": ["sts:GetCallerIdentity", "ec2:DescribeRegions"],
      "Resource": "*"
    },
    {
      "Sid": "VMImportBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": ["arn:aws:s3:::snp-vmimport-*", "arn:aws:s3:::snp-vmimport-*/*"]
    },
    {
      "Sid": "VMImport",
      "Effect": "Allow",
      "Action": [
        "ec2:ImportSnapshot",
        "ec2:DescribeImportSnapshotTasks",
        "ec2:RegisterImage",
        "ec2:DeregisterImage",
        "ec2:DescribeImages"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadAllEC2",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeSnapshots",
        "ec2:DescribeTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IdempotentInfra",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateVpc",
        "ec2:DeleteVpc",
        "ec2:CreateSubnet",
        "ec2:DeleteSubnet",
        "ec2:ModifySubnetAttribute",
        "ec2:CreateInternetGateway",
        "ec2:DeleteInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:DetachInternetGateway",
        "ec2:CreateRoute",
        "ec2:DeleteRoute",
        "ec2:CreateRouteTable",
        "ec2:DeleteRouteTable",
        "ec2:AssociateRouteTable",
        "ec2:DisassociateRouteTable",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateKeyPair",
        "ec2:DeleteKeyPair"
      ],
      "Resource": "*"
    },
    {
      "Sid": "Instances",
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:RebootInstances",
        "ec2:TerminateInstances",
        "ec2:GetConsoleOutput",
        "ec2:CreateTags",
        "ec2:DeleteTags",
        "ec2:DescribeInstanceAttribute"
      ],
      "Resource": "*"
    },
    {
      "Sid": "VMImportServiceRole",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:GetRole",
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:PassRole"
      ],
      "Resource": "arn:aws:iam::*:role/vmimport"
    }
  ]
}
```

#### 这个身份怎么在 AWS 上落地

执行身份可以是 IAM 用户，也可以是 IAM 角色。推荐用**用户 + JSON 内联策略**，路径最短且不依赖额外角色。操作在 AWS 控制台完成：

1. 打开 IAM 控制台 → 左侧「用户」→「创建用户」，填写用户名（例如 `chenxinghao`），访问类型勾选「编程访问」（供 AWS CLI 使用）。
2. 在「设置权限」页选择「直接附加策略」→ 右下角「创建策略」→ 切到「JSON」页签，粘贴上面这份策略 →「下一步」命名（例如 `TokenHive-SNP-Test`）→「创建策略」。
3. 回到用户创建向导，在搜索框输入 `TokenHive-SNP-Test` 选中它 →「创建用户」。
4. 创建完成后回到该用户详情页 →「安全凭证」标签，生成访问密钥 `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`，填入 `cloudtest/.env`。

如果你的执行身份已是某个角色（例如 CI 用的角色），同等做法：角色详情 →「权限」→「添加权限」→「创建内联策略」粘贴同样 JSON。

用 AWS CLI 也可以完全等价（脚本化交付更利于团队复制）。先确认已配置好一个有 IAM 权限的凭证，然后仅在受控区间执行：

```bash
# 1) 创建执行用户 + 附加内联策略（access-key 打印后请立刻保存）
aws iam create-user --user-name chenxinghao
aws iam put-user-policy --user-name chenxinghao --policy-name TokenHive-SNP-Test \
  --policy-document file://aws-snp-policy.json
aws iam create-access-key --user-name chenxinghao

# 2) 创建 vmimport 服务角色并附加其权限（见 3.3）
aws iam create-role --role-name vmimport \
  --assume-role-policy-document file://vmimport-trust-policy.json
aws iam put-role-policy --role-name vmimport --policy-name vmimport \
  --policy-document file://vmimport-role-policy.json
```

`aws-snp-policy.json`、`vmimport-trust-policy.json`、`vmimport-role-policy.json` 三份文件在仓库中的位置：

```text
tokenhive/cloudtest/snp/iam/aws-snp-policy.json        # 执行身份最小策略
tokenhive/cloudtest/snp/iam/vmimport-trust-policy.json # vmimport 角色的信任策略
tokenhive/cloudtest/snp/iam/vmimport-role-policy.json   # vmimport 角色的权限策略
```

### 3.3 vmimport 服务角色

VM Import 是 AWS 的托管服务，它需要以一个名为 `vmimport` 的 IAM 角色身份去读取 S3 桶并写入 EC2 快照。该角色创建一次即可，仓库 `tokenhive/cloudtest/snp/iam/` 下提供了两份现成的 JSON：

`vmimport-trust-policy.json` 声明信任策略：主体是 `vmimport.amazonaws.com` 服务，允许它执行 `sts:AssumeRole`，即允许 AWS 的 VM Import 服务以该角色身份工作：

```bash
aws iam create-role --role-name vmimport \
  --assume-role-policy-document file://vmimport-trust-policy.json
```

`vmimport-role-policy.json` 声明角色权限，两条语句：`ReadSourceS3` 允许从 `snp-vmimport-*` 桶读取对象（`s3:GetBucketLocation`、`s3:GetObject`、`s3:ListBucket`），`WriteEC2Snapshot` 允许写入 EC2 快照（`ec2:ModifySnapshotAttribute`、`ec2:CopySnapshot`、`ec2:DescribeSnapshots`、`ec2:RegisterImage`、`ec2:DescribeImages`）：

```bash
aws iam put-role-policy --role-name vmimport --policy-name vmimport \
  --policy-document file://vmimport-role-policy.json
```

这个角色在控制台的操作路径：IAM 控制台 →「角色」→「创建角色」→ 受信任实体类型选「AWS 服务」，用例选「EC2」下的「VM Import」（若不显示，选择「其他 AWS 服务」并粘贴 `vmimport-trust-policy.json`）→「下一步」→「添加权限」里选择「创建内联策略」粘贴 `vmimport-role-policy.json` → 角色名填 `vmimport` →「创建角色」。角色名必须是 `vmimport`，因为 VM Import 服务会以此固定名称去 AssumeRole，且构建脚本把 `arn:aws:iam::*:role/vmimport` 之外的任何角色都拒绝在授权范围内。

验证角色是否就绪：执行 `aws sts assume-role --role-arn arn:aws:iam::<账号ID>:role/vmimport --role-session-name probe`，返回临时凭证即说明 VM Import 后续能成功承担该角色。

### 3.4 实测踩过的权限坑

本次实测中，唯一一次构建失败根因是执行身份缺少 `s3:CreateBucket`。现象链条是：脚本里 `aws s3 mb ... || true` 把 AccessDenied 吞掉，随后 `aws s3 cp` 报出令人困惑的 `NoSuchBucket`，看起来像桶不存在，实际是建桶的权限没有。修复有两层：在 IAM 策略中补上 `s3:CreateBucket`（策略文件本就包含，只是没有真正挂载）；在构建脚本中去掉 `|| true` 的静默吞错，只对幂等重跑会出现的 `BucketAlreadyOwnedByYou` 宽容，其余失败直接打印并退出，让权限问题第一次发生就暴露根因。

另一个实测观察：如果执行身份连 `iam:ListAttachedUserPolicies` 都没有，就无法自查策略挂载情况。诊断权限问题建议从最小动作开始逐层探测：`aws sts get-caller-identity` 确认身份，`aws s3 mb` 确认建桶，`aws --region <region> ec2 describe-import-snapshot-tasks` 确认 VM Import 查询权限。

---

## 4. 环境与配置

两处配置文件都需要操作者填写，且都被 .gitignore 排除，不会进入版本库；仓库各自保留了模板（`deploy/.env.example` 与 cloudtest 目录内说明）。

`deploy/.env` 是构建侧配置。本模块必填项为 `AWS_SNP_REGION`，限定为 eu-west-1；`GCP_PROJECT` 在 AWS 路径只是占位（构建脚本会强制其非空但实际不用于 AWS）。另一个关键项是 APT 镜像源选择 `SNP_APT_MIRROR`：默认值 `snapshot` 会把 Ubuntu 软件源固定到 snapshot.ubuntu.com 的不可变快照（确定性基础镜像，可复现），当该站点经本地代理访问不稳定（实测大量 502）时，可切换为 `aliyun` 走阿里云实时镜像把构建跑通。这个切换只影响诊断用基础镜像的摘要，信任根 R 与应用 bundle 摘要完全不受影响；生产可复现构建应切回 `snapshot`。

`cloudtest/.env` 是测试侧配置。`TOKENHIVE_USER` 是唯一必填项，它既是实例 Name 前缀的一部分，更是删除安全边界的另一半（`user` tag 的取值），绝不能留空或误填；`TOKENHIVE_REGION` 默认 eu-west-1；`TOKENHIVE_INSTANCE_TYPE` 默认 m6a.large，实测使用 c6a.large。

`deploy/snp-image/pins.env` 锁定了构建链上每个工具的精确版本：内核包、systemd 的 stub 与 ukify、zstd、cpio、binutils、sbsigntool、efitools，以及基础镜像摘要与 Go 工具链版本。这些锁定保证同一份源码在任何机器上重建出字节一致的镜像。

---

## 5. 构建 AMI（snp.sh build）

构建阶段从打包应用 bundle 开始，到注册 AMI 结束，内部是一条完整的流水线。执行：

```bash
cd tokenhive/cloudtest/snp
env -u PYTHONHOME -u PYTHONPATH ./snp.sh build
```

（`PYTHONHOME`/`PYTHONPATH` 在本机环境中被其他工具污染，会导致基于 Python 的 aws CLI 崩溃，显式清空是稳妥做法。）

第一步，`pack.sh` 把 loader 探针程序（`runner/main.go`）交叉编译为静态 amd64 二进制，并用 Python 的 tarfile 模块打成确定性的 bundle 归档：文件按名称排序、owner/group 固定为 0、mtime 固定为 2025-01-01 纪元值。确定性是硬要求，因为 bundle 的 SHA-256 就是 SNP_APP_HASH 与跨云应用身份 `snp-app:<hash>`，同样的输入必须产出同样的摘要，否则验证方锚定的值无法被重建。这一步输出 `snp-app:6944dc93...` 格式的摘要行。

白名单的**唯一定义**是一份文档：`tokenhive/policy/whitelist.json`。`policy.Default()` 读它，`-emit-policy-dir` 把它转成 `policy.cbor`（文档写 `version`/`hosts`/`rules`/`limits`；有效期窗口由代码统一盖成"永不过期"，文档里出现未知字段直接报错——为的是绝不静默丢掉一条规则）。`crosshost.sh build` 的 `ensure_policy` 在打包前用这份文档重新生成 `policy.cbor` 放进 `SNP_POLICY_DIR`：文档是确定性的，重新生成在文档未变时是空操作，这样改了文档一定进得了镜像，而不会沿用一份旧副本。

白名单策略与运行时代码一起打进被测 bundle：设置 `SNP_POLICY_DIR=<目录>`（目录内是唯一一份 `policy.cbor`，即 `LoadPolicy` 读取的文件）后，`pack.sh` 会把它原样拷进 bundle 的 `./policy/`（每个拓扑都做）。这既让 tee（`-policy-dir` 指向，运行期等价于 `TEE_POLICY_DIR` 环境变量）和单机 supervisor 拉起的 hub 读取同一份被测字节，也让白名单被 loader 的 SNP_APP_HASH 一并测量——**换白名单等于换镜像：它会改变 `snp-app:` 摘要与 PCR 8 预期值，而不是在运行期静默放宽外墙**。TEE 内没有改写白名单的代码路径，策略在部署时定死。**白名单对真实 TEE 是强制的**：TEE 以 `-platform sevsnp` 启动时，解析不到 `./policy/policy.cbor`（`shared.ResolvePolicyDir` 要求其必须存在）就直接 `log.Fatalf` 拒绝启动，绝不静默回退去加载一份自己物化的默认——因此不设 `SNP_POLICY_DIR` 打出的 sevsnp bundle，其 TEE 无法上线（`pack.sh` 只打一行 warning、不会拦阻断构建）。显式给出却装不下 `policy.cbor` 的目录在任何模式（含仿真）下都是启动错误；sevsnp 下显式目录只能复述被测字节，内容不一致同样拒绝启动——覆盖不能替代度量。仿真路径保持宽松：未显式配置且无白名单时，TEE 落回状态目录并物化默认文档。

第二步，`deploy/snp-build.sh` 编译 Secure Boot loader（`deploy/snp-image/loader`），然后在 Docker 内完成两层镜像组装（`snp-image/Dockerfile` + `tier-build.sh`）：基础 initrd 以 loader 为 /init，打入 AWS 需要的非内置内核模块（ena 网卡驱动、tsm_report、sev-guest 的 SEV 设备驱动）；ukify 用内核与 initrd 组装 UKI，并用 R.key/R.crt.pem 通过 sbsign 签名，随后 sbverify 验证签名；systemd-repart 把磁盘组装为 ESP 分区（放置签名 UKI）与一个独立的 96MB 原始分区（CopyBlocks 写入 app bundle）。这一步的日志会打印三行关键摘要：`base_uki_sha256`（基础 UKI 摘要，随应用变化稳定）、`app_sha256`（应用 bundle 摘要，即 SNP_APP_HASH）、`expected_PCR8`（PCR 8 的理论预期值）。

第三步，云打包（AWS 路径）：`qemu-img` 把原始磁盘转换为 streamOptimized 的确定性 VMDK，并修正其中 CID 字段的格式问题（qemu 用 %x 写出的短 CID 会被 AWS 误判为带父盘引用的增量盘而拒绝）；幂等创建暂存桶 `snp-vmimport-<账号ID>` 后上传 VMDK；发起 `import-snapshot` 并轮询直到 completed（实测约 8-10 分钟）；最后用 `register-image` 注册 AMI，关键参数包括 `--boot-mode uefi`、`--tpm-support v2.0` 与 `--uefi-data "$(cat aws-uefi-data.b64)"`——正是这一步把包含新 R 证书的 UEFI 变量存储写进镜像，实例启动后固件加载的就是这份 db。

构建成功的标志是日志出现 `AMI <ami-id> (snp-tokenhive) registered`。

---

## 6. 启动机密实例（snp.sh up）

`launch.py` 先以幂等语义确保基础设施：VPC、子网、互联网网关、安全组、密钥对，全部"先查后建"，重复执行不会产生重复资源。随后以 `CpuOptions={"AmdSevSnp": "enabled"}` 启动实例——这是实例真正获得机密内存的开关，AWS 会在实例 tag 上自动打上 `aws:ec2:sev-snp: ec2-sev_snp` 作为已启用机密计算的标志。实例启动即带双 tag（`tokenhive-TEE: true` 与 `user: <配置值>`），实例信息写入 `cloudtest/hosts.json`（仅作信息记录，删除不依赖它）：

```bash
./snp.sh up
```

该镜像没有 sshd，也没有登录方式；实例是"一次性自检机"：启动 → loader 测量应用 → 生成并自验证 attestation → 把结果打到串口控制台 → 自动关机。验证阶段读取的就是这份串口输出。

---

## 7. 验证 attestation（snp.sh verify）

`verify` 子命令轮询 EC2 的 `GetConsoleOutput`，把每次抓取的控制台输出写进 `logs/<时间戳>/<实例ID>.console.log`，直到出现结果行或超时：

```bash
./snp.sh verify
```

实测得到的成功结果是：

```text
SNP_TEST_RESULT matched=yes attestation_type=secure-boot app_hash=6944dc931575609749e855d73a50b550a64ab97adb1b7185f121b8022c2c2d86
```

`app_hash` 与第 5 节构建时打印的 `snp-app:` 摘要完全一致，说明实例上被 loader 测量的字节与本地打包的字节逐位相同。控制台日志里可以读到完整的硬件证据链：`Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP` 与 `SEV: SNP running at VMPL0` 证明机密内存与 VMPL0 层级已激活；`secureboot: Secure boot enabled` 与 `Loaded X.509 cert 'Reclaim Cross-Cloud Release Key: 95f1c88a...'` 证明固件在 Secure Boot 模式下加载了 db 中的 R 证书（重建 aws-uefi-data.b64 的直接效果）；`extended PCR 8 with app_sha256` 证明 loader 完成了对应用的 TPM 度量；`app pid=89 uid=65532 broker pid=88` 证明根权限的 attestation broker 与普通权限的应用进程分流正确。这四行合在一起，就是"真实 TEE 在跑、跑的确实是我们打包的应用"的完整证明。

---

## 8. 清理（snp.sh down / delete-infra）

清理分两级。`down` 只删实例，`delete-infra` 才动网络基础设施（VPC、安全组等），两者都严格按双 tag 过滤。删除逻辑从不读取 hosts.json，只按 `tokenhive-TEE: true` 与 `user: <配置值>` 两个 tag 描述实例，其中 user 值必须与配置完全匹配——这是"绝不误删他人机器"的结构性保证，而不是约定俗成。先预演再执行是安全的操作习惯：

```bash
./snp.sh down --dry-run    # 列出将被终止的实例，什么都不删
./snp.sh down              # 真正终止（输出每台被终止的实例 ID）
./snp.sh status            # 随时确认双 tag 范围内的存活实例
```

实测一次完整测试后的收尾输出是 `terminated: i-070b6fa8d1bc1aed4`，随后 status 返回空，双 tag 范围内无残留。

---

## 9. 真实业务闭环：单机与双机两种拓扑

第 5-8 节的 `snp.sh` 跑的是"一次性自检机"：实例启动后 loader 测量应用、生成并自验证 attestation、把结果打到串口后自动关机，全程没有真正的业务流量。真实业务闭环（`crosshost.sh`）则把 TokenHive 的完整调用链搬进机密实例：`hub → tee → provider agent → mockprovider`，让一次真实的聊天请求穿过真实的 RA-TLS（Remote Attestation TLS，远程证明传输层安全）mTLS 请求面与真实的 WebSocket 反向隧道上游面。

### 9.1 两种拓扑

**双机（cross-host）拓扑**：一台普通 EC2 实例运行 hub（请求网关）、provider agent（上游代理）与 mockprovider（模拟模型服务）；一台 SEV-SNP 机密实例运行真正的 `tee` 二进制（loader 的 broker/app 双进程模式）。hub 通过 mTLS（mutual TLS，双向传输层安全）主动连接 tee 的 `/v1/execute` 请求面；tee 通过 WebSocket 反向隧道连接 hub 的 `/v1/relay` 上游面，经 agent 隧道访问 mockprovider。这种形态最接近生产部署：hub 与 provider agent 可以位于家庭私有网络（只有反向隧道出站，无需入站端口）。

**单机（single）拓扑**：只用一台 SEV-SNP 机密实例，其 bundle 的 `./app` 是 supervisor（`tokenhive/cmd/single`），它在实例内以 loopback 依次拉起 mockprovider、真正的 tee、hub 与 provider agent；hub 对 tee 采用与双机完全相同的 attestation 校验（`-tee-verify attestation`）。所有组件都在同一台机密实例内闭环，不需要普通主机。这种形态用于验证"整条业务链都在 TEE 度量范围内"的最强隔离，也方便在没有第二台机器时做端到端回归。

两种拓扑共用同一个 bundle：`pack.sh` 的 `TOKENHIVE_BUILD_SINGLE=1` 模式把 supervisor 打成 `./app`、四个真实服务打成 `./svc/*`，并附上 hub 的 mTLS 身份（`./mtls/{hub-ca,hub-cert,hub-key}.pem`）；默认模式则把真实 tee 打成 `./app` 并附 hub-ca。supervisor 在 `TOKENHIVE_SUPERVISE=1` 时执行整个单机闭环，未设置时只是 `exec ./svc/tee`，行为与双机 bundle 完全一致——同一个镜像文件可以按 user-data 切换拓扑。每个拓扑都会把 `SNP_POLICY_DIR` 指向的白名单备份进 bundle 的 `./policy/`（受与 `./app` 相同的 SNP_APP_HASH 测量，见第 5 节）；单机 supervisor 在 bundle 带 `./policy` 时会给 tee 与 hub 都传 `-policy-dir`，令二者读取同一份被测策略。

### 9.2 构建两种 AMI

`crosshost.sh build` 构建双机 AMI（`snp-tokenhive`），`crosshost.sh build-single` 构建单机 AMI（`snp-tokenhive-single`）。两者都先由 `gencerts` 生成一组 TLS 固定件到 `snp/.certs/`：hub↔tee 的 mTLS 身份（`hub-ca/hub-cert/hub-key.pem`）与 mock AI provider 的 TLS 身份（`mp-ca/mp-cert/mp-key.pem`）。随后 `pack.sh build` 打出确定性 bundle（其 SHA-256 即 `snp-app:` 摘要，也是 PCR 8 的度量对象），最后 `deploy/snp-build.sh` 编译 loader、组装两层镜像并注册 AMI。

构建单机 AMI 时会额外把 hub 的 `hub-cert.pem`/`hub-key.pem` 与 mockprovider 的 `mp-cert.pem`/`mp-key.pem` 打进 bundle，因为单机模式下 hub 与 mockprovider 也在这台机密实例里；双机模式则只把两个 CA（`hub-ca.pem`、`mp-ca.pem`）打进 bundle，客户端证书/私钥通过 `deploy` 上传到普通主机。**CA 覆盖能力是构建成败的关键**：`ensure_certs` 只在首次生成、此后跨构建复用，以确保同一套 CA 同时签发包进 AMI 的 bundle 与部署到普通主机的证书——任一构建重新生成 CA 都会让之前构建的 AMI 静默失效（其 tee 会依新 CA 拒绝旧 hub 客户端证书）。

```bash
cd tokenhive/cloudtest/snp
./crosshost.sh build          # -> snp-tokenhive AMI（双机）
./crosshost.sh build-single   # -> snp-tokenhive-single AMI（单机）
```

### 9.3 机密实例的配置注入与信任建立

机密实例没有 sshd，其运行配置完全由 loader 从 EC2 user-data 注入为环境变量：`TEE_ADDR`（mTLS 请求面监听地址）、`TEE_RELAY`（双机模式的反向隧道地址）、`TEE_PLATFORM=sevsnp`（强制真实 attestation，非 SNP 环境直接失败）、`TEE_MTLS=1`（RA-TLS + 要求 hub 客户端证书）、`TEE_CA=/run/bundle/mtls/mp-ca.pem`（mock provider 的 CA 打进被测 bundle，**追加**在平台自身的信任根之上，而不是取而代之：sevsnp 的平台根正是被度量 bundle 里的 `./etc/ssl/certs/ca-certificates.crt`，由 loader 经 `SSL_CERT_FILE` 指给飞地，见 9.6 的信任库条目）。策略目录**不在**这份 user-data 里：tee 的 `-policy-dir`/`TEE_POLICY_DIR` 留空，于是按默认规则直接取被测 bundle 的 `./policy` 本体（sevsnp 下该文件必须存在，否则拒绝启动）。tee 的每个命令行 flag 都支持从同名环境变量回退取值，因此被测 bundle 保持字节一致，运行时路由完全由 VM metadata 决定。

mockprovider 也改用固定身份：`-ca/-cert/-key` 三个 flag 让它加载并复现 bundle 内 `mtls/mp-*.pem` 的身份，并把 CA 复写到 `TOKENHIVE_SIM_DIR/ca.pem`（供 agent 拉取模型列表时信任该模拟提供商）。这正是真实闭环的必要条件——tee 与 mockprovider 分处不同主机，CA 必须随被测 bundle 度量进 TEE，而非运行时从无 sshd 的机密实例经不可信路径传递。

**信任建立：attestation，不是证书固定。** hub 以 `-tee-verify attestation` 启动，它不比对任何本地证书文件，而是校验 tee 在握手时出示的 RA-TLS 叶**内部嵌的 SEV-SNP 证据**：证据须链到 AWS/AMD 根、须与那张叶自己的公钥绑定（证据不能被搬到别的密钥上）、并经 `-expected-app snp-app:<sha256>` 收敛到被测应用的精确字节。之所以必须是这个模式：`TEE_PLATFORM=sevsnp` 的实例会**持续轮换**它的 attested epoch（NitroTPM 证据只有小时级有效期），一次启动只固定一次的叶证书在第一个刷新周期后就不再匹配。attestation 模式没有任何需要重新分发的东西，因此轮换对部署完全不可见。

> 取叶诊断走 mTLS 端口本身：运维在普通主机上以 hub 客户端身份（`mtls/hub-cert.pem`、`mtls/hub-key.pem`）对 tee 的 18090 做一次 TLS 握手，即可读到监听器当前所持的那张叶证书（`./crosshost.sh fetch`）。它**不是**信任链的一环——hub 校验叶内嵌的证据，取回什么都不会改变 hub 的判定。单机模式下 supervisor 以拨号探针等待 tee 的 mTLS 端口 accept，作为"tee 已可服务"的启动顺序。

### 9.4 双机运行全流程

```bash
./crosshost.sh up            # 启动普通主机 + 机密 tee（幂等，可复用未删除的实例）
./crosshost.sh fetch         # 经 mTLS 端口取回 tee 当前的 RA-TLS 叶到 .certs/tee-cert.pem（只供人工核对，不参与信任）
./crosshost.sh deploy        # 上传 hub/agent/mockprovider 与证书到普通主机并启动
./crosshost.sh drive         # 通过 hub 发送 2 次真实 chat 请求
./crosshost.sh verify        # 打印 hub/agent/mockprovider 日志 + tee 控制台（attestation 证据）
./crosshost.sh down          # 严格按双 tag 终止两台实例
```

`up` 用幂等语义确保 VPC、子网、安全组、密钥对"先查后建"，并把跨主机端口（18085 hub relay、18090 tee）在安全组内放行（源为安全组自身，仅组内成员互通）。普通主机先启动，其公网 IP 自动注入 tee 的 `TEE_RELAY`。`up` 会把**所启动镜像自己携带的摘要**记录进状态（`crosshost.json` 的 `tee.app_hash`）：`snp-build.sh` 注册镜像时用 `snp-app` 标签写下它内嵌的 bundle 摘要，`up` 读这个标签而不是本地 `bin/`——本地 bundle 每次构建都会被覆盖（`build-single` 共用同一路径），而一次「打好了包、却在注册镜像前失败」的构建会让本地文件描述一个任何镜像都不包含的应用。hub 必须把它写成 `-expected-app snp-app:<hash>` 才能接受这篇由 loader 度量的应用的证明。`deploy` 在启动 hub 时带上 `-tee-verify attestation -allowed-platforms aws-sev-snp -expected-app snp-app:<hash>`：第一项让 hub 以证书内嵌的证据校验 tee（而不是比对一张本地固定证书，见 9.3），`-allowed-platforms aws-sev-snp` 令 hub 放行真实 SEV-SNP 平台（默认值 `simulated` 会拒绝真实证明），`-expected-app` 把应用身份锚定到被测 bundle 的精确字节。三者缺一不可：attestation 模式**要求**有 `-expected-app`（否则 hub 拒绝启动），并**拒绝**同时给出 `-mtls-ca`。白名单同样按那个身份取：每次 `build` 都把 bundle 归档到 `bin/bundles/<sha256>.tar`（键就是它被测出的摘要），`deploy` 按状态里的 `app_hash` 取回对应归档、从其 `./policy/policy.cbor` 抽出白名单，上传到 `~/policy/policy.cbor`，并以 `-policy-dir "$HOME/policy"` 让 hub 读取——上传点与读取点由同一个变量派生，不会再各写一份而漂移。**取不到能测出该摘要的归档时 `deploy` 直接报错退出**，绝不退而使用「当前构建的那一份」：否则「改了白名单 → 重新构建 → 却部署更早启动的实例」会让 hub 按一套规则准入、而飞地执行另一套。TEE 侧通常无需配置：sevsnp 启动时默认从 `/run/bundle/policy` 加载被测白名单（`shared.ResolvePolicyDir`）；显式 `-policy-dir`/`TEE_POLICY_DIR` 只能复述该目录的精确字节（不一致即拒绝），缺失 `policy.cbor` 同样直接拒绝启动（白名单对真实 TEE 强制，见 §5）。多 vendor 部署（OpenAI 与 Anthropic 卖家并存）时，hub 另需 `-provider-hosts provider=host:port,...` 声明各卖家的上游，未列出的 provider 走 `-host` 默认；该 host 必须在白名单内（上线准入即查），且必须落在对应 agent 的 `-targets` 内，否则流打不开。实测闭环中，hub 日志出现 `relay` 建立与 `chat/completions` 响应即代表请求面与上游面都真实走通；tee 控制台出现 `Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`、`SEV: SNP running at VMPL0` 与 `extended PCR 8 with app_sha256` 即代表硬件机密内存与度量链激活。

**TEE 的日志发到哪：`TOKENHIVE_TEE_INSTANCE_PROFILE`。** `up` 启动机密实例时，若该环境变量非空（如 `tokenhive-tee-logs`），就把它作为 `IamInstanceProfile` 挂上。AWS 上 tee 的结构化日志正是用这个实例角色发往 CloudWatch Logs（`shared/logger_cloudwatch_linux.go`，日志组默认 `/reclaim-tee/snp`，流名 = 服务名 + 主机名）。不挂也能跑，但那台飞地一条日志都发不出去——SDK 照常建好客户端，每次 ship 都被丢弃——只剩串口控制台，而控制台只保留几分钟。实例角色是 `RunInstances` 时绑定的、事后改不了：`up` 复用一台既有实例时会打印它实际携带的角色名与本次请求的名字之差（复用不重放 user-data，这行提示是唯一会说出"你刚配的东西没生效"的地方）。角色/profile 需另外创建（运行 `crosshost.py` 的身份还需 `iam:PassRole`）；名字写错无需额外校验——`RunInstances` 直接拒绝，不会留下半配置的实例。`up` 把最终值记进 `crosshost.json` 的 `tee.instance_profile`（空串 = 未挂）。

### 9.5 单机运行全流程

```bash
./crosshost.sh up --single   # 只启动一台机密 tee（supervisor 模式）
./crosshost.sh verify        # 直接 dump 机密实例控制台（含 supervisor 各服务日志 + attestation）
./crosshost.sh down          # 严格按双 tag 终止实例
```

单机模式不启动普通主机，`fetch`/`deploy`/`drive` 都不适用（业务请求由 supervisor 在实例内通过 loopback 驱动）。`verify` 通过 EC2 控制台输出一次拿到 supervisor 的全部日志：mockprovider 的 TLS 服务、tee 的 mTLS 监听、hub 的 relay 与会话、agent 的隧道连接，以及 loader 的 attestation 证据行。

### 9.6 实测要点与故障

**PYTHONHOME/PYTHONPATH 被宿主工具污染导致 Python 崩溃**：本机某些工具会注入这两个环境变量，令 venv 的 python3 与裸 `python3`/aws CLI 报 `No module named 'encodings'`。`crosshost.sh` 顶部已统一 `unset` 二者，子步骤不再需要逐个 `env -u`。

**单机 AMI 启动后自动关机**：单机 bundle 需要 `./mtls/mp-ca.pem`（`pack.sh build` 经 `SNP_MP_CA/SNP_MP_CERT/SNP_MP_KEY` 或 `.certs/` 注入）。缺失时 tee 在 attestation 成功（控制台已打印 `policy hash bound into attestation evidence`）之后，因读不到该 CA 而 `log.Fatalf("upstream TLS config")` 退出，从未开始监听；supervisor 的拨号探针满 4 分钟超时后返回错误，loader 随即 powerOff 关机。诊断特征为控制台出现 `[tee] upstream TLS config: read CA /run/bundle/mtls/mp-ca.pem: no such file or directory` 与 `[loader] FATAL: TEE app exited`；mockprovider 同样加载这份身份，缺失时也会先于它退出。修复是先在 `.certs/` 生成齐全（`gencerts` 输出 `mp-ca/cert/key`）后再执行 `crosshost.sh build-single`，让 supervisor bundle 确实带上三个 `mp-*` 文件。

**上游 TLS 只发出一个 ClientHello 就断开（信任库被 `-ca` 替换掉了）**：`-ca`/`TEE_CA` 是**追加**到平台根，而不是替换——`tls.Config.RootCAs` 一旦非 nil 就整个接管系统信任库，所以把它实现成替换时，`TEE_CA=/run/bundle/mtls/mp-ca.pem` 会让飞地里一个公共根都不剩，任何真实上游（chatgpt.com、api.anthropic.com）都在证书校验处断掉。观测特征极不直观：hub 侧只有 `relay stream to "chatgpt.com:443" closed after Xms: sent 1560 bytes toward Bee, received 3870 bytes`。上行 1560 字节只够 ClientHello（该账号的 `Authorization` 头单独就要 1880 字节），下行 3870 字节正好是 ServerHello + 证书链——即飞地收到证书链后一个应用字节都没发出就断了。判据是 tee 启动日志里那一行 `upstream TLS trust: <source> -> N anchors`：`N` 为 0 说明根没进来（在 Linux 上 `SSL_CERT_FILE` 指向的文件不存在时，`x509.SystemCertPool()` 返回 **0 个 anchor 且 `err == nil`**，是一个静默的空池）。注意「烘焙进 bundle 的 CA」与「`TEE_CA`」是两件事：前者进系统根，后者只是追加项，所以看到 `[loader] SSL_CERT_FILE=/run/bundle/etc/ssl/certs/ca-certificates.crt` 与控制台正常启动，**并不能**说明 tee 实际用的就是它。核对 bundle 里到底有没有某个根时不要 `grep` PEM 文本（内容 base64 编码，明文 CN 不会出现），用 `openssl crl2pkcs7 -nocrl -certfile <bundle-ca> | openssl pkcs7 -print_certs -noout` 读 subject，或数 `BEGIN CERTIFICATE` 条数。

**hub 拒绝 tee 证明（app hash 不匹配）**：`up` 记录的是所启动镜像自带的 `snp-app` 标签，正常情况下与实例里 loader 度量的摘要一致。若仍不一致（AMI 由别的机器/检出构建，或 `crosshost.json` 被手改过），hub 会报 `verify receipt: attestation does not match the signing key`。对齐方法：从机密实例控制台的 `[loader] app_sha256 = <hash>` 读实际摘要，把 `crosshost.json` 的 `tee.app_hash` 与 hub 的 `-expected-app` 都调成该值。

**`up` 报 AMI `carries no snp-app tag`**：该镜像没有 `snp-app` 标签（不是本流水线注册的镜像）。重新 `./crosshost.sh build` 生成带标签的镜像即可；`up` 宁可拒绝也不会去猜一个摘要。

**`deploy` 报 `no archived bundle measuring snp-app:<hash>`**：状态里的 `app_hash` 在本地 `bin/bundles/` 里找不到能测出该摘要的归档——多为构建那个 AMI 时的归档已被清理，或镜像来自另一台机器。要么重建该实例所跑的应用，要么重新 `up`。这是刻意拒绝：用它去换一份「当前的」白名单，就等于让 hub 按飞地不执行的规则准入。

**TEE 的日志一条都没留下（实例没有 IAM instance profile）**：AWS 上 tee 的日志走 CloudWatch Logs，认证靠实例角色。没有 profile 时，SDK 会照常建好客户端而每一次 `PutLogEvents` 都被丢弃：飞地看起来在健康运行，实际把轮换失败、上游失败全丢了，只留串口控制台那几分钟。修复分两层：(1) 启动时就挂 profile（`TOKENHIVE_TEE_INSTANCE_PROFILE`，见 §9.4）；(2) sink 自证——`NewLogger` 只有在**真正成功 `PutLogEvents` 一条探针**之后才信任这个 sink，否则返回错误并回退到控制台输出（控制台本就是 `NewLogger` 的默认路径），此后每次丢包在 stderr 上每分钟最多报一次（`logger: cloudwatch sink is losing logs after N failed ships and M dropped events: ...`）。排查顺序：先在 tee 控制台找这行 sink 丢失提示或 `logger: cloudwatch sink ... cannot ship events`，再取当前 RA-TLS 叶算轮换余量。取叶走 mTLS 端口（实例无 sshd）：以 hub 客户端身份对 `18090` 握手并把链存成 `leaf.pem`（`./crosshost.sh fetch` 存到 `.certs/tee-cert.pem`），再 `go run ./tokenhive/cloudtest/probe_ratls leaf.pem` —— 它从叶里的 NitroTPM 证据直接读出两个截止时刻：`admission`（叶自己的 `NotAfter`，握手在此停止，也正是 hub 链校验比较的时刻）与 `signing deadline`（`NotAfter − SNPSigningMargin`，出 receipt 在此停止，也是轮换瞄准的时刻），以及下一次重试时刻与两者之差 `slack`。`slack` 归零意味着轮换正好排在签名截止时刻，一次拿不到新叶的失败会立刻变成至少 `minRefreshFloor`(2m) 的**拒服务**（receipt 停发）；但**握手不断**——准入一直延续到叶自己的 `NotAfter`。3 小时叶＋2 小时上限下 `slack` 稳定在 55 分钟左右（约 27 次重试窗口）。排查顺序上要注意：`admission` 之前没有任何"到点就拒"的人工余量，所以一旦这里报 `past the leaf's NotAfter`，就是轮换真的连续失败到了叶子本身过期。

**串口控制台被 fail-closed 监听器的报错刷爆**：tee 的 mTLS 监听在 `GetCertificate` 返回 `ErrNotReady` 时拒绝握手（fail-closed），而 hub 会不停重试，于是"每个重试一行"足以在几分钟内把控制台（唯一在 sink 损坏后仍存活的通道）填满：实测缓冲 682 行里有 679 行是同一句话，loader 的启动行与 attestation 设备相关的内核消息已被挤出。`cmd/tee/listenerlog.go` 现在把**原因相同**的失败（丢掉对端地址后按原因聚合）折叠为前几条原文 + 每分钟一条计数汇总，既不刷屏也不会把"仍在坏"误读成"已恢复"。

**删除永远按双 tag**：`down` 通过 `delete.py` 只匹配同时携带 `tokenhive-TEE: true` 与 `user: <配置值>` 的实例，绝不读取 hosts.json/crosshost.json，绝不触碰其他用户的机器。先 `down --dry-run` 预演是安全习惯。

**单机控制台日志看起来"重复"**：这是设计使然，不是缺陷。loader 会把同一 `./app` 启动两次——一次作根权限的 attestation broker（走 `execTee`，转成 `svc/tee`，直接写控制台），一次作普通权限的应用（`supervise()` 里再拉起一个 `svc/tee` 负责 mTLS 服务，经统一前缀写到控制台）。于是控制台会看到 broker 的 tee 日志与 supervisor 调度的 tee 日志，两者的启动/attestation 行形态相似，观感上像重复输出。broker 路径不能静默，否则会丢失硬件证明的关键证据，因此保留两块输出并靠 `[tee]` 前缀等人造边界区分，是刻意取舍。

---

## 10. 故障排查

**构建时 APT 大量 502**：snapshot.ubuntu.com 的不可变快照服务经本机代理访问不稳定。在 `deploy/.env` 设置 `SNP_APT_MIRROR=aliyun` 切换到阿里云实时镜像即可跑通；生产可复现构建切回 `snapshot`。

**上传 VMDK 报 NoSuchBucket**：几乎总是 `s3:CreateBucket` 权限缺失，而不是桶不存在。按第 3.4 节补权限，脚本现在也会直接把真实错误打出来。

**启动报不支持 SEV-SNP**：区域不对。SEV-SNP 只有 eu-west-1 与 us-east-2；实例类型必须是 m6a/c6a/r6a 家族。

**本地 aws CLI 崩溃（Python encodings 错误）**：`PYTHONHOME`/`PYTHONPATH` 被外部工具污染。执行前 `env -u PYTHONHOME -u PYTHONPATH` 清空。

**SNP_APP_HASH 未设置**：应用绕过了 loader 直接运行（例如手动放进 Ubuntu 镜像）。SNP_APP_HASH 由 loader 注入，只有被 loader 引导的应用进程才能拿到；本模块的探针正是为此验证"loader 注入的值与 attestation 绑定的值一致"。
