---
title: "Keystone 和 TrustZone 后端开发"
summary: "为 OpenClaw trusted isolation 开发 Keystone 与 TrustZone 后端的实现指南"
read_when:
  - 你要为 OpenClaw 的 trusted isolation 接入 Keystone 或 TrustZone
  - 你希望在不修改 OpenClaw 核心逻辑的前提下实现新平台后端
  - 你需要明确 authorize complete confirm 合同和联调验收要求
---

# Keystone 和 TrustZone 后端开发

这份文档面向实现 OpenClaw trusted isolation 平台后端的开发者，目标是为 `TrustZone` 和 `Keystone` 提供可落地的后端开发约束、实现步骤和验收方式。

前提结论先写清楚:

- OpenClaw 核心当前按统一 trusted backend 合同工作
- 平台差异应尽量收敛在各自的 TEE 后端服务
- 只要后端继续兼容现有 HTTP 合同和签名语义，通常不需要修改 OpenClaw 核心代码

建议先配合阅读:

- [Cross-Platform Trusted Backends](/cross-platform-trusted-backends)
- [Trusted Isolation Design](/trusted-isolation-design)
- [Trusted Isolation Testing](/trusted-isolation-testing)
- [TDX Guest](/install/tdx-guest)

## 目标和边界

Keystone 和 TrustZone 后端的目标不是把平台内部细节暴露给 OpenClaw，而是把平台特定的安全世界调用、enclave RPC、证明材料采集和归一化逻辑封装在 trusted backend 内部。

OpenClaw 侧只依赖这些稳定能力:

- 规范化后的请求生成
- `/v1/trusted/authorize` 决策返回
- `scopeToken` 校验
- `/v1/trusted/complete` 完成上报
- 如果需要人工确认，则使用 `/v1/trusted/confirm`
- `evidence` 中返回统一的 proof 元数据

不要做的事:

- 不要在 OpenClaw 核心里新增 `if platform === "trustzone"` 或 `if platform === "keystone"` 这样的分支
- 不要修改 OpenClaw 请求结构来适配某个平台私有协议
- 不要引入新的 `decision`、`executionMode` 或 token 语义，除非你准备同时改 OpenClaw 校验逻辑

## OpenClaw 如何选择 TEE 后端

OpenClaw 不是通过某个内部 adaptor 名称来选择 TrustZone、Keystone 或 TDX，而是通过配置里的 trusted backend 地址来决定调用哪个后端服务。

关键配置是:

- `tools.trustedIsolation.enabled`
- `tools.trustedIsolation.backendBaseUrl`
- `tools.trustedIsolation.authorizePath`
- `tools.trustedIsolation.completePath`
- `tools.trustedIsolation.verify.mode`

也就是说:

- 指向 TDX guest backend 的 `backendBaseUrl`，就是走 TDX
- 指向 TrustZone backend service 的 `backendBaseUrl`，就是走 TrustZone
- 指向 Keystone backend service 的 `backendBaseUrl`，就是走 Keystone

OpenClaw 侧不需要知道你的后端内部是 `SMC`、共享内存、vsock、RPC 还是 enclave runtime。

## 推荐实现路径

### 路径一

首选方案是为 `TrustZone` 和 `Keystone` 分别实现独立的 trusted backend service，只要求它们兼容 OpenClaw 当前的统一 HTTP 合同。

这个方案的优点:

- OpenClaw 客户端完全不需要改
- 后端服务可以按各自平台特点演进
- OpenClaw 的联调方式保持一致
- 可以直接复用现有 smoke 和合同测试思路

适用于:

- 你已经有自己的 TrustZone secure world 服务
- 你已经有自己的 Keystone enclave 服务
- 你希望每个平台独立维护部署、签名和证明逻辑

### 路径二

如果你想快速起步，可以把 `external/openclaw-trusted-backend` 当成当前 TDX 参考实现和合同样板，按它的行为实现你自己的 TrustZone 或 Keystone 后端服务。

这个方案的价值在于:

- 可以直接对照现有请求和响应行为
- 可以复用当前 token、confirm 和日志语义
- 可以先按行为兼容，再逐步接真实 TEE transport

需要注意:

- `external/openclaw-trusted-backend` 当前是 TDX canonical backend 来源
- 那里面的 `trustzone-remote-backend` 和 `keystone-remote-backend` 占位分支不应被当成正式实现路线
- 真正的 TrustZone 和 Keystone 接入，应该是独立后端服务对外暴露统一合同

## 总体架构

### TrustZone

推荐的逻辑链路:

```text
OpenClaw REE
  -> backendBaseUrl 指向的 TrustZone backend service
    -> REE proxy
      -> shared memory / SMC
        -> secure world service
          -> 证明材料与决策结果
        <- 归一化 proof
    <- 统一 authorize / complete / confirm 响应
```

### Keystone

推荐的逻辑链路:

```text
OpenClaw REE
  -> backendBaseUrl 指向的 Keystone backend service
    -> REE host runtime
      -> enclave RPC
        -> enclave service
          -> 证明材料与决策结果
        <- 归一化 proof
    <- 统一 authorize / complete / confirm 响应
```

### 关键原则

- OpenClaw 只看到统一 HTTP 合同
- 后端负责把平台原始返回转换成统一 `evidence.proof`
- 平台内部 transport 细节不能泄漏到 OpenClaw 请求结构
- token 的签发和验证语义必须保持稳定

## 必须兼容的 HTTP 合同

后端至少要提供:

- `GET /healthz`
- `POST /v1/trusted/authorize`
- `POST /v1/trusted/complete`

如果后端可能返回 `decision = "duc"`，还必须提供:

- `POST /v1/trusted/confirm`

如果你希望调试平台 guest 或 enclave 状态，建议保留:

- `GET /v1/trusted/guest`

### healthz

建议至少返回:

```json
{
  "ok": true,
  "mode": "ed25519",
  "adaptor": "trustzone-remote-backend",
  "platform": "trustzone"
}
```

如果能安全暴露，也可以带上:

- policy 版本
- guest 或 enclave 基本身份信息
- 当前后端签名模式

### authorize 请求

OpenClaw 发来的 authorize 请求核心字段如下:

```json
{
  "version": 1,
  "reqId": "0d44d143-2fb9-40bb-a842-8dc5f94d7f0c",
  "sid": "session-123",
  "seq": 1,
  "ttlMs": 15000,
  "issuedAtMs": 1760000000000,
  "toolName": "exec",
  "action": "exec",
  "object": "echo hello",
  "scope": {
    "action": "exec",
    "target": "echo hello",
    "exec": {
      "matchMode": "exact",
      "rawCommand": "echo hello",
      "command": "echo",
      "args": ["hello"]
    }
  },
  "context": {
    "sessionId": "session-123",
    "workspaceRoot": "/workspace"
  },
  "level": "L2",
  "normalizedScopeDigest": "sha256:...",
  "requestDigest": "sha256:..."
}
```

你不需要重新定义这些字段。后端只需要:

- 校验输入是否完整
- 基于同一份 canonical request 做决策
- 返回与之匹配的 `normalizedRequest`

### authorize 响应

后端必须返回下列稳定字段:

```json
{
  "allow": true,
  "decision": "dia",
  "level": "L2",
  "executionMode": "ree-constrained",
  "reason": "command requires constrained execution",
  "matchedRuleId": "exec.action.high-risk",
  "normalizedRequest": {
    "version": 1,
    "reqId": "0d44d143-2fb9-40bb-a842-8dc5f94d7f0c",
    "sid": "session-123",
    "seq": 1,
    "ttlMs": 15000,
    "issuedAtMs": 1760000000000,
    "toolName": "exec",
    "action": "exec",
    "object": "echo hello",
    "scope": {
      "action": "exec",
      "target": "echo hello"
    },
    "context": {
      "sessionId": "session-123"
    },
    "level": "L2",
    "normalizedScopeDigest": "sha256:...",
    "requestDigest": "sha256:..."
  },
  "classification": {
    "actionRisk": {
      "level": "L2",
      "reason": "high-risk exec",
      "matchedRuleId": "exec.action.high-risk"
    },
    "objectRisk": {
      "level": "L0",
      "reason": "workspace object",
      "matchedRuleId": "object.ordinary.workspace",
      "classification": "ordinary"
    },
    "contextRisk": {
      "level": "L0",
      "reason": "trusted context",
      "matchedRuleId": "context.default",
      "factors": {}
    },
    "effectRisk": {
      "level": "L2",
      "reason": "command may mutate state",
      "matchedRuleId": "effect.exec",
      "factors": {}
    },
    "contextFlags": {
      "destructive": false,
      "export": false,
      "multi_step": false,
      "outside_workspace": false,
      "protected_path": false,
      "remote_target": false,
      "shell_wrapper": false,
      "task_mismatch": false,
      "user_absent": false
    },
    "effectFlags": {
      "destructive": false,
      "export": false,
      "multi_step": false,
      "outside_workspace": false,
      "protected_path": false,
      "remote_target": false,
      "shell_wrapper": false,
      "task_mismatch": false,
      "user_absent": false
    },
    "finalRiskLevel": "L2",
    "decision": "dia",
    "reason": "command requires constrained execution",
    "matchedRuleId": "exec.action.high-risk"
  },
  "scopeToken": "<signed-token>",
  "evidence": {
    "backend": "openclaw-trusted-backend",
    "adaptor": "trustzone-remote-backend",
    "platform": "trustzone",
    "proofPath": "ree-proxy",
    "proof": {
      "platform": "trustzone",
      "adaptor": "trustzone-remote-backend",
      "matchedRuleId": "exec.action.high-risk"
    }
  }
}
```

必须满足的兼容性约束:

- `decision` 只能使用 `dree`、`dia`、`die`、`duc`、`ddeny`
- `executionMode` 只能使用 `ree-direct`、`ree-constrained`、`isolated`
- `level` 只能使用 `L0`、`L1`、`L2`、`L3`
- `normalizedRequest` 必须与请求的关键字段保持一致
- 当 `allow = true` 且 `executionMode !== "ree-direct"` 时，必须返回 `scopeToken`
- `classification` 必须存在，不能省略

不要做的兼容性破坏:

- 不要新增 OpenClaw 不认识的 `decision`
- 不要把 `normalizedRequest` 改成平台内部格式
- 不要把 `scopeToken` 改成只对平台 transport 可见的私有载荷

### confirm 流程

如果后端返回 `decision = "duc"`，OpenClaw 会先请求外部审批，再调用 `/v1/trusted/confirm`。

所以你的后端必须支持:

1. 在 `authorize` 响应里返回 `confirmation`
2. 保存待确认状态
3. 在 `confirm` 收到批准后重新发放 `scopeToken`
4. 在确认被拒绝或过期时返回可判定状态

推荐的确认响应最小结构:

```json
{
  "ok": true,
  "confirmationRequestId": "confirm-123",
  "status": "approved",
  "decision": "dia",
  "level": "L2",
  "executionMode": "ree-constrained",
  "reason": "operator approved trusted confirmation",
  "matchedRuleId": "exec.action.high-risk",
  "normalizedRequest": {
    "version": 1,
    "reqId": "0d44d143-2fb9-40bb-a842-8dc5f94d7f0c",
    "sid": "session-123",
    "seq": 1,
    "ttlMs": 15000,
    "issuedAtMs": 1760000000000,
    "toolName": "exec",
    "action": "exec",
    "object": "echo hello",
    "scope": {
      "action": "exec",
      "target": "echo hello"
    },
    "context": {
      "sessionId": "session-123"
    },
    "level": "L2",
    "normalizedScopeDigest": "sha256:...",
    "requestDigest": "sha256:..."
  },
  "confirmedAtMs": 1760000005000,
  "operatorId": "approval:confirm-123",
  "scopeToken": "<signed-token>"
}
```

### complete 请求

`complete` 主要用于把执行完成态和摘要回写 trusted backend，后端不应把它当成新的 authorize。

请求重点字段:

- `reqId`
- `sid`
- `toolName`
- `action`
- `object`
- `level`
- `decision`
- `executionMode`
- `matchedRuleId`
- `normalizedScopeDigest`
- `requestDigest`
- `startedAtMs`
- `finishedAtMs`
- `durationMs`
- `status`
- `resultDigest`
- `errorCode`
- `errorMessage`
- `context`

建议响应最小结构:

```json
{
  "ok": true,
  "adaptor": "keystone-remote-backend",
  "platform": "keystone",
  "proof": {
    "platform": "keystone",
    "adaptor": "keystone-remote-backend",
    "phase": "complete",
    "reqId": "0d44d143-2fb9-40bb-a842-8dc5f94d7f0c"
  }
}
```

## 平台 proof 设计建议

`evidence.proof` 的目标不是复刻平台原始返回，而是为审计和排障提供可稳定消费的摘要。

建议保留这些公共字段:

- `platform`
- `adaptor`
- `proofPath`
- `matchedRuleId`
- `reqId` 或平台内部请求关联 ID
- attestation 或 measurement 摘要
- transport 类型摘要

### TrustZone proof

建议包含:

- `platform: "trustzone"`
- `adaptor: "trustzone-remote-backend"`
- `proofPath: "ree-proxy"`
- `teeCall: "smc/shared-memory authorize"` 或更具体的动作名
- `worldId` 或 secure world service 标识
- `measurementSha256` 或 image/version 摘要
- `nonceBound: true`

示例:

```json
{
  "platform": "trustzone",
  "adaptor": "trustzone-remote-backend",
  "proofPath": "ree-proxy",
  "teeCall": "smc/shared-memory authorize",
  "matchedRuleId": "exec.action.high-risk",
  "worldId": "tz-os:v1",
  "measurementSha256": "sha256:...",
  "nonceBound": true
}
```

### Keystone proof

建议包含:

- `platform: "keystone"`
- `adaptor: "keystone-remote-backend"`
- `proofPath: "ree-proxy"`
- `teeCall` 或 `enclaveCall`
- `enclaveId`
- `measurementSha256`
- `attestationReportSha256`
- `nonceBound: true`

示例:

```json
{
  "platform": "keystone",
  "adaptor": "keystone-remote-backend",
  "proofPath": "ree-proxy",
  "teeCall": "enclave authorize",
  "matchedRuleId": "exec.action.high-risk",
  "enclaveId": "keystone-enclave-01",
  "measurementSha256": "sha256:...",
  "attestationReportSha256": "sha256:...",
  "nonceBound": true
}
```

## 签名和密钥管理

开发阶段可以先用 `hmac-sha256`，但生产建议尽快切到 `ed25519`。

### 开发阶段

- `TRUSTED_VERIFY_MODE=hmac-sha256`
- OpenClaw 与后端共享同一个 `TRUSTED_HMAC_KEY`

### 生产阶段

- `TRUSTED_VERIFY_MODE=ed25519`
- 私钥只保留在 trusted backend
- OpenClaw 只保存公钥
- `scopeToken`、`challengeToken` 都由后端签发

最重要的约束:

- 不要把私钥放到 OpenClaw 主机配置里
- 不要让 OpenClaw 自己生成 scope token
- 不要让 secure world 或 enclave 的私有签名格式直接泄漏成 OpenClaw 客户端合同

## TrustZone 开发建议

### 后端职责拆分

建议分成三层:

1. HTTP 层
2. REE proxy 层
3. secure world service 层

各层职责建议如下:

1. HTTP 层负责接 OpenClaw 请求、返回统一 JSON、管理签名和确认流
2. REE proxy 层负责共享内存分配、参数编组、SMC 调用和超时处理
3. secure world service 层负责平台内部校验、可选 attestation 采样和 proof 原始结果生成

### 实现重点

- 统一超时策略，避免 secure world 卡死导致 OpenClaw 长时间挂起
- 所有 secure world 返回都要做长度、版本和字段校验
- 不要把共享内存布局直接映射成外部 API
- proof 要做归一化，不要把原始二进制 blob 直接塞进 `evidence`

### 推荐最小开发顺序

1. 先打通 `authorize` 占位调用
2. 再补 `complete`
3. 再补真实 measurement 或 attestation 摘要
4. 最后再加 `duc` 确认流

## Keystone 开发建议

### 后端职责拆分

建议分成三层:

1. HTTP 层
2. host runtime 层
3. enclave service 层

各层职责建议如下:

1. HTTP 层负责统一合同、签名、确认流、事件日志
2. host runtime 层负责 enclave 生命周期、RPC 编解码、重试和隔离边界
3. enclave service 层负责平台内部授权逻辑、可选 attestation 报告和 proof 原始结果生成

### 实现重点

- enclave RPC 要有明确版本号
- 每次 authorize 最好带 nonce 或 request digest 绑定
- attestation 报告建议返回摘要，而不是整份大对象
- enclave 重启、失效、measurement 变化都要体现在 proof 或 healthz 中

### 推荐最小开发顺序

1. 先让 REE host runtime 能稳定调用 enclave
2. 再把 proof 归一化成统一结构
3. 再接入 `complete`
4. 最后再补审批确认和 attestation 增强

## 事件日志和可观测性

建议沿用现有 backend 事件日志思路:

- 每次 `authorize` 记录一条事件
- 每次 `confirm` 记录一条事件
- 每次 `complete` 记录一条事件
- 记录 hash 链，保证跨重启连续性

至少记录这些关联字段:

- `reqId`
- `sid`
- `matchedRuleId`
- `decision`
- `executionMode`
- `platform`
- `adaptor`
- proof 摘要

不要把敏感原始密钥、完整 attestation 原文或平台私有大对象直接写入日志。

## TDX guest 后端怎么部署

这里单独说清楚一件事: `external/openclaw-trusted-backend` 不是只给本地开发看的，它也是当前 TDX guest backend 的 canonical 来源。只是实际部署通常不是手工进去复制 `env.example`，而是由脚本把它打包、拷进 guest、生成正式环境文件并安装 `systemd` 服务。

### 推荐部署路径

当前仓库里已经有一条完整脚本链:

1. `scripts/scaffold-trusted-backend-standalone.mjs`
2. `scripts/tdx/prepare-trusted-backend-tdx-guest.sh`
3. `scripts/tdx/install-trusted-backend-guest.sh`

职责分别是:

1. 从 `external/openclaw-trusted-backend` 导出 standalone backend 目录
2. 把 backend 和安装脚本打进 TDX guest 镜像
3. 在 guest 内安装目录、密钥、环境文件和 `systemd` 服务

### 一次性准备 TDX guest 镜像

如果你已经有 TDX base image:

```bash
sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
  --base-image /path/to/tdx-guest-ubuntu-24.04-generic.qcow2 \
  --artifact-dir /var/tmp/openclaw-tdx
```

如果你有 Canonical `tdx` 仓库，也可以直接让脚本从它生成:

```bash
sudo scripts/tdx/prepare-trusted-backend-tdx-guest.sh \
  --canonical-tdx-dir /path/to/tdx \
  --ubuntu-version 24.04 \
  --artifact-dir /var/tmp/openclaw-tdx
```

这个脚本会做这些事:

- 从 `external/openclaw-trusted-backend` scaffold backend
- 生成或复用 TDX guest 镜像
- 在镜像里执行 `install-trusted-backend-guest.sh`
- 自动生成 guest 侧 `ed25519` 密钥
- 导出 guest 公钥
- 生成 host 侧 `openclaw.json` 配置片段

产物重点看这两个:

- guest 公钥
- host 侧 trustedIsolation 配置片段

### guest 内实际安装结果

`scripts/tdx/install-trusted-backend-guest.sh` 在 guest 内会落这些关键文件:

- `/opt/openclaw-trusted-backend`
- `/etc/openclaw-trusted-backend/openclaw-trusted-backend.env`
- `/etc/systemd/system/openclaw-trusted-backend.service`
- `/etc/openclaw-trusted-backend/ed25519-private.pem`
- `/etc/openclaw-trusted-backend/ed25519-public.pem`
- `/var/lib/openclaw-trusted-backend/trusted-backend-events.jsonl`

也就是说，正式部署时真正生效的是:

- `/etc/openclaw-trusted-backend/openclaw-trusted-backend.env`
- `/etc/systemd/system/openclaw-trusted-backend.service`

不是仓库里的 example 文件本身。

### external 目录里几个 example 文件是干什么的

`external/openclaw-trusted-backend` 里常见这三个模板:

- `.env.example`
- `openclaw-trusted-backend.env.example`
- `openclaw-trusted-backend.service.example`

它们的定位分别是:

- `.env.example`
  - 本地手工启动 `node server.mjs` 时参考用
  - 默认是本地开发风格配置，比如 `127.0.0.1` 和相对路径日志目录
- `openclaw-trusted-backend.env.example`
  - guest 或服务器上跑 `systemd` 服务时的环境文件模板
  - 默认是生产部署风格配置，比如 `0.0.0.0`、`/etc/openclaw-trusted-backend`、`/var/lib/openclaw-trusted-backend`
- `openclaw-trusted-backend.service.example`
  - `systemd` unit 模板
  - 指向 `/opt/openclaw-trusted-backend/server.mjs` 和 `/etc/openclaw-trusted-backend/openclaw-trusted-backend.env`

之前你可能没有手工“部署过”这些 example，是因为脚本已经代替你做了两件事:

1. 把 `service.example` 装成正式 unit
2. 按当前安装参数生成真正的 `.env` 文件

### 安装后怎么启动和验证

guest 启动后，先看服务状态:

```bash
sudo systemctl status openclaw-trusted-backend.service
```

再看监听和健康检查:

```bash
ss -ltnp | rg 19090
curl http://127.0.0.1:19090/healthz
curl http://127.0.0.1:19090/v1/trusted/guest
```

如果 guest 对宿主可达，再从 host 测:

```bash
curl http://<tdx-guest-ip>:19090/healthz
```

### OpenClaw host 侧怎么指向它

OpenClaw host 侧只需要把 `backendBaseUrl` 指到 guest:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "enforceFailClosed": true,
      "backendBaseUrl": "http://<tdx-guest-ip>:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "requestTimeoutMs": 5000,
      "ttlMs": 5000,
      "verify": {
        "mode": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n<guest-public-key>\\n-----END PUBLIC KEY-----\\n",
        "requireScopeToken": true
      },
      "forceTrustedActions": ["exec"]
    }
  }
}
```

这里的公钥通常就是 `prepare-trusted-backend-tdx-guest.sh` 导出的那份。

### 如果你想手工部署

不走镜像脚本时，也可以手工部署:

1. 用 `scripts/scaffold-trusted-backend-standalone.mjs` 导出 backend
2. 把目录拷到 guest 的 `/opt/openclaw-trusted-backend`
3. 参考 `openclaw-trusted-backend.env.example` 生成 `/etc/openclaw-trusted-backend/openclaw-trusted-backend.env`
4. 参考 `openclaw-trusted-backend.service.example` 安装 `systemd` unit
5. 生成 `ed25519` 私钥和公钥
6. `systemctl enable --now openclaw-trusted-backend.service`

不过当前更推荐直接用仓库里的 TDX 脚本，因为它已经把 key、权限、日志路径和 service 用户都处理好了。

## 本地开发和联调

### TrustZone 和 Keystone 的联调方式

对 TrustZone 和 Keystone，建议直接联调你自己的 backend service，然后把 OpenClaw 的 `backendBaseUrl` 指过去。

例如:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "backendBaseUrl": "http://trustzone-backend.internal:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "verify": {
        "mode": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n<trustzone-backend-public-key>\\n-----END PUBLIC KEY-----\\n",
        "requireScopeToken": true
      }
    }
  }
}
```

或:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "backendBaseUrl": "http://keystone-backend.internal:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "verify": {
        "mode": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n<keystone-backend-public-key>\\n-----END PUBLIC KEY-----\\n",
        "requireScopeToken": true
      }
    }
  }
}
```

### 运行 OpenClaw 侧 smoke

如果你的 TrustZone 或 Keystone backend 已经独立部署，直接跑:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-smoke.ts \
  --backend-base-url http://<backend-host>:19090
```

### 运行定向测试

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
pnpm test -- src/security/trusted-isolation/tests
```

这一步主要用来检查:

- authorize 响应字段是否齐全
- token 是否可验证
- scope mismatch 是否 fail-closed
- backend 不可用时是否正确阻断
- evidence 链路是否完整

## 验收清单

Keystone 或 TrustZone 后端准备合入前，至少确认下面这些点全部成立:

- `healthz` 可用，并且能明确返回当前 `platform` 和 `adaptor`
- `authorize`、`complete` 兼容 OpenClaw 当前合同
- 如果支持 `duc`，`confirm` 也兼容当前合同
- `decision`、`executionMode`、`level` 没有引入新枚举
- `normalizedRequest` 与请求关键字段一致
- 非 `ree-direct` 的允许决策会返回 `scopeToken`
- `scopeToken` 在 OpenClaw 侧可以通过现有验证逻辑
- `evidence.proof` 能表达平台证据摘要，但不泄漏敏感原始材料
- backend 不可用、超时、格式错误时，OpenClaw 能保持 fail-closed
- `scripts/trusted-isolation-paper-smoke.ts` 能跑通
- `src/security/trusted-isolation/tests` 能通过与本改动相关的场景

## 常见错误

### 把平台细节塞进 OpenClaw 请求

错误做法是让 OpenClaw 直接感知 `SMC opcode`、共享内存布局、enclave 文件描述符或平台私有 RPC 字段。正确做法是把这些细节收敛在你的后端服务内部。

### 复用占位 proof 但修改返回语义

proof 可以逐步增强，但 `decision`、`executionMode`、`normalizedRequest` 和 `scopeToken` 语义不能漂移。

### confirm 只做状态记录，不重新签发 token

如果 `duc` 最终被批准，而响应里没有新 token，OpenClaw 后续执行会失败。`confirm` 不是日志接口，而是确认后的授权收口点。

### 把 attestation 大对象直接回传给 OpenClaw

OpenClaw 更需要稳定摘要，而不是平台专有原始大对象。建议回传 hash、measurement、nonce 绑定标记和版本信息。

## 建议的开发节奏

推荐按下面顺序推进:

1. 先定义独立 TrustZone 或 Keystone backend service 的 HTTP 合同实现
2. 先让 OpenClaw 能通过 `backendBaseUrl` 跑通 smoke
3. 再接真实 TrustZone 或 Keystone transport
4. 再补 proof 摘要和 attestation 摘要
5. 最后再补 `duc` 确认流、生产签名模式和部署加固

这样可以把兼容性风险和平台实现风险拆开，不会一开始就把问题混在一起。
