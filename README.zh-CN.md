# OpenClaw 中文说明

这个仓库基于上游 **OpenClaw**，当前这条分支主要围绕 `trusted isolation` 和 TEE 后端链路做了补充说明与落地整理，重点是把 OpenClaw 主体、trusted backend、TDX guest 部署，以及后续 Keystone / TrustZone 扩展之间的关系讲清楚。

如果你只想看上游项目总览，可以直接看英文首页 `README.md`。如果你想看这条安全链路在这个仓库里怎么组织、怎么部署、后面怎么扩平台，这份中文 README 更贴近当前改动。

## 上游 OpenClaw 是什么

**OpenClaw** 是一个运行在自己设备上的个人 AI 助手。它把你已经在用的聊天入口统一接到同一个 Gateway 上，让你可以通过 WhatsApp、Telegram、Slack、Discord、Signal、Google Chat、iMessage、Matrix、WebChat 等入口和自己的 AI 助手对话，同时还能接入浏览器、Canvas、设备节点、自动化任务和多代理路由。

上游入口：

- 项目主页：https://openclaw.ai
- 文档站：https://docs.openclaw.ai
- 英文 README：`README.md`
- 上游仓库：https://github.com/openclaw/openclaw

## 这个仓库当前改了什么

当前这部分工作，核心不是改 OpenClaw 的普通渠道逻辑，而是把 **trusted isolation -> trusted backend -> TEE 平台后端** 这条链路补齐并说明清楚。

当前明确下来的设计结论是：

- OpenClaw 主体继续按统一的 trusted backend HTTP 合同工作
- 具体跑的是 TDX、TrustZone 还是 Keystone，不由 OpenClaw 内部 adaptor 名字决定
- OpenClaw 通过 `tools.trustedIsolation.backendBaseUrl` 指向哪个后端服务，就走哪个 TEE 后端
- 平台差异应尽量收敛在各自后端服务内部，而不是把平台分支塞进 OpenClaw 核心

也就是说：

- 指向 TDX guest backend，就是走 TDX
- 指向 TrustZone backend service，就是走 TrustZone
- 指向 Keystone backend service，就是走 Keystone

## 当前已经落下来的重点

### 1. TDX 作为当前主链路

仓库里当前可直接参考的 canonical backend 在：

- `external/openclaw-trusted-backend`

这部分现在是 TDX 路线的参考实现和部署源，负责：

- `/healthz`
- `/v1/trusted/authorize`
- `/v1/trusted/complete`
- 按需提供 `/v1/trusted/confirm`
- TDX guest 身份和 attestation 相关信息输出

OpenClaw host 侧只需要把 trusted isolation 指到 guest backend：

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "backendBaseUrl": "http://<tdx-guest-ip>:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete"
    }
  }
}
```

### 2. Keystone / TrustZone 的接入方式被重新说明清楚

这两个平台后端的目标不是继续往 `external/openclaw-trusted-backend` 里塞占位分支，而是：

- 各自做独立 backend service
- 对 OpenClaw 暴露同一套 trusted backend 合同
- 由 OpenClaw 的 `backendBaseUrl` 配置决定实际连哪个后端

这样做的好处是：

- OpenClaw 主体不需要知道平台内部是 SMC、共享内存、vsock、RPC 还是 enclave runtime
- 不需要在核心代码里加 `if platform === "trustzone"` / `if platform === "keystone"` 这种分支
- 各平台的证明材料采集、策略判断和 transport 细节都能留在自己的 backend service 里

### 3. TDX guest 部署方式被补了文档

`external/openclaw-trusted-backend` 目录里的这些文件：

- `openclaw-trusted-backend.env.example`
- `openclaw-trusted-backend.service.example`
- `server.mjs`

不是“之前没部署过所以没用”的文件，而是 **guest 侧正式部署模板和源文件**。实际部署通常不是手工抄模板，而是通过脚本：

- 导出 standalone backend
- 拷进 guest
- 生成正式 env
- 安装 systemd service
- 再由 OpenClaw host 把 `backendBaseUrl` 指到 guest

## 当前建议先看哪些文件

如果你要继续做这条链路，先看这几个文件最省时间：

- `README.md`
- `README.zh-CN.md`
- `external/openclaw-trusted-backend/README.md`
- `docs/trusted-isolation-design.md`
- `docs/trusted-isolation-testing.md`
- `docs/install/tdx-guest.md`
- `docs/keystone-trustzone-backend-development.md`

## 后续开发原则

如果后面继续做 Keystone / TrustZone，建议直接按下面这个边界推进：

- OpenClaw 核心保持统一 trusted isolation 客户端逻辑
- 每个平台实现自己的 backend service
- 后端继续兼容现有 `authorize` / `complete` / `confirm` 合同
- `scopeToken`、签名校验、proof 元数据语义保持稳定
- 平台差异只留在后端内部

不要做的事：

- 不要把平台私有 transport 暴露进 OpenClaw 请求结构
- 不要把平台判断逻辑散落到 OpenClaw 核心
- 不要把占位 adaptor 当成正式接入方案

## 快速联调思路

### OpenClaw host

1. 打开 `tools.trustedIsolation.enabled`
2. 设置 `tools.trustedIsolation.backendBaseUrl`
3. 配好签名校验公钥和 verify mode

### TDX guest backend

至少先确认：

- `GET /healthz` 正常
- `GET /v1/trusted/guest` 正常
- `GET /v1/trusted/guest?attest=1` 能返回 attestation 样本

### Keystone / TrustZone backend

先做兼容合同的 backend service，再让 OpenClaw 把 `backendBaseUrl` 指过去，不建议先改 OpenClaw 核心。

## 适合谁看这份 README

这份中文 README 主要面向：

- 想在这个仓库里继续推进 trusted isolation / TEE 接入的人
- 需要部署 TDX guest backend 的人
- 准备补 Keystone / TrustZone 后端的人
- 想快速理解“OpenClaw 本体”和“trusted backend 平台实现”边界的人

## 参考链接

- 官网：https://openclaw.ai
- 文档：https://docs.openclaw.ai
- Discord：https://discord.gg/clawd
- 上游仓库：https://github.com/openclaw/openclaw
