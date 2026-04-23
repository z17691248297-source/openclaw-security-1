这个目录现在是一个可打包 `.ke` 的 Keystone 版 OpenClaw trusted backend 示例。

目标是让 Keystone 侧保持官方开发形态：

- `eapp/`
  - enclave 内部 eapp
  - 负责生成 Keystone attestation report
- `host/keystone_example_openclaw_trusted_backend`
  - 纯 C 的策略与证明 shim
  - 输出 OpenClaw 兼容的 `healthz` / `guest` / `authorize` / `confirm` / `complete` JSON
- `host/keystone_example_openclaw_trusted_backend_server`
  - 纯 C 的 HTTP 服务
  - 对外暴露 OpenClaw trusted backend API
  - 默认使用 `ed25519` 签发 `scopeToken`
- `host/openclaw-keystone-package-runner`
  - `.ke` 包启动入口
  - 先探测 Keystone attestation 是否可用
  - 再拉起 HTTP 服务

当前实现约束：

- OpenClaw 仍然部署在 TDX 一侧
- Keystone 这边提供 trusted backend HTTP 服务，默认端口是 `19090`
- `.ke` 启动后，包装器会先尝试跑一次 Keystone attestation probe
- 如果当前机器没有 Keystone 设备节点，probe 会失败，但 HTTP 服务仍会继续启动
- `guest.attestationReady` 会根据 probe 结果返回 `true` 或 `false`

文件说明：

- `include/openclaw_trusted_backend_keystone.h`
  - 共享的请求/响应结构体
- `host/main.c`
  - OpenClaw trusted backend 的纯 C 命令行后端
- `host/backend_server_c.c`
  - OpenClaw trusted backend 的纯 C HTTP 服务
- `host/keystone_attestor.cpp`
  - Keystone host 侧 attestation probe 逻辑
- `host/package_runner.cpp`
  - `.ke` 启动包装器
- `eapp/openclaw_keystone_backend_eapp.c`
  - Keystone eapp

## 构建

需要 Keystone SDK、Eyrie runtime 和 `makeself`。

示例：

```bash
cmake -S . -B build \
  -DKEYSTONE_SDK_DIR=/path/to/keystone-sdk \
  -DKEYSTONE_EYRIE_RUNTIME=/path/to/keystone/runtime \
  -DKEYSTONE_BITS=64
cmake --build build -j
```

构建产物：

- `build/keystone_example_openclaw_trusted_backend`
- `build/keystone_example_openclaw_trusted_backend_server`
- `build/openclaw-keystone-backend-eapp`
- `build/openclaw-keystone-package-runner`
- `build/openclaw-keystone-trusted-backend.ke`

## 运行方式

### 1. 直接运行 HTTP 服务

默认值已经内置，不需要手写一长串参数：

- 绑定地址：`0.0.0.0`
- 端口：`19090`
- CA binary：`./keystone_example_openclaw_trusted_backend`
- 签名模式：`ed25519`
- 私钥路径：`/etc/openclaw-trusted-backend-keystone/ed25519-private.pem`

直接运行：

```bash
./keystone_example_openclaw_trusted_backend_server
```

### 2. 运行 `.ke` 包

`.ke` 包会先做一次 attestation probe，然后再启动 HTTP 服务：

```bash
./openclaw-keystone-trusted-backend.ke
```

`.ke` 启动后的默认 HTTP 端口仍然是：

```text
19090
```

## 私钥

当前默认是 `ed25519` 签名模式，所以 Keystone 板子上需要放和 OpenClaw 公钥匹配的私钥：

```text
/etc/openclaw-trusted-backend-keystone/ed25519-private.pem
```

如果 TDX 一侧已经在用同一组 `ed25519` 公私钥，那么 Keystone 这边要复用与之配对的私钥，不能重新生成一把随机私钥。

## OpenClaw 侧配置

OpenClaw 指向 Keystone backend 时，核心是把 trusted isolation backend URL 指过去：

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "backendBaseUrl": "http://<keystone-host>:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "verify": {
        "mode": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
        "requireScopeToken": true
      }
    }
  }
}
```

## 验证说明

当前这套实现包含两层验证目标：

- 在普通 Keystone 开发机上
  - 验证可以成功编译并打出 `.ke`
  - 验证即使设备节点不可用，`.ke` 仍能把 HTTP 服务拉起来
- 在最终开发板上
  - 验证真实 Keystone attestation probe 成功
  - 验证 `guest.attestationReady=true`
  - 验证 OpenClaw 从 TDX 侧调用 Keystone trusted backend 全链路可用
