# ProxSep

<p align="center">
  <a href="./README.md">English</a> | <strong>简体中文</strong>
</p>

<p align="center">
  <strong>面向开发者、逆向工程师与高级用户的 Rust 原生 Windows 代理路由器与流量策略引擎。</strong>
</p>

<p align="center">
  程序级路由 · SOCKS/HTTP 代理 · 规则调试 · DNS 关联 · Windows Service · WFP 驱动
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong>
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024-orange?logo=rust">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows">
  <img alt="License" src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue">
  <img alt="Status" src="https://img.shields.io/badge/status-experimental-yellow">
</p>

---

> [!WARNING]
> ProxSep 仍处于积极开发阶段。当前 WFP 驱动可以构建，但尚未签名、安装，也不能视为可用于生产环境的透明代理组件。

## 为什么做 ProxSep？

ProxSep 不是为了逐像素复刻其他产品，而是一个独立实现的 Rust Windows 网络工具，重点放在：

- 可编程代理路由
- 流量与进程可观测性
- 规则解释与调试
- DNS 与连接关联
- Windows 透明网络能力

长期目标是让用户可以直接回答这些问题：

- 哪个进程创建了这条连接？
- 为什么命中了这条规则？
- 这条流量最终被路由到了哪里？
- 哪一次 DNS 解析产生了这个目标地址？
- 能不能不重启程序就修改它的网络路径？
- 同一个路由核心能否同时被桌面界面、CLI、Windows Service 和 API 控制？

抓包和 Payload 分析不属于 ProxSep 核心范围。后续可以通过独立的抓包/流量分析工具与 ProxSep 联动。

## 当前能力

### 路由与规则

- 有序规则匹配与 Default 回退。
- 支持按程序路径、文件名、PID、目标地址、IPv4 CIDR、双栈地址范围、端口范围、指定接口匹配。
- 配置热更新。
- Direct / Proxy 路由基础能力。
- 基于 WFP 上下文与记录的透明 TCP 路由路径。

### 代理协议

- SOCKS4 / SOCKS4A / SOCKS5。
- HTTP CONNECT。
- HTTP Basic 认证。
- Windows SSPI NTLM / Negotiate。
- 串行代理链。
- 冗余 / 故障转移。
- 随机负载均衡与 PID 黏性。

### DNS 与进程身份

- 独立 DNS 监听入口。
- 稳定的 `127.8.0.0/16` Fake-IP 映射。
- 本地 SOCKS 入口通过 Windows TCP 表识别进程。
- 透明连接可读取 WFP 提供的目标和身份信息。

### 工具链

- 原生桌面配置编辑器。
- CLI：配置校验、路由评估、服务启动、透明模式。
- Windows Service / 控制台守护进程。
- 连接日志与流量计数。
- 代理连通性检查。
- PPX v100–102 导入与回写。
- 支持嵌套认证、Windows 当前账户 DPAPI 凭据、代理链、DNS/接口配置。
- 尽量保留未知扩展字段，减少配置往返过程中的信息丢失。

## 当前未完成

以下功能仍在开发计划中：

- 内核 DNS datagram 捕获 / 注入与完整系统 DNS 衔接。
- UDP 策略与 UDP 路由。
- HTTP-only 请求转发。
- PPX Basic 与主密码凭据解密 / 生成（已支持 Windows 当前账户 DPAPI 模式）。
- 持续后台健康检查。
- 手动启动覆盖。
- Windows Service / 其他用户 / 泄漏防护策略。
- 系统级行为对照验证。
- 已签名、可安装、可分发的 WFP 驱动方案。

## 架构

```text
Desktop UI ─┐
CLI        ──┼────> ProxSep Core / Rule Engine
Service    ──┘               │
                              ├── Proxy protocols
                              ├── DNS tracker
                              ├── Runtime / flow manager
                              └── Windows platform layer
                                         │
                                         └── WFP driver
```

## Workspace 结构

```text
crates/
  proxsep-core       配置、规则、DNS
  proxsep-protocol   代理协议与 SSPI
  proxsep-runtime    路由、监听、Windows 查询
  proxsep-driver     用户态驱动通信协议
  proxsep-desktop    原生桌面界面
  proxsep-service    Windows Service / 守护进程
  proxsep-cli        命令行工具

drivers/
  proxsep-wfp        独立 Rust WDM/WFP 驱动
```

## 构建

需要：

- 支持 Rust Edition 2024 的 Rust 工具链。
- Windows。
- 仅在构建内核驱动时需要 WDK。

验证命令：

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo test --workspace
cargo build --workspace --release
.\scripts\build-driver.ps1
```

驱动构建脚本不会自动安装驱动，也不会修改 Windows 测试签名或 Secure Boot 设置。

## 使用示例

打开桌面配置编辑器：

```powershell
cargo run -p proxsep-desktop -- 'C:\Profiles\Profile.ppx'
```

校验配置：

```powershell
cargo run -p proxsep-cli -- check-profile 'C:\Profiles\Profile.ppx'
```

评估路由规则：

```powershell
cargo run -p proxsep-cli -- route 'C:\Profiles\Profile.ppx' --app app.exe --host example.com --port 443
```

启动本地代理入口：

```powershell
cargo run -p proxsep-cli -- serve 'C:\Profiles\Profile.ppx' --listen 127.0.0.1:1081
```

可选 DNS 监听：

```powershell
cargo run -p proxsep-cli -- serve 'C:\Profiles\Profile.ppx' --dns-listen 127.0.0.1:5353 --dns-upstream 127.0.0.1:53
```

透明模式，仅在你已经自行部署 ProxSep 驱动后使用：

```powershell
cargo run -p proxsep-cli -- transparent 'C:\Profiles\Profile.ppx'
```

本地 SOCKS 入口会尝试通过 Windows TCP 表识别真实 PID / 程序身份。显式传入的 `--app` 只是用户标签，不属于可信内核身份。

透明入口只接受具有 ProxSep WFP context / records 的套接字，普通连接不能自行声明目标地址或进程身份。

## Roadmap

### v0.1 — 基础能力

- [x] Rust workspace
- [x] PPX 解析 / 回写
- [x] 有序规则引擎
- [x] SOCKS4 / SOCKS4A / SOCKS5
- [x] HTTP CONNECT
- [x] 代理链、故障转移、负载均衡
- [x] 桌面编辑器
- [x] CLI 与 Windows Service
- [x] 实验性 WFP 驱动路径

### v0.2 — 可观测路由

- [ ] Rule Decision Trace：解释规则为什么命中
- [ ] Process Tree 与更完整的进程身份
- [ ] DNS → Flow 关联
- [ ] 连接时间线
- [ ] 更完整的代理健康指标
- [ ] 从实时连接直接创建规则

### v0.3 — UDP 与自动化

- [ ] UDP 路由模型
- [ ] QUIC-aware Flow Metadata
- [ ] REST API
- [ ] WebSocket 事件流
- [ ] 动态策略与条件故障转移
- [ ] 机器可读的规则诊断结果

### 后续

- [ ] 独立抓包 / 流量分析配套工具
- [ ] Flow → PCAP 联动
- [ ] Plugin / Extension API
- [ ] 驱动签名、安装器与正式分发

## Clean-room / 兼容性原则

ProxSep 为独立开发项目。

项目不复用第三方私有源码、图标、品牌资源或非公开资产。兼容性实现应基于公开行为、公开格式和独立观察得到的互操作需求。

ProxSep 与 Proxifier、Initex 无隶属或官方关联。

## 参与贡献

欢迎提交：

- Bug
- 功能建议
- 文档改进
- 实现讨论
- 聚焦且易于审查的 Pull Request

参与前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。

安全敏感问题请参考 [SECURITY.md](SECURITY.md)，不要直接公开完整漏洞细节。

## 开源许可证

ProxSep 使用 **GPL-3.0-or-later**。

你可以使用、修改、再分发和收费销售该软件。

如果你发布基于 GPL 覆盖的 ProxSep 代码修改而来的版本，对应源码需要继续按照 GPL 条款提供。

完整条款见 [LICENSE](LICENSE)。
