# ProxSep

独立开发的 Rust Windows 代理路由器。目标是功能与行为兼容；当前不是完整 1:1，也不是像素级界面复制。不复用第三方源码、图标或品牌资源。

目前具备：

- PPX v100–102 导入/回写，嵌套认证、代理链、DNS/接口配置；保留未知节点，规则重命名/重排不丢扩展字段；
- 有序规则与 Default 回退，应用路径/文件名/PID、目标通配符/IPv4 CIDR/双栈地址段、端口段、指定接口；
- SOCKS4/4A/5、HTTP CONNECT、Basic 与 Windows SSPI NTLM/Negotiate，串行链、冗余、随机负载均衡/PID 黏性；
- 动态 SOCKS5 入口、独立 DNS 入口与稳定127.8假地址、连接日志/流量计数、配置热更新；
- 原生桌面编辑器、代理检查、Windows 服务/控制台守护进程；
- 可构建的独立 Rust WDM/WFP 驱动，以及读取 WFP 目标/身份/records 的双栈透明 TCP 入口。

关键未完成项：内核 DNS datagram 捕获/注入及全系统 DNS 衔接、UDP 策略、HTTP-only 请求转发、受保护 PPX 凭据解密/生成、完整后台健康检查、手动启动覆盖、服务/其他用户/泄漏防护策略、系统级对照验证。驱动尚未签名、安装或加载；编译成功不等于透明代理已可部署。

## 构建与验证

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo test --workspace
cargo build --workspace --release
.\scripts\build-driver.ps1
```

内核驱动是独立workspace，使用已有WDK。构建脚本不安装驱动，不更改测试签名或安全启动状态。

## 使用

```powershell
cargo run -p proxsep-desktop -- 'C:\Profiles\Profile.ppx'
cargo run -p proxsep-cli -- check-profile 'C:\Profiles\Profile.ppx'
cargo run -p proxsep-cli -- route 'C:\Profiles\Profile.ppx' --app app.exe --host example.com --port 443
cargo run -p proxsep-cli -- serve 'C:\Profiles\Profile.ppx' --listen 127.0.0.1:1081
# 可选DNS入口；不会修改系统DNS
cargo run -p proxsep-cli -- serve 'C:\Profiles\Profile.ppx' --dns-listen 127.0.0.1:5353 --dns-upstream 127.0.0.1:53
# 仅当用户已部署我们的独立签名驱动时使用，不会打开原Proxifier驱动
cargo run -p proxsep-cli -- transparent 'C:\Profiles\Profile.ppx'
```

本地SOCKS入口默认尝试Windows TCP表识别真实PID/应用；显式传入的 `--app` 是人为标签，不是可靠内核身份。透明入口只接受有WFP context/records的套接字，不允许普通连接自报目标/身份。接口/归属查询是快照，存在进程退出竞态。

## 工程结构

`core` 配置/规则/DNS，`protocol` 代理协议/SSPI，`runtime` 路由/监听/Windows查询，`driver` 控制编解码，`desktop` 原生界面，`service` SCM/守护进程，`cli` 命令行。独立驱动在 `drivers/proxsep-wfp`。
