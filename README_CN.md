# MCAce（中文说明）

MCAce 是面向现代 Minecraft 网络的隐私优先信任、准入、证据与可逆处置栈。
发布面严格收窄为 Fabric 客户端 Mod、Velocity/BungeeCord 代理插件以及一个
Paper/Folia 后端插件。

> **v0.0.1 当前仍未放行。** 代码和服务端矩阵已在工作，但正式 tag 必须等
> 三版本可见 GUI 人工确认、真实 Vulcan genuine event、以及 Fabric federation
> source→target handoff 都在审查提交上留下证据。

[English README](README.md) · [发布门](docs/RELEASE_GATES.md) ·
[安全模型](docs/SECURITY.md) · [反作弊证据](docs/evidence/anti-cheat-real-server-2026-08-23.json) · [当前 Helio 复测](docs/evidence/real-server-2026-08-23/rerun-2026-08-23.json) · [当前候选 Helio 实测](docs/evidence/real-server-2026-08-23/current-candidate-fe5f2d1.json) ·
[Helio 静态套件证据](docs/evidence/cluster-helio-static-suite-2026-08-22.json) ·
[最新 Helio 静态套件证据](docs/evidence/cluster-helio-static-suite-2026-08-22-33878f2.json)
· [当前提交回归证据](docs/evidence/static-regression-2026-08-23.json)
· [当前 HEAD Helio Paper 测试](docs/evidence/cluster-helio-cc91c63-paper-test-2026-08-23.json)
· [当前 HEAD Helio 静态 wrapper](docs/evidence/cluster-helio-cc91c63-static-2026-08-23.json)
· [本轮 active-pack 证据](docs/evidence/active-pack-integrity-2026-08-22.json)
· [当前 e7f6f74 发布包证据](docs/evidence/release-bundle-e7f6f74.json)

![验证总览](docs/assets/verification-dashboard.svg)

## 产品边界与隐私契约

- Fabric 客户端 Mod：`1.21.11`、`26.1.2`、`26.2`。
- Velocity、BungeeCord 代理插件。
- Paper/Folia 后端插件。
- 默认 `MONITOR`；客户端来源事实只能观察，不能单独处罚玩家。
- 文件/截图证据必须经过可见、明确的人工同意。
- `DENY` 只作用于当前连接，可复核、可撤销；没有自动永久 BAN。
- 发布面不包含 launcher、agent、内核驱动、隐藏采集、键盘记录、摄像头/麦克风、
  任意封包利用或强制 Cloud 服务。

## 精确版本适配

兼容性是精确 tuple allowlist，不按协议号大小推断。

![版本矩阵](docs/assets/version-compatibility.svg)

| Minecraft | 协议号 | Java | Fabric Loader | Fabric API | 客户端产物 |
| --- | ---: | ---: | --- | --- | --- |
| `1.21.11` | `774` | `21` | `0.19.3` | `0.141.6+1.21.11` | 最终 remap JAR |
| `26.1.2` | `775` | `25` | `0.19.3` | `0.155.2+26.1.2` | 最终 named JAR |
| `26.2` | `776` | `25` | `0.19.3` | `0.157.0+26.2` | 最终 named JAR |

当前真正验证的 `1.21.x` 只有 `1.21.11`，未列出的 patch 全部 fail-closed：

```powershell
.\scripts\version-compatibility-contract-smoke.ps1 -Execute
.\scripts\version-compatibility-contract-smoke.ps1 -ReportOnly `
  -ReportPath .\build\compatibility-contract\report.json
```

## 证据仪表盘

| 门 | 当前证据 | 状态 |
| --- | --- | --- |
| 根 + modern 严格离线测试 | 历史 exact 包 `171 suites / 755 tests / 0 failures / 0 errors`；[Helio 定向构建证据](docs/evidence/cluster-targeted-build-2026-08-22.json) 已成功运行 Fabric、Velocity、BungeeCord、Paper 与 runtime integration 测试 | 在已记录源码边界内通过 |
| 当前提交回归套件 | [473ef5b 回归证据](docs/evidence/static-regression-2026-08-24-473ef5b.json) 记录精确源码 `473ef5b…` 的 15/15 wrapper 通过；当前 HEAD 另有 [Helio Paper 测试](docs/evidence/cluster-helio-cc91c63-paper-test-2026-08-23.json)：37 tests、0 failures、0 errors、1 skip，以及 [14/14 静态 wrapper](docs/evidence/cluster-helio-cc91c63-static-2026-08-23.json) | 当前 feature HEAD `cc91c63…`/`6925dab…` 通过；受保护 main 发布路径仍待完成 |
| Paper/Folia × Velocity/Bungee 进程矩阵 | [`server-version-process-matrix-2026-08-23-219e146.json`](docs/evidence/server-version-process-matrix-2026-08-23-219e146.json)：当前 HEAD Execute + ReportOnly 均通过，`12/12`、六棵精确版本树、清理为零；source manifest `beb3d4ad…` / 688 文件，绑定 `219e146…` | 当前 feature HEAD 通过，受保护主分支发布 CI 仍待完成 |
| Fabric GUI consent | 1.21.11 已到可见显式文件授权页；未记录人工点击，因此没有生成发布证据 | 待 6 次人工确认 |
| 反作弊检测 | [`current-candidate-fe5f2d1.json`](docs/evidence/real-server-2026-08-23/current-candidate-fe5f2d1.json) 将 e7f6f74 发布包所用的同一 Paper artifact SHA 与 Helio 当前实测关联：真实 Leaf 1.21.11 + GrimAC `2.3.74-155abaf`，40 个移动探针，三次 `SERVER_CONFIRMED` `BEHAVIOR_HIGH_RISK`（`AimDuplicateLook`、`Simulation`、`TickTimer`），三次 loopback 风险上传；运行记录的源码绑定仍是 `fe5f2d1…`，因为后续只修复兼容性脚本 | 真实检测/拦截上传 PASS；`MONITOR`/`NONE` 有意保留，未执行惩罚动作 |
| Vulcan | 静态契约通过；当前工作区没有 licensed JAR 和 genuine 外部触发 | 待做 |
| Fabric federation | V2 静态契约通过；真实 source export/target import GUI handoff 尚未执行 | 待做 |
| exact-commit CI/release | push [`32615615400`](https://github.com/TypeThe0ry/MCAce/actions/runs/32615615400) 与 PR [`32615617012`](https://github.com/TypeThe0ry/MCAce/actions/runs/32615617012) 均对已测试源码提交 `27bb101d68bd0fcbc8891020951f28a523105038` 通过；e7f6f74 兼容性修复仍需受保护 main 的 exact-commit CI | 当前 HEAD CI 待补 |
| Helio exact-commit release candidate | [`release-bundle-e7f6f74.json`](docs/evidence/release-bundle-e7f6f74.json) 记录 Helio 对 `e7f6f74a9d08b6c4cef829b7b5e65ba150f5d834` 构建 `releaseBundle`：六个 deployable + exact-eight manifest，`product_version=0.0.1`，bundle ZIP SHA-256 为 `4799733be6a178a7ed119d69f4945453dec1d73fbab7a22e95e51e259e035ded`，八项 hash 与三版本兼容性契约均通过 | 当前 feature 候选通过；受保护 `main` CI、外部 GUI/Vulcan/federation 门和最终 tag 仍待完成 |

最新记录的 exact-commit CI 证据绑定到
`27bb101d68bd0fcbc8891020951f28a523105038`；当前 Helio 发布包候选独立绑定到
`e7f6f74a9d08b6c4cef829b7b5e65ba150f5d834`。每个 artifact 都要用
`git rev-parse HEAD` 校验；只有 `release-manifest.properties` 中
`release_identity=true` 且 `source_commit` 与 checkout 完全一致时，才允许把包放进 tag。
当前 v0.0.1 放行仍由六次 GUI 人工确认、真实反作弊、Vulcan 和 federation 门共同决定。

![反作弊证据边界](docs/assets/anti-cheat-evidence-flow.svg)

![启用资源包关联管线](docs/assets/active-pack-correlation.svg)

![验证结果图](docs/assets/verification-dashboard.svg)

## 反作弊与特征检测

检测管线严格区分来源和置信度：

1. `CLIENT_REPORTED` 的 Mod/资源包事实只是低置信度观察。
2. 签名、nonce、sequence、expiry、replay、scope 检查拒绝伪造或过期证据。
3. 只有配置的 provider 和时间窗口共同佐证时，关联器才产生 review 信号。
4. 高影响动作必须由 `SERVER_CONFIRMED` producer 或持久化管理员授权触发；客户端加载
   不是检测/拦截结果。

现在客户端遥测还会携带运行时实际启用的 resource/shader pack ID。启用资源包发生变化时，
会立即触发一次有界 observation update；服务端给每个条目标记 `selected=true|false`，再交给
签名 disposition policy 评估。因此，审查过的客户端观察可以自动执行 `NOTICE`/`WARN`/
`CHALLENGE`；`LIMIT`/`QUARANTINE`/`DENY` 仍必须等独立服务端 provider 或持久化管理员授权。
provider 通过 `ServerBehaviorCorrelationRuntime` 进入授权边界：必须是配置的 Grim/Vulcan
事件，并且和同一 session 在关联窗口内匹配，才会生成持久化的 `SERVER_CONFIRMED` 事件。
精确 hash/content-root 的录入、客户端自保护和 fail-closed 生成脚本见
[`docs/CLIENT_INTEGRITY_POLICY.md`](docs/CLIENT_INTEGRITY_POLICY.md)、
[`docs/CLIENT_SELF_PROTECTION.md`](docs/CLIENT_SELF_PROTECTION.md) 和
[`scripts/new-exact-artifact-policy.ps1`](scripts/new-exact-artifact-policy.ps1)。

当前 Helio 发布包候选绑定源码 `e7f6f74a9d08b6c4cef829b7b5e65ba150f5d834`：Helio 已构建 exact-release
candidate；真实 Leaf/GrimAC 运行记录使用相同 Paper artifact SHA，但源码绑定仍记录为 `fe5f2d1…`，因为后续变更只修复兼容性脚本。Node.js v22.23.2 完成探针；Helio
Node.js v24.18.0 在生成结果前崩溃，仅作为诊断限制保留。当前没有创建 tag，也没有发布 GitHub release。

受控 fixture 只读 metadata，不执行第三方代码：

```powershell
.\scripts\anticheat-fixture-smoke.ps1 -Execute `
  -MinecraftVersion 1.21.11 `
  -MeteorJar 'C:\fixtures\meteor-client.jar' -MeteorSha256 '<sha256>' `
  -XrayPack 'C:\fixtures\Spectator_Xray_1.2.1.zip' -XraySha256 '<sha256>'
```

耐久真实客户端记录只证明客户端发现/资源加载，并明确写出
`real_server_connection=false`、`real_server_detection_event=false`、
`real_server_enforcement_exercised=false`。因此当前不宣称检测 precision、kick/DENY
效果或 BAN 效果。

## 构建与测试

根模块使用 JDK21，modern 客户端使用 JDK25；严格离线并启用依赖校验：

```powershell
$env:JAVA_HOME = '<JDK 21 路径>'
.\gradlew.bat clean build localVerificationBundle `
  "-PmcaceSourceCommit=$(git rev-parse HEAD)" `
  "-PmcaceModernJavaHome=<JDK 25 路径>" `
  --offline --dependency-verification=strict --rerun-tasks `
  --no-build-cache --no-configuration-cache --no-daemon `
  --no-parallel --max-workers=1 --console=plain
```

服务端权威矩阵：

```powershell
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly
```

为减少本机占用，编译/测试通过 cluster-orchestrator 分发。最近一次远端任务运行在
**Helio**（Windows、JDK21、RTX 4070 主机），显式使用 Gradle
`-Xmx2G -XX:TieredStopAtLevel=1`，约 3 分 50 秒完成，退出码 0。对应的脱敏记录见
[cluster-targeted-build-2026-08-22.json](docs/evidence/cluster-targeted-build-2026-08-22.json)。远端使用审查提交的
tree-equivalent 快照；凭据和 worker 路径不会写入仓库。

## 三版本 GUI 人工门

每个目标需要两次可见决定：显式文件授权，以及单独的 `GAME_RENDER_FRAME` 证据授权。
脚本等待真人点击并记录页面阶段、决定、产物 hash、清理和 binding，不模拟输入：

```powershell
$env:JAVA_HOME = '<目标对应的 JDK21 或 JDK25>'
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricEvidence -ManualConsentTimeoutSeconds 120
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2 -WithFabricEvidence -ManualConsentTimeoutSeconds 120
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2 -WithFabricEvidence -ManualConsentTimeoutSeconds 120
```

成功后用脚本输出的 report/binding hash 做 `-ReportOnly`；超时报告是诊断记录，不能升级成发布证据。

## Vulcan 与 federation

Vulcan 需要操作者提供 licensed JAR、当前源码结构预检、隔离 Paper enablement，以及一次
外部真实触发的 genuine event。MCAce 不下载、不打包该授权产物；genuine-event wrapper
拒绝 synthetic event injection，只保存脱敏证据。

Federation 需要 source export consent、source disconnect、直接连接 target、target import
consent、subject binding、expiry 观察，以及零残留进程/端口。静态测试不等于真实 handoff。

## 发布产物

精确分发包固定为 8 项：六个可部署 JAR、`release-manifest.properties`、`SHA256SUMS`。
hash 必须来自干净 exact-commit `releaseBundle`，不要把旧构建 hash 粘进 release note。
当前 Helio 候选包已携带 Gradle `product_version=0.0.1` 且
`release_identity=true`；在外部发布门全部关闭前，仍不把 `v0.0.1` 标签提升为正式 tag。

| 文件 | 作用 |
| --- | --- |
| `mcace-client-fabric-1.21.11.jar` | Fabric 1.21.11 客户端 |
| `mcace-client-fabric-26.1.2.jar` | Fabric 26.1.2 客户端 |
| `mcace-client-fabric-26.2.jar` | Fabric 26.2 客户端 |
| `mcace-server-velocity.jar` | Velocity 代理插件 |
| `mcace-server-bungeecord.jar` | BungeeCord 代理插件 |
| `mcace-server-paper.jar` | Paper/Folia 后端插件 |
| `release-manifest.properties` | exact source/runtime 身份 |
| `SHA256SUMS` | 权威 JAR hash |

## 架构

```mermaid
flowchart LR
  c[Fabric 客户端\n1.21.11 / 26.1.2 / 26.2] -->|签名 envelope| p[Velocity / Bungee]
  p -->|准入 + policy| s[Paper / Folia]
  c -->|CLIENT_REPORTED| o[低置信度观察]
  s --> x[有界服务器上下文]
  o --> r[关联 + 人工审核]
  x --> r
  r --> a[当前连接可逆动作]
```

## 目录

| 模块 | 职责 |
| --- | --- |
| `mcace-protocol` | wire contract、签名、重放防护 |
| `mcace-core` | session、policy、risk、disposition、federation |
| `mcace-client-common` | loader-neutral 完整性/证据原语 |
| `mcace-client-fabric` | 1.21.11 客户端与 consent UI |
| `fabric-modern` | JDK25 official-namespace 客户端 |
| `mcace-server-velocity` / `mcace-server-bungeecord` | 代理适配器 |
| `mcace-server-paper` | Paper/Folia 适配器 |
| `scripts/` | 构建、资产、兼容性与证据 gate |

更多资料：[架构](docs/ARCHITECTURE.md)、[运行](docs/OPERATIONS.md)、[平台测试](docs/PLATFORM_TESTING.md)、
[发布门](docs/RELEASE_GATES.md)、[安全](docs/SECURITY.md)、[federation](docs/FEDERATION.md)。
