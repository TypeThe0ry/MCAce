# MCAce（中文说明）

开发更新：Velocity 已接入可选的管理员清单拒绝规则，精确匹配已加载 Mod ID 和已启用资源包标识。
默认关闭，且其启用开关独立于签名处置路径的 MONITOR 模式。它不是作弊定罪、基于内容的矿透检测，
也不是保证先拦截再入服的屏障。Paper 1.21.11/Velocity 的 Mod 标识对照已完整通过两次，
选中资源包标识对照通过一次，包含认证成功、关闭规则时准入和开启规则时客户端实际断开。
这些使用原始协议测试客户端，不是真实 Fabric 采集，也没有加载外挂或矿透材质包。
两类对照也已在 Paper 26.1.2/JDK 25 上各通过一次。26.2 的 Mod 对照通过，资源包对照首轮基线超时、
单项复测通过；该间歇性超时仍未解决。
真实 GUI 验收和 Bungee 对齐仍待完成；见
[验证记录与边界](docs/evidence/inventory-admission-2026-09-08.md)。启用前请阅读
[配置方式、证据语义与限制](docs/INVENTORY_ADMISSION.md)。

开发更新（2026-09-08）：Velocity 和 BungeeCord 已提供管理员只读命令
`/mcaceobservation freshness <uuid> [秒数]`，需要 `mcace.admin.audit` 权限。
诊断窗口默认三个上报周期（当前 900 秒），范围为 1–3600 秒；返回 FRESH、STALE、CLOCK_ANOMALY
或 UNAVAILABLE。它表示服务端接收的客户端遥测状态，不是无作弊证明或动作执行回执。
查询不会改变准入，也不会设置自动处置策略。详见
[架构重评与实施进度](docs/ARCHITECTURE_REASSESSMENT_2026-09-08.md)。

Velocity 可选择在清单过期、收到更新清单后恢复时向玩家发送提示。在 `mcace.properties`
设置 `telemetry.notice.enabled=true` 和 `telemetry.notice.max-age-seconds=900`，
再按维护流程重启插件／服务器加载。默认关闭；窗口必须大于 300 秒且不超过 3600 秒。
它只发通知，不踢出或封禁；日志仅证明发送 API 调用结果，不证明客户端已收到。
Bungee 自动通知和真实运行时消息送达验证仍待完成。

MCAce 是面向现代 Minecraft 网络的隐私优先客户端可见性、准入、证据与可逆处置栈。
它的可部署边界严格收窄为 Fabric 客户端 Mod、Velocity/BungeeCord 代理插件，以及一个
Paper/Folia 后端插件。

> ## v0.0.1 — RELEASE LOCKED
>
> **当前没有创建正式 tag，也没有发布 GitHub Release。** 只有下面七个 fail-closed
> 发布门在同一个已审查精确源码上全部通过后才能放行。不可变的 `2a6274a` artifact
> boundary 保留了一份历史外部签名 Matrix V4 包，但当前 readiness validator 因精确受保护
> bundle 绑定失败而拒绝该 Matrix index（`MCACE_RELEASE_MATRIX_PROTECTED_BUNDLE_INVALID`）。
> 当前分支还被 Matrix 绑定、当前源码 GUI/Federation V5、licensed Vulcan V3、Production
> Authority V4，以及受保护 main/tag 的 V4 exact-commit CI 阻塞。当前 `live16` 只渲染了同意
> 页面，随后在没有生成可见截图/accepted event 前 fail-closed，并不是已接受的发布决定。

**2026-09-08 开发更新：** ZIP 材质包的有界 PNG 内容特征已接入客户端签名清单，
服务端可将它与单独上报的材质包选中状态一起用于策略评估。它仍是低置信度遥测，
不是作弊实锤，也没有默认开启处罚。见[纹理探测实现与测试记录](docs/evidence/TEXTURE_PROBE_2026-09-08.md)
和[最新 GUI/运行证据](docs/evidence/GUI_RUNTIME_2026-09-08.md)。文中的 `live16` 为历史尝试；
当前源码的发布级 GUI 与 federation 验收仍待完成，先前发布包不包含本次代码。

[English README](README.md) · [架构](docs/ARCHITECTURE.md) ·
[安全模型](docs/SECURITY.md) · [发布门](docs/RELEASE_GATES.md) ·
[运维](docs/OPERATIONS.md) · [当前进度台账](docs/evidence/PROGRESS_2026-09-06.md) · [2026-09-07 更新](docs/evidence/PROGRESS_2026-09-07.md)

![发布验证总览](docs/assets/verification-dashboard.svg)

## 发布状态：精确七门

以下名称和 `scripts/release-readiness.ps1` 完全一致。受控 fixture、历史 PASS、调用者
Boolean 或未签名报告都不能把任何发布门提升为通过。

| Readiness gate | 正式发布需要的证据 | 状态 |
| --- | --- | --- |
| `server_matrix_exact_source` | Matrix V4 七根条目 native package；精确 12 份 raw 进程 case；进程 incarnation 与清理承诺；受保护 V4 release bundle 和三份服务端 JAR 交叉绑定；仓库外 RSA supervisor root、受保护 pin、新鲜 detached receipt、replay 与 TOCTOU 校验 | **BLOCKED — artifact-commit A 有外部签名的 12/12 证据，但当前 validator 拒绝 20260906/20260907 index 的精确受保护 bundle 绑定；仍需针对当前 bundle 的新批准绑定** |
| `fabric_gui_single_enablement_confirmation` | 整个 v0.0.1 发布验收只保留一次真人来源、可见、绑定当前连接的 `Enable MCAce` 决定；签名 GUI attestation 和完整解码 PNG 必须进入 Federation V5 证据集 | **PENDING — 当前源码 `live16` 渲染 prompt，但没有生成可见截图或 accepted event；runner 已 fail-closed** |
| `fabric_federation_real_handoff` | Federation V5 source→target handoff、继承同一次确认且不弹第二次窗口、subject/route/session 绑定、expiry 与关联负例、runtime ledger、零自有残留，以及不同 post-run supervisor 的 receipt | **PENDING — 没有当前源码绑定的 V5 index/native package；旧 ce4f6 package 已被拒绝** |
| `vulcan_genuine_event` | 已审查 licensed Vulcan JAR、真实非合成外部 provider event、精确发布产物绑定，以及仓库外已批准 supervisor 签名的 Vulcan V3 receipt/index | **PENDING** |
| `production_server_confirmed_authority` | Authority V4 raw package，包含真实 Grim/Vulcan provider events、实际签名 grant/observation frames、进程与 journal ledgers、精确 V4 服务端 JAR、已批准外部 Ed25519 supervisor receipt 和 native release index | **PENDING** |
| `protected_exact_release_bundle` | 受保护 `main` 或 `v0.0.1` tag-push CI 校验精确 `MCACE_RELEASE_BUNDLE_V4`、兼容性报告、canonical artifact-source marker、最终 HEAD 和八项发布内容 | **PENDING** |
| `clean_worktree` | 最终精确发布 checkout 的 `git status --porcelain` 为空 | **当前 checkout 已通过；发布 commit 仍需复核** |

最终 exact bundle 通过 `release-manifest.properties` 的 `source_commit` 字段绑定
干净 checkout；不可变 artifact source 仍是
`2a6274a9200f2aa195e1238eaddf43650f549a0a`。strict 本地构建、checksum 校验和三版本
兼容性合同均通过，六个 JAR 哈希记录在[进度台账](docs/evidence/PROGRESS_2026-09-07.md)。
历史 artifact-commit A 的 Matrix V4 run 完成 12/12（10 stable + 2 beta），通过启动、登录、
MCAce hello/auth、backend admission 和 cleanup zero 检查，外部 detached receipt 也作为
provenance 保留。但它不能自动满足当前 exact-source gate：当前 readiness 输出由
`scripts/release-readiness.ps1` 写入未跟踪的 `build/`，并在已跟踪的
[2026-09-07 进度台账](docs/evidence/PROGRESS_2026-09-07.md)中汇总；它拒绝已跟踪 Matrix
index 的受保护 bundle 绑定。因此 readiness 现在有六个 blocker：Matrix exact-source
绑定、当前 GUI consent、Federation V5、Vulcan V3、Production Authority V4 和受保护
exact-release CI。正式发布前必须核对输出的 `source_commit`、`observed_head` 与最终
bundle 完全一致。

历史 Matrix/Federation package 继续用于回归与 provenance，但不会被改名或冒充当前证据。
当前仍没有 licensed Vulcan V3 genuine-event package、Production Authority V4 raw package/
receipt，也没有运行受保护 exact-commit release CI。

随后 Helio job `20260906-mcace-5880460-final-doc-bundle` 又针对文档后代
`5880460ac856ecd61cb81b2a8c3024f0bee29c71` 重建了 bundle，同时保持
artifact source 为 `2a6274a9200f2aa195e1238eaddf43650f549a0a` 和六个产品 JAR
字节不变。该次 strict bundle 仍满足 1966-byte manifest 控制；兼容性
`-Execute`/`-ReportOnly` 都通过。带仓库外 Matrix supervisor root 和 approved
pin 的 readiness 重跑确认 `server_matrix_exact_source=true`、
`clean_worktree=true`；其余五个门仍 fail-closed，这不是发布批准。

之前的文档/证据后代是 `97b9d9e5` 和 `07c36f6`；权威当前 SHA 以最新
exact-bundle manifest 的 `source_commit` 为准。Helio job
`20260906-mcace-d8066f7-final-doc-bundle` 已针对当时的文档提交重新生成 exact
bundle，同时保持 artifact source 为
`2a6274a9200f2aa195e1238eaddf43650f549a0a`，六个产品 JAR 字节不变；1966
字节 manifest、565 字节 `SHA256SUMS`、兼容性 Execute/ReportOnly 和 Matrix
绑定 readiness 复核均通过。四个外部验收门以及受保护 exact-release CI 仍待完成；该
job 之后的文档提交还需要最后一次 exact bundle 复核。

### 当前可执行验证快照（当前分支 / `2a6274a` artifact）

截至最近一次复核，权威 checkout 是 `D:\Projects\MCAce`，分支为
`feature/active-pack-integrity`；精确当前 HEAD 始终以最新 exact bundle manifest 的
`source_commit` 字段为准；六个产品 JAR 仍按字节绑定 artifact source commit
`2a6274a9200f2aa195e1238eaddf43650f549a0a`。
GitHub PR [#17](https://github.com/TypeThe0ry/MCAce/pull/17) 仍是基于 `main` 的 open draft；
当前 `build` 与 `windows-contracts` checks 为绿色；每次新的 evidence/documentation 后代
仍必须重新通过它们。尚未创建 `v0.0.1` tag 或 GitHub Release。

审计基线 `live16` 启动了真实 Fabric 26.2 客户端并渲染 `Enable MCAce` prompt；但本机
Computer Use 的 `sky` RPC 未配置，运行中没有捕获真人点击。runner 在生成可见截图前以
`FABRIC_FEDERATION_GUI_EXTERNAL_SCREENSHOT_NOT_CREATED_IN_VISIBLE_WINDOW` fail-closed，
随后清理自有进程；exchange 目录没有 screenshot、signing request、attestation、handoff
或 post-run receipt。旧 live15/历史 accepted GUI/Federation package 属于旧源码边界，当前
readiness 会拒绝它们。

本次 README/台账更新只改文档，不改变六个产品 JAR 字节；后续任何文档/evidence 后代
都必须在发布前重新生成 exact-source bundle、重跑 readiness，并通过受保护 CI。

仓库内已跟踪的 Fabric 与 Cheat-Mod/Xray 包仍是 diagnostic/controlled evidence：不是
第三方作弊程序执行，也不能关闭当前 GUI 或 release gate。实现仍会在明确同意后采集 Loaded
ModList、active resource-pack 和可选 shader-pack observation；服务器把它们记录为
`CLIENT_REPORTED / LOW`，受控 fixture 则覆盖关联与 `SERVER_CONFIRMED`/`QUARANTINE` 状态。
2026-09-07 复跑输出保留在被忽略的 `build/` 路径，并在进度台账中汇总；它们没有被提升为仓库
内的 release evidence。本节引用的 [Helio 可执行客户端/服务端关联证据](docs/evidence/anticheat-live-fixture-20260906-97b9d9e.json)
和 [ModList/Xray 分类证据](docs/evidence/anticheat-classification-20260906-97b9d9e.json)
记录了此前源码边界的复跑结果；它们仍是受控证据，不是公网或 Tencent ACE 级别承诺。
详见
[脱敏反作弊验证摘要](docs/evidence/anticheat-validation-20260905-25b8b06.json) 与
[完整事实台账](docs/evidence/PROGRESS_2026-09-06.md)。

## MCAce 是什么、又不是什么

MCAce 让服务器在用户明确同意后获得一份狭窄、可复核的 Fabric 客户端视图，并把它与
服务端独立产生的证据关联。目标是让准入和当前连接动作保持显式、签名、有界、可审计、
可撤销。

MCAce v0.0.1 **不是**腾讯 ACE 等价的内核级反作弊。它没有 launcher、常驻 agent、
内核驱动、跨进程内存扫描、调试器拦截、DMA 检测、隐藏采集、键盘记录、摄像头/麦克风访问，
也没有自动永久封禁路径。当前不宣称 kernel/injection/DMA 覆盖、公网 precision/recall，
或生产 kick/deny/ban 效果。

### 产品边界与隐私契约

- 精确 Fabric 目标：`1.21.11`、`26.1.2`、`26.2`。
- Velocity、BungeeCord 代理适配；Paper、Folia 后端路径。
- MCAce 默认禁用。运行时同意仅绑定当前连接，断开后不持久化。
- 客户端来源事实保持 `CLIENT_REPORTED / LOW`，不能单独授权高影响动作。
- Loaded ModList 不发送绝对本地路径或任意 classpath 值。
- `DENY` 即使由另一个已授权 policy 允许，也只能作用于当前连接，可复核、可撤销；自动永久
  BAN 不在产品合同内。
- Production Authority 默认 `authority.enabled=false`，只接受 `MONITOR`；当前通过校验的
  authority frame 没有接入平台动作 executor。

![可部署客户端隐私边界](docs/assets/client-privacy-boundary.svg)

## 精确版本 allowlist

发布 allowlist 对 Minecraft patch、protocol、Fabric API 与 client build ID 使用精确绑定，
而不是根据协议号阈值猜测。可部署 JAR 对运行时声明的是最低版本：Fabric Loader
`>=0.19.3`，`1.21.11` 使用 Java `>=21`，`26.x` 使用 Java `>=25`；因此 Loader/Java
不是等值 gate。未列出的 Minecraft patch 会 fail-closed，更高 Loader/Java 组合在单独执行
验证前不属于已记录的 release test matrix。当前真正验证的 `1.21.x` patch 只有
`1.21.11`。

![精确版本兼容矩阵](docs/assets/version-compatibility.svg)

| Minecraft | 协议号 | 最低 Java | 最低 Fabric Loader | Fabric API | 客户端产物 |
| --- | ---: | ---: | --- | --- | --- |
| `1.21.11` | `774` | `>=21` | `>=0.19.3` | `0.141.6+1.21.11` | 最终 remap JAR |
| `26.1.2` | `775` | `>=25` | `>=0.19.3` | `0.155.2+26.1.2` | 最终 named JAR |
| `26.2` | `776` | `>=25` | `>=0.19.3` | `0.157.0+26.2` | 最终 named JAR；Folia 26.2 仍是 BETA lane |

对当前 bundle 运行兼容性合同：

```powershell
.\scripts\version-compatibility-contract-smoke.ps1 -Execute
.\scripts\version-compatibility-contract-smoke.ps1 -ReportOnly `
  -ReportPath .\build\compatibility-contract\report.json
```

## 一次可见连接启用

客户端在发送任何 MCAce 帧之前显示清晰的 `Enable MCAce` / `Decline` 窗口。拒绝、关闭、
超时或当前连接失效时，客户端保持禁用。接受后，签名文件观察、渲染证据和一次由 source 选择的
federation handoff 继承同一个连接决定，不再打开第二个确认窗口。

对 **v0.0.1 发布验收**，只由一个代表性连接产生真人 GUI 批准证据。整个 release gate
只保留一次确认，不是每个 Minecraft target 各确认一次，更不是六次批准。披露页内的翻页
不产生新的决定。其他两个版本的 UI smoke 只是可选兼容性覆盖，不会产生额外发布批准。

release-grade GUI 记录属于 Federation V5：一个独立批准的 GUI signer 绑定可见 prompt、
decision window、process/session/attempt、随机 challenge 和完整解码 PNG；另一个不同的已批准
supervisor 签名不可变 post-run report、binding 和 runtime ledger。两份签名都不会增加第二次
UI 弹窗。

![Federation 认证绑定](docs/assets/federation-auth-binding.svg)

## 实际 Loaded ModList

当前开发实现通过 `FabricLoader.getAllMods()` 读取 Fabric Loader 的实际运行时 graph，
不会把 `mods/` 目录里的每个 JAR 都当成已加载。

![Loaded ModList 与已安装产物绑定](docs/assets/loaded-modlist-binding.svg)

签名 snapshot 最多携带 256 个按 canonical 顺序排列的 Mod ID 和版本：

- `<gameDir>/mods` 的直接子文件只发送 basename；MCAce 再把该身份与已安装 manifest 的
  Mod ID、版本、文件大小和 SHA-256 对齐；
- nested JAR 只发送 parent Mod ID；
- 外部、classpath、built-in 或其他无法验证的 origin 不发送绝对路径，并保守表示为没有本地
  path 值的来源；
- 已安装文件与已加载 Mod 是两份独立 claim：一个 JAR 可以存在但未加载，nested Mod 也可能
  没有自己的直接 `mods/` 文件；
- 在任何动态 update 被接受前，第一次检测到运行时 graph 变化可以把首次发送提前到当前时刻；
  一旦有动态 update 被接受，后续变化会合并到下一个完整的五分钟窗口。整个路径保持
  single-flight，并由签名 ACK 驱动。

`CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1` 会进入签名 policy 和 authentication request
协商。默认 Velocity/BungeeCord policy 要求该 capability，因此空的 legacy request 不能
悄悄获得 VERIFIED 准入。服务端校验顺序、唯一性、origin shape 和直接文件 reconciliation，
再为签名 policy matching 派生 `loaded`、`loaded_origin`、
`origin_manifest_matched` metadata。

该能力已在当前工作树实现，本轮开发已运行 collector、protocol、handshake、服务端校验、
budget 和 refresh 相关的 focused local tests。这些只是开发证据：当前工作树不是最终发布提交，
尚未发布 Loaded ModList 的 exact-commit release evidence。

最重要的是，loaded identity 仍然只是 `CLIENT_REPORTED / LOW`。直接文件 hash 只把扫描时
磁盘条目与 loaded identity claim 关联起来，不能证明 JVM 内已经执行的必然是同一份字节。
高影响 authority 仍需要服务端独立证据。

详见[客户端完整性策略](docs/CLIENT_INTEGRITY_POLICY.md)。

## 当前资源包与 Shader 包

同一份有界签名 snapshot 还包含运行时 selected resource-pack ID 和顺序，以及可选 loader
能够提供时的 active shader-pack ID。selection 变化只会把 ACK 驱动的 scheduler 标为
dirty；第一次动态 update 被接受前可以立即尝试，一旦有 update 被接受，后续变化会合并到
下一个五分钟窗口。Iris adapter 只使用反射：loader 缺失、关闭或失败时返回空
selection，不根据目录猜测。

对于每一份完整且可解析的动态 snapshot，proxy 都会返回一份服务端签名的
`ArtifactObservationResult`，并把它绑定到 session、sequence、aggregate root 和完整
update 的 SHA-256。客户端只有在验证完全匹配的 accepted result 后，才提交本地
sequence/root 状态。result 丢失时会用新的 transfer identity、nonce 和签名重传同一份
pending payload；有效拒绝会安排一次全新扫描，签名 rate-limit result 则提供一个有界的
重试时间。完整 update digest 能阻止同 sequence、同 root 的重试偷偷修改 selected packs、
loaded Mods、capabilities 或其他不进入 aggregate root 的字段。

transport 或 ACK timeout 失败采用 1–30 秒有界指数退避。重试只是用新的 transfer ID、
nonce 和签名重新分片同一份序列化 update；它不是一份更新的观察，也不会重置五分钟语义周期。

动态上报只是可选 telemetry，不是持续证明，也不是 freshness lease。客户端停止发送动态
update 时仍保持 `VERIFIED`；服务端记住的最后一份动态视图可能一直过期，直到收到下一份
被接受的 update，或该 session 被替换、断开并清理。

服务端派生 `selected=true|false`，并可匹配已审查的精确 SHA-256 或目录 content root。
这些仍是客户端来源证据，不能自行提升为处罚 authority。

![当前资源包关联](docs/assets/active-pack-correlation.svg)

## 反作弊证据与信任模型

![反作弊证据流](docs/assets/anti-cheat-evidence-flow.svg)

1. 客户端 Mod/resource/shader 观察从 `CLIENT_REPORTED / LOW` 开始。
2. signature、nonce、sequence、expiry、replay、scope、budget 和 canonical-form 校验拒绝
   格式错误或过期证据。
3. 已审查客户端事实可在签名 policy 下驱动 `OBSERVE`、`NOTICE`、`WARN`、`CHALLENGE`。
4. 高影响可逆处置在具备同一 session 的独立服务端 provider 或持久化管理员 authority 前，
   连候选资格都没有。
5. Production Authority V4 是独立的 Paper/Folia→proxy 签名通道；当前终止于
   content-free MONITOR 日志，并故意不连接 `LIMIT`、`QUARANTINE`、`DENY`、kick、ban。

只有进入有界 audit queue 后，Velocity 与 BungeeCord 才会使用相同的 signed-policy
evaluator，并把得到的低影响事件交给相同的 session-bound executor。签名 `ACCEPTED`
`ArtifactObservationResult` 只确认协议层的 session、sequence、root 与完整 update digest；
它不是 audit queue 入队回执，也不是执行回执。队列饱和或 scheduler submit 失败会被记录，
并丢弃该下游事件，但不会改变 admission，也不会回滚协议 ACK。经过当前 session 与 policy
重新校验后，客户端来源证据只能执行低影响的 `NOTICE`、`WARN` 和 content-free
`CHALLENGE` message；高影响动作在没有独立持久 authority 时继续 fail closed，动态输入也
不会改写 admission。

Grim/Vulcan adapter 使用精确 provider ID、version、stable check family、threshold、独立
trust domain 和有界 correlation window。Paper 重新签名一条客户端 claim 并不会把它变成
server-confirmed evidence；authority path 必须消费真实 Paper-local provider callback。

## 受控可执行 fixture：已验证开发证据

![受控可执行 fixture 结果](docs/assets/controlled-anticheat-results.svg)

当前保留的最新 exact-commit 受控 fixture index 是
[`helio-2026-08-25-anticheat-live-fixture-2c89876.json`](docs/evidence/helio-2026-08-25-anticheat-live-fixture-2c89876.json)，
绑定源码 `2c898762dd770723957ea0a8279f68c6c5e5abb3` 和 Helio Windows/JDK 21 运行。

| 结果 | 实测 |
| --- | ---: |
| 覆盖版本 | `1.21.11`、`26.1.2`、`26.2` |
| MCAce 自有可执行 fixture 加载 | `3 / 3` |
| 同一 session 独立服务端信号 | `3 / 3` |
| 签名实验室 policy 下 `SERVER_CONFIRMED / QUARANTINE` | `3 / 3` |
| clean control 误报 | `0` |
| 自有子进程残留 | `0` |

保留的 canonical 文件：

- [report](docs/evidence/anticheat-live-fixture/20260825T145002572Z/report.json)
- [JUnit XML](docs/evidence/anticheat-live-fixture/20260825T145002572Z/test-results.xml)
- [run log](docs/evidence/anticheat-live-fixture/20260825T145002572Z/run.log)

### Fixture 边界

- 可执行 JAR 是 MCAce 自有测试代码，不是第三方作弊程序。
- 它运行于隔离 child JVM/loopback integration harness，不是真实 Fabric GUI 客户端，也不是
  公网服务器。
- 没有加载第三方代码，也没有访问第三方网络。
- 服务端根据同一 fixture session 的移动增量独立派生 `Simulation` 信号。
- `QUARANTINE` 由签名 laboratory policy 选择，不是 Production Authority V4，也不是
  真实平台 kick/deny/ban executor。
- 结果不证明 kernel、injection、debugger、DMA、公网 precision/recall 或腾讯 ACE 级覆盖。
- 证据只精确绑定 `2c89876…`；不覆盖其后的脏工作树 Loaded ModList、Authority、Federation
  或发布门改动。

metadata-only fixture 另行保存在
[`helio-2026-08-25-anticheat-sync-current.json`](docs/evidence/helio-2026-08-25-anticheat-sync-current.json)。
它不执行第三方 JAR 或 pack，只能作为历史 correlation evidence，不能称为当前发布证据。

## 历史真实服务器 witness

仓库保留了一组真实 Leaf `1.21.11` loopback server/GrimAC witness：

- [首次真实服务器记录](docs/evidence/anti-cheat-real-server-2026-08-23.json)
- [Helio rerun](docs/evidence/real-server-2026-08-23/rerun-2026-08-23.json)
- [历史 feature 候选 rerun](docs/evidence/real-server-2026-08-23/current-candidate-fe5f2d1.json)

这些带日期的记录包含真实 Grim callback、三条 `SERVER_CONFIRMED` behavior event，以及成功的
interception/upload response。它们绑定旧 source/artifact identity，运行在 `MONITOR/NONE`，
并明确没有 automatic kick/ban。它们是有价值的历史服务端证据，但不能关闭当前 Matrix V4、
Vulcan V3、Authority V4、Federation V5 或受保护发布门。

更早的[客户端检测记录](docs/evidence/anti-cheat-detection-2026-08-21.json)明确写有
`real_server_connection=false`、`real_server_detection_event=false`、
`real_server_enforcement_exercised=false`；它只证明客户端发现/资源加载。

## Matrix V4

Matrix V4 是第一个在结构上有资格满足 `server_matrix_exact_source` 的 Matrix schema。
它精确覆盖：

- 三个 Minecraft 版本；
- Paper 和 Folia；
- Velocity 和 BungeeCord；
- `3 × 2 × 2 = 12` 个真实进程 case。

保留的 [Matrix V4 证据索引](docs/evidence/server-version-process-matrix-20260905-92a49b9.json)
是 artifact source `92a49b9…` 的历史 release-eligible package。它记录 12/12 个进程
case、24 个进程身份、全部六个发布产物、三份服务端 JAR、精确八项 bundle 和独立 RSA
supervisor receipt，但没有绑定当前 `2a6274a` source/artifact pair，因此当前 validator 会
拒绝它；它只是历史 provenance。匹配当前 2a6274a 的新鲜 Matrix supervisor receipt 已
写入下面的当前 V4 index。

修正后的 artifact-commit A diagnostic 及发布包见
[server-version-process-matrix-20260907-2a6274a.json](docs/evidence/server-version-process-matrix-20260907-2a6274a.json)，
原生证据目录为
[`server-version-process-matrix-20260907-2a6274a`](docs/evidence/server-version-process-matrix/server-version-process-matrix-20260907-2a6274a/)。
它针对冻结的 Paper/Folia 与 Velocity/Bungee 资产完成了 12/12 个真实 case（10 STABLE +
2 BETA）；每个 case 都通过启动、登录、MCAce hello/auth、backend admission，且 cleanup
为 zero。随后 A worktree 与仓库外 supervisor 完成 fresh request/receipt 交换，publisher 校验
`release_eligible=true`、`test_fixture=false` 并关闭 Matrix V4 发布门。当前 index 为
[server-version-process-matrix-20260907-2a6274a.json](docs/evidence/server-version-process-matrix-20260907-2a6274a.json)，
信任根 SHA-256 为 `05be3d1ce14b03ab66db85045377f52afa91f03d662a4d70c26468a93bcde223`，
receipt SHA-256 为 `878ee99995f46fc63d02ea568dee1f16e11c504546f1bad49732fb912c8e53ad`。

producer 冻结全部 raw report、report/binding/raw-manifest 字节、ordered raw root、case 与
process-incarnation identity、invocation 与 cleanup 事实、精确 V4 bundle、六份发布 JAR，以及
三份 Matrix 服务端 JAR。仓库外独立 RSA supervisor 必须在受保护 trust-root pin 下返回新鲜
detached receipt，producer 才能最后写入 `commit.json`。publisher 与 readiness 随后重新校验
signature、expiry、replay、no-follow identity、稳定重读、bundle hash 和 JAR cross-binding。

当前保留的 `bef44e3…` [12/12 Helio V1 index](docs/evidence/server-version-process-matrix-2026-08-25-bef44e3.json)
及其 [report](docs/evidence/server-version-process-matrix/2026-08-25T13-28-42-6795528Z/report.json)、
[binding](docs/evidence/server-version-process-matrix/2026-08-25T13-28-42-6795528Z/binding.json)、
[commit marker](docs/evidence/server-version-process-matrix/2026-08-25T13-28-42-6795528Z/commit.json)
仍是可信历史执行诊断：12/12、10 STABLE + 2 BETA、cleanup zero。但它们属于 legacy V1，
**不能关闭 Matrix V4 发布门**；V2/V3 同样不具备发布资格。

完整外部 supervisor 工作流见：
[Server Version Matrix Evidence V4](docs/SERVER_VERSION_MATRIX_EVIDENCE_V4.md)。

## Federation V5

Federation V5 为一个由 source 选择且已 pin 的 target 复用唯一连接级 enablement decision。
handoff 不增加 authority，也不打开第二个 prompt。正式证据必须绑定 source disconnect、直接
target connect、签名 assertion 与 AUTH hash、精确 subject/route/session、expiry、两个关联
负例、全部关键进程 incarnation、零残留、完整解码 GUI PNG、runtime-ledger raw
hash/head/seal/count、不可变 report/binding 字节，以及精确 Fabric/Paper/source-proxy/
target-proxy V4 JAR。

GUI signer 与 post-run supervisor 必须分别独立批准，使用不同的仓库外 root/private key。
fixture、相同 key、自批准、缺 receipt、过期、replay 或篡改 package 全部 fail-closed。链接的
[Federation V5 package](docs/evidence/federation-gui-handoff-20260905T1212514132609Z-26.2-velocity-to-velocity-ce4f6d9.json)
只是旧源码/产物边界的历史 witness，当前 validator 会拒绝它。当前源码 `live16` 渲染了
prompt，但没有生成可见 screenshot、accepted consent 或 source→target handoff，因此 GUI 与
Federation 两门仍为 PENDING。

详见 [Federation](docs/FEDERATION.md)。

## Vulcan V3

仓库不会下载或重新分发 licensed Vulcan。历史结构/V2 diagnostic 可以检查 API shape 与产物
identity，但不能证明 genuine non-synthetic event，也不能满足 release readiness。

v0.0.1 gate 需要已审查 licensed Vulcan JAR、隔离的当前源码 Paper enablement、一次真实外部
触发 provider event、精确发布产物绑定，以及仓库外已 pin supervisor 签名的 Vulcan V3
receipt/index。当前未保留任何一份，因此该门 PENDING。

## Production Authority V4

![Production SERVER_CONFIRMED 证据链](docs/assets/authority-evidence-chain.svg)

Paper/Folia→proxy 签名 authority path 已在当前开发工作树实现，并保持 opt-in、fail-closed、
MONITOR-only：

1. Velocity/Bungee 为精确 authenticated physical login/backend 签发短时 Ed25519 grant。
2. Paper/Folia 校验 grant，关联 exact-profile 独立 provider callback，并在暴露一份签名
   observation frame 前先写入并强制落盘 durable issuance record。
3. 选中的 proxy 校验 carrier、session、backend、key、grant、profile、sequence、expiry，
   然后只记录 content-free MONITOR event。

通过校验的 observation 被故意隔离在 disposition queue 和平台 action executor 之外；当前不能
kick、limit、quarantine、deny 或 ban 玩家。

release-grade Authority V4 还需要实际签名 protobuf grant/observation frames、真实 Grim/Vulcan
events、provider/Paper/proxy/process 与 journal ledgers、精确 artifact bytes、14 份 canonical
raw document、10 份 packaged artifact、已批准外部 Ed25519 supervisor descriptor/pin 与新鲜
detached receipt，以及精确受保护 V4 服务端 JAR。producer 固定输出 `release_eligible=false`；
只有 native publisher 在完整 raw revalidation 后才能创建 release-eligible V4 index。当前没有
保留 genuine external capture/index，因此该门 PENDING。

详见[服务端确认 authority](docs/SERVER_CONFIRMED_AUTHORITY.md)和
[生产 Authority provision](docs/PRODUCTION_AUTHORITY_PROVISIONING.md)。

## 构建与开发检验

根模块使用 JDK 21，隔离 modern 客户端使用 JDK 25；dependency verification 必须保持 strict：

```powershell
$env:JAVA_HOME = '<JDK 21 路径>'
.\gradlew.bat clean build localVerificationBundle `
  "-PmcaceProductVersion=0.0.1" `
  "-PmcaceSourceCommit=$(git rev-parse HEAD)" `
  "-PmcaceModernJavaHome=<JDK 25 路径>" `
  --offline --dependency-verification=strict --rerun-tasks `
  --no-build-cache --no-configuration-cache --no-daemon `
  --no-parallel --max-workers=1 --console=plain
```

Matrix V4 focused regression（不能替代外部 receipt）：

```powershell
pwsh -NoProfile -File .\scripts\test-server-version-process-matrix.ps1
pwsh -NoProfile -File .\scripts\test-publish-server-version-matrix-evidence.ps1
pwsh -NoProfile -File .\scripts\test-release-readiness.ps1
```

不要把裸 Matrix `-Execute` 当成发布证据。真实 Matrix V4 run 必须提供精确 artifact source、
既有 V4 bundle、外部 trust root、受保护 pin、supervisor exchange directory、detached receipt、
publication 和 readiness revalidation。完整流程以
[SERVER_VERSION_MATRIX_EVIDENCE_V4.md](docs/SERVER_VERSION_MATRIX_EVIDENCE_V4.md)为准。

### UI smoke 与唯一发布批准的区别

可以选择一个 target 做开发阶段可见平台 smoke：

```powershell
$env:JAVA_HOME = '<所选 target 对应的 JDK21 或 JDK25>'
.\scripts\platform-load-smoke.ps1 `
  -FabricTarget 1.21.11 -WithFabricEvidence `
  -ManualConsentTimeoutSeconds 120
```

如需检查版本特定 UI 兼容性，可以可选地把同一 smoke 重复到 `26.1.2` 与 `26.2`。这些可选
运行**不是额外发布批准**，platform-only evidence 也不能替代唯一的外部签名 GUI/Federation V5
package。超时报告只能作为 diagnostic。

## 发布产物

精确分发包固定为八项：六个可部署 JAR、`release-manifest.properties`、`SHA256SUMS`。

| 文件 | 作用 |
| --- | --- |
| `mcace-client-fabric-1.21.11.jar` | Fabric 1.21.11 客户端 |
| `mcace-client-fabric-26.1.2.jar` | Fabric 26.1.2 客户端 |
| `mcace-client-fabric-26.2.jar` | Fabric 26.2 客户端 |
| `mcace-server-velocity.jar` | Velocity 代理插件 |
| `mcace-server-bungeecord.jar` | BungeeCord 代理插件 |
| `mcace-server-paper.jar` | Paper/Folia 后端插件 |
| `release-manifest.properties` | V4 最终源码、artifact source、runtime、toolchain 与 bundle identity |
| `SHA256SUMS` | 六份 JAR 的权威 hash |

只有干净的受保护 main/tag `MCACE_RELEASE_BUNDLE_V4` 才能发布。manifest 的最终
`source_commit`、`artifact_source_commit`、canonical tracked artifact-source marker 和全部
hash 必须与受保护 CI context 一致。旧 feature bundle 只能作为历史候选，不能给正式 release
note 或 tag 提供产物。

## 历史证据归档

下列文件继续用于 provenance 与 regression history，但没有一份是当前 release evidence：

| 历史 witness | 精确边界 |
| --- | --- |
| [Feature CI `5a7e423`](docs/evidence/github-feature-ci-2026-08-25-5a7e423.json) | 历史 feature build/test/upload witness；不是受保护最终源码 CI |
| [Helio bundle `63ae400`](docs/evidence/release-bundle-2026-08-25-63ae400.json) | 历史 feature exact-source 候选；不是受保护 V4 release bundle |
| [Readiness `dda766b`](docs/evidence/release-readiness-2026-08-25-dda766b.json) | 历史 `MCACE_RELEASE_READINESS_V1`；当前 validator 是 V2 |
| [Matrix `bef44e3`](docs/evidence/server-version-process-matrix-2026-08-25-bef44e3.json) | 历史 V1 12/12 进程诊断；不是 Matrix V4 发布证据 |
| [Metadata fixture `d835f42`](docs/evidence/helio-2026-08-25-anticheat-sync-current.json) | 历史 metadata-only correlation run；没有第三方执行或 enforcement |
| [更早 bundle `e7f6f74`](docs/evidence/release-bundle-e7f6f74.json) | 仅历史 feature 候选 |
| [仓库保护快照](docs/evidence/github-protection-2026-08-25.json) | 带日期的 branch/tag policy witness；不能替代受保护 release CI |
| [项目迁移记录](docs/PROJECT_MIGRATION.md) | D 盘源码迁移历史；与发布门完成无关 |

## 架构

```mermaid
flowchart LR
  C[Fabric 客户端\n1.21.11 / 26.1.2 / 26.2]
  P[Velocity / BungeeCord]
  B[Paper / Folia]
  O[CLIENT_REPORTED / LOW\nloaded Mods + selected packs]
  S[独立服务端 providers]
  A[签名 MONITOR authority]
  R[可复核当前连接 policy]

  C -->|签名 handshake + 有界 observations| P
  P -->|admission + backend grant| B
  C --> O
  B --> S
  S --> A
  O --> R
  A --> R
```

这些箭头不代表自动处罚。客户端观察保持 advisory；Production Authority V4 输出目前终止于
MONITOR 日志。

## 目录

| 模块 | 职责 |
| --- | --- |
| `mcace-protocol` | wire schema、capability negotiation、签名、canonical encoding、replay defense |
| `mcace-core` | session、admission、policy、risk、disposition、federation、服务端 authority 原语 |
| `mcace-client-common` | loader-neutral integrity、Loaded ModList model、证据和连接 enablement 原语 |
| `mcace-client-fabric` | Fabric 1.21.11 客户端、loaded-graph collector、consent UI |
| `fabric-modern` | 26.1.2 与 26.2 的 JDK 25 official-namespace 客户端 |
| `mcace-server-velocity` | Velocity admission、policy、federation 与可选 authority adapter |
| `mcace-server-bungeecord` | BungeeCord admission、policy、federation 与可选 authority adapter |
| `mcace-server-paper` | Paper/Folia context、provider adapter、durable MONITOR authority path |
| `mcace-runtime-integration` | process、protocol、受控 fixture 与 integration harness |
| `scripts` | fail-closed 构建、兼容性、GUI、federation、Matrix、Vulcan、Authority、publisher、readiness gate |

## 文档索引

- [架构](docs/ARCHITECTURE.md)
- [客户端完整性与 Loaded ModList policy](docs/CLIENT_INTEGRITY_POLICY.md)
- [检测与证据边界](docs/DETECTION_AND_EVIDENCE.md)
- [Server Version Matrix Evidence V4](docs/SERVER_VERSION_MATRIX_EVIDENCE_V4.md)
- [Federation V5 设计与验收](docs/FEDERATION.md)
- [服务端确认 authority](docs/SERVER_CONFIRMED_AUTHORITY.md)
- [Production Authority provisioning](docs/PRODUCTION_AUTHORITY_PROVISIONING.md)
- [Native release evidence 发布流程](docs/NATIVE_RELEASE_EVIDENCE.md)
- [平台测试](docs/PLATFORM_TESTING.md)
- [运维](docs/OPERATIONS.md)
- [安全模型](docs/SECURITY.md)
- [发布门](docs/RELEASE_GATES.md)
