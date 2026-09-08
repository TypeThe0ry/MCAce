# Resource-pack texture observations — 2026-09-08

## Implementation / 实现

MCAce now probes policy-authorized ZIP resource packs for a small, bounded
content feature. This is not a filename blacklist. It examines PNG overrides
for stone, deepslate, dirt, gravel, sand and netherrack. A texture is counted
as mostly transparent when at least 90% of its pixels have alpha below 32;
three such textures produce `xray_heuristic=opaque-block-transparency`.

客户端现在对策略授权范围内的 ZIP 材质包检查纹理内容，而不是按文件名判定。
目前检查上述六种常见不透明方块；至少三种纹理满足透明像素阈值时，生成可疑特征。

The archive bytes are SHA-256 matched to the preceding integrity manifest
before content findings are emitted. No extraction or image disk cache is used.
Limits per archive: 16 MiB compressed, 8 MiB expanded across all ZIP entries,
4,096 entries, 1 MiB per target PNG, and dimensions at most 512 × 512.
Cancellation is checked during archive reading. Invalid or over-budget inputs
discard partial findings and report `invalid` or `limit-exceeded`, not clean.
Directory-form packs remain ordinary manifest entries; they are not analyzed
by this ZIP probe.

读取到的 ZIP 字节必须与完整性清单 SHA-256 一致；不解压到磁盘。
无效、超限、目录式材质包均不能算作“已经证明安全”。

## Transport and interpretation / 上报与解释

An optional typed `FileEntry.texture_probe` carries status and two bounded
counters inside the signed authentication request and the existing signed
observation-update scope manifests. The server permits it only on ZIP entries
in the directory-authorized resource-pack scope, validates the counters, and
derives the heuristic from them. This field does not change the file-content
Merkle root: its authenticity is covered by the enclosing signed payload, not
by the file-content root alone. Legacy entries without the field remain valid.

The server observation retains the existing `selected` state separately.
Both selected and dormant packs can contain the feature. Every such report
remains `CLIENT_REPORTED` / `LOW`; no built-in ban, kick, or quarantine rule is
enabled by this change. A malicious client can lie about its own telemetry.
A transparent texture feature can also occur in legitimate custom packs.
It is not independent `SERVER_CONFIRMED` proof and cannot cover model-based
Xray, shaders, arbitrary cheat programs, kernel tampering, injection or DMA.

服务端能接收此纹理特征，并单独保留材质包是否被选中的状态。
报告仍为低置信度客户端自报；本次没有默认开启封禁、踢出或隔离策略。
合法自定义材质也可能触发，客户端还可能伪造自报数据，不能把这条特征当成独立实锤。

## Verification / 验证

Automated tests generate actual PNG bytes in temporary ZIP files, then exercise
the production scanner and collector. Cases cover neutral filenames, opaque
recolors, transparent glass exclusion, the three-texture threshold, malformed
and oversized PNGs, decompression limits, scan cancellation, changed archive
hashes, policy scope exclusion and directory-pack preservation.

`HandshakeIntegrationTest.signedTextureProbeReachesServerWithSelectedStateAndLowConfidence`
generates a transparent three-texture pack, collects it, signs a real protocol
authentication request and delivers it to `ServerHandshakeCoordinator`.
The server callback and observation deriver must retain the feature for both
selected and unselected cases without promoting origin or confidence.
Another test rejects a signed attempt to attach this report to a Mod entry.
The same integration test then sends a bounded, signed post-authentication
update toggling the selected state in both directions. The server acknowledges
the update, retains the texture feature, updates `selected`, and leaves the
verified admission unchanged.

Local results (JDK 21 root project; JDK 25 modern Fabric, Gradle 9.6.1):

| Suite | Tests | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Protocol, full | 76 | 0 | 0 |
| Client common, full | 103 | 0 | 3 |
| Core handshake + manifest deriver, selected | 41 | 0 | 0 |
| Fabric 1.21.11 | 50 | 0 | 0 |
| Fabric 26.1.2 | 51 | 0 | 0 |
| Fabric 26.2 | 51 | 0 | 0 |

The three skips are one Windows symlink-creation coverage gap and two opt-in
classification fixture tests whose external fixture inputs were not supplied
in the full client-common invocation. A preliminary full core run was stopped
during slow authority-filesystem tests; it is not counted as a full-suite pass.
The initial new collector test used an invalid empty-scope bundle; it was fixed
to use an authorized mods-only policy for the resource-pack exclusion case.

Reproduction, with the cached dependencies and appropriate JAVA_HOME:

```powershell
# JDK 21, repository root
./gradlew.bat :mcace-protocol:test :mcace-client-common:test :mcace-core:test --tests '*HandshakeIntegrationTest' --tests '*AuthenticatedManifestObservationDeriverTest' :mcace-client-fabric:test stageModernFabricDeps --offline --no-daemon --no-configuration-cache --max-workers=1
# JDK 25, repository root
./gradlew.bat -p fabric-modern :client-26.1.2:test :client-26.2:test --offline --no-daemon --no-configuration-cache --max-workers=1
```

These are automated Java integration tests, not a real Minecraft GUI/server
session and not a third-party cheat run. Real Fabric reload → server receive →
explicit policy action verification is still pending. The previous release
bundle predates this product change and must not be presented as its build.

以上是实际 PNG 内容与签名协议的自动化集成测试，不是 Minecraft GUI 实服验收。
真实客户端重载材质 → 服务端接收 → 明确策略处置仍待验证，旧发布包不包含本次代码。

## Candidate build / 候选构建

After implementation, `releaseBundle` succeeded for source
`fcc5396d140760da29fdb91a6a2347fe59ef0fb9`, artifact source
`91ce31dc98ab4b0b0ccb09e534ca87a8a0c69688`, version `0.0.1`.
The V4 manifest reports six deployables and eight bundle entries. All six
on-disk SHA-256 values were independently compared with `SHA256SUMS`:

```text
2e9d9d3672df30bfa6fbdb280a8c7b8f55cf62eb76e7b054b0a63febc24119ac  mcace-client-fabric-1.21.11.jar
122cbcd29aa6412df74dd2c281b86c3f32310e6a2406deea4c66c7305811144a  mcace-client-fabric-26.1.2.jar
86b9f8a867e485cfa4fa01e133a80a095cb8c10f3e098f1ee32f964586cedcf4  mcace-client-fabric-26.2.jar
24079074685ea001cc3edceb9e5fa639a502cd9bc4e5707908d51cfad9cdbe91  mcace-server-velocity.jar
6fd7e75db5096dd66bc8df044646fff4f06eb495eb9b5d5fb14a5ba7093d2309  mcace-server-bungeecord.jar
bb48dce55e3b75b9347e146107309355daeac57b60e642a7702044c72d6e10d8  mcace-server-paper.jar
```

Version compatibility static contracts also passed with six negative cases.
This is a local candidate build, not protected-main/tag CI or release approval.
Its source identity is the commit above, not the later documentation-only
commit recording this result. No tag or GitHub Release was created.
