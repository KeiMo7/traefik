# 同一主机名多证书并存与按对端能力选择

## 问题定位

两个缺陷都在 `pkg/tls/certificate_store.go`：

1. **存储按域名集合去重**。`UpdateConfigs` 把动态证书存成 `map[域名集合]*CertificateData`。
   同一主机名的 RSA 与 ECDSA 两张证书域名集合完全相同，`appendCertificate` 判定
   “已存在”后直接丢弃后者，只在 Debug 日志里留一句 Skipping。配置侧因此没有任何报错，
   而 Store 里只剩一张（取决于配置顺序）。
2. **选择不看对端能力，且缓存键不含能力**。`GetBestCertificate` 只按 `ServerName`
   匹配域名后返回第一张，`CertCache` 也只用 `serverName` 做键。于是：
   - 只会出示配置顺序上靠前的那一张，对端不支持时握手失败；
   - 先到的客户端产生的选择结果会被后到、能力不同的客户端复用。

另外还有两处与需求直接相关的问题：

3. `Manager.Get` 在构建 `tls.Config` 时把 `*CertificateStore` 指针捕获进 `GetCertificate` 闭包，
   而 `UpdateConfigs` 是整体替换 `m.stores`。已经发出的 `tls.Config` 会一直指向旧 Store，
   热更新后仍从旧集合选证书（对应需求“更新后不残留旧选择”）。
4. 选不出证书时一律回落到默认证书，即使默认证书对端也用不了；对端只能一直等到握手失败，
   服务端日志也看不出是“没有该名字的证书”还是“有证书但对端不接受”。

## 改动

### 存储模型（`pkg/tls/certificate_store.go`）

- 新增 `certificateEntry{data, domains, domainsKey, fingerprint}` 与不可变快照
  `certificateSet{entries, generation}`，取代 `map[域名集合]*CertificateData`。
  一个主机名可以对应任意多张证书。
- 去重只针对证书内容：`certificateFingerprint` 对整条证书链做 SHA-256，
  只有内容完全相同的证书才跳过（`certificateStoreBuilder.seen`）。
- `DynamicCerts` 字段保留原类型 `*safe.Safe`，其中装的是 `*certificateSet`。
  `CertificateStore` 的导出方法签名（`GetAllDomains`/`GetDefaultCertificate`/
  `GetBestCertificate`/`GetCertificate`/`ResetCache`）与 `CertificateData` 均未改动。

### 原子发布与缓存同源失效

- `setDynamicCertificates` 每次构建并发布一个**新的** `*certificateSet` 对象，
  已发布的快照此后不再被修改，因此握手读取时不会看到半新半旧的集合。
- `generation` 递增并写入新快照，同时 `CertCache.Flush()`；缓存键内含 generation，
  即使有遗漏的条目也不会被下一代复用。配置更新与缓存失效因此是同源的。

### 选择过程（只读、无 I/O、确定性）

`certificateSet.candidates(serverName)` 返回按优先级排好序的候选：

1. 精确匹配优先于通配匹配；
2. 同级之间沿用既有顺序（域名集合逆字典序），保证现有单证书/通配行为的取舍不变；
3. 域名集合也相同时按证书内容指纹排序 —— 这就是“两族都支持时按固定优先级选一张”，
   且优先级与配置顺序无关，多次握手结果一致。

`certificateUsableByClient` 用 `crypto/tls` 的 `ClientHelloInfo.SupportsCertificate`
判断对端能否使用某张证书（签名算法、曲线、密码套件、TLS 版本）。判断时会清空 `ServerName`：
名字匹配已由 `matchDomain` 完成，且默认证书历来允许不带请求的名字。

选择被拆成两段：

- **按名字的候选集**才进缓存（键为 `names\0<serverName>\0<generation>`）；
- **按能力过滤**每次握手现算，不缓存。

这样既保持了“选择只由对端能力与已配置证书决定”的确定性，也从结构上杜绝了
“一种能力的选择串给另一种能力”。

### 握手入口（`pkg/tls/tlsmanager.go`）

- `GetCertificate` 改为每次握手通过 `m.currentStores(storeName)` 重新取当前 Store，
  不再捕获构建时的指针，热更新立即对已发出的 `tls.Config` 生效。
- 选不出证书时按原因记日志：
  - `reason=no_certificate_for_name`：该名字没有配置任何证书；
  - `reason=no_acceptable_certificate`：有证书，但对端能力不接受。
- `sniStrict` 语义不变（仍然拒绝）。非严格模式下，如果默认证书对端也用不了，
  直接返回 nil 让 `crypto/tls` 以 `alertUnrecognizedName` 关闭握手，
  不再把一张对端无法验证的证书发出去让对端慢慢超时。
- ACME TLS-ALPN 挑战证书仍走独立 store，并以 `requireClientSupport=false` 按名字选择，
  行为与改动前一致，不受新逻辑干扰。

### 日志

新增 `reason` 字段（`reasonNoCertificateForName` / `reasonNoAcceptableCertificate`），
日志中不出现私钥或整段证书内容；`TestCertificateSelection_LogsReasonsAndNoSecrets`
对此做了断言。

## 失败与降级

- 某张证书解析失败时 `UpdateConfigs` 跳过并记录（原有行为），其余证书照常入 Store，
  不会因为一张坏证书导致全站无证书可用（`TestBuildCertificateSet_PartialParseFailure`）。
- 更新期间握手要么看到完整旧快照、要么看到完整新快照（`TestCertificateSelection_ConcurrentUpdate`）。
- 失败路径不写缓存：只有成功选出的候选集才 `SetDefault`，不存在的名字不会被缓存成空结果。

## 测试

新增/调整的文件：

- `pkg/tls/certificate_store_handshake_test.go`：真实起 `net.Listener` + `crypto/tls` 服务端，
  用两类受限客户端完成真实握手：
  - RSA-only：TLS 1.2，仅 `TLS_ECDHE_RSA_WITH_AES_*`；
  - ECDSA-only：TLS 1.2，仅 `TLS_ECDHE_ECDSA_WITH_AES_*`。- `pkg/tls/certificate_selection_test.go`：表驱动覆盖选择规则、固定优先级、只读性、
  缓存不跨能力、更新失效、去重、部分解析失败、store 隔离、并发更新、日志。
- `pkg/tls/testcert_test.go`：测试用 RSA/ECDSA 证书生成与贴近真实的 ClientHello 构造。
- `pkg/tls/certificate_store_test.go`、`tlsmanager_test.go`：适配新的快照结构。

覆盖到的形态（对应需求一.1–9）：

| 需求 | 用例 |
| --- | --- |
| 同名两族并存、都参与选择 | `TestSelectCertificate/both key families...`、`TestHandshake_MultipleKeyFamiliesSameName` |
| 只支持一族时选该族；两族都支持时固定优先级且可重复 | `TestHandshake_MultipleKeyFamiliesSameName`、`TestSelectCertificate_FixedPriority` |
| 无 SNI 时按本地地址回退并选出可用证书 | `TestHandshake_NoServerName` |
| 精确优先于通配，同级稳定取舍 | `TestSelectCertificate` 中精确/通配用例、`TestGetBestCertificate_SharedSAN` |
| 先到者结果不复用给后到者 | `TestGetBestCertificate_CacheDoesNotCrossCapabilities`、握手测试中的打乱顺序段 |
| 增删改后下一次握手用新集合 | `TestHandshake_ConfigUpdate`、`TestGetBestCertificate_CacheInvalidatedOnUpdate` |
| 普通流量与挑战 store 隔离 | `TestHandshake_ACMECertificateIsolation`、`TestBuildCertificateSet_StoresAreIsolated` |
| 无共同可接受证书时立即给可诊断拒绝 | `TestHandshake_NoAcceptableCertificate`（断言 `unrecognized name` 且 < 3s） |
| 日志可区分原因、不含私钥/证书 | `TestCertificateSelection_LogsReasonsAndNoSecrets` |

实际输出见同目录 `tls-selection-tests.log`、`tls-package-tests.log`。选择相关的用例全部通过：

```
--- PASS: TestSelectCertificate
--- PASS: TestSelectCertificate_FixedPriority
--- PASS: TestSelectCertificate_ReadOnly
--- PASS: TestGetBestCertificate_CacheDoesNotCrossCapabilities
--- PASS: TestGetBestCertificate_CacheInvalidatedOnUpdate
--- PASS: TestBuildCertificateSet_Deduplication
--- PASS: TestBuildCertificateSet_PartialParseFailure
--- PASS: TestBuildCertificateSet_StoresAreIsolated
--- PASS: TestCertificateSelection_ConcurrentUpdate
--- PASS: TestCertificateSelection_LogsReasonsAndNoSecrets
--- PASS: TestHandshake_MultipleKeyFamiliesSameName
--- PASS: TestHandshake_ExactOverWildcard
--- PASS: TestHandshake_NoServerName
--- PASS: TestHandshake_NoAcceptableCertificate
--- PASS: TestHandshake_StrictSNINoAcceptableCertificate
--- PASS: TestHandshake_ConfigUpdate
--- PASS: TestHandshake_ACMECertificateIsolation
--- PASS: TestGetBestCertificate
--- PASS: TestGetBestCertificate_SharedSAN
ok  	github.com/traefik/traefik/v3/pkg/tls	1.963s
```

日志里可看到按原因区分的两类拒绝/回落：

```
{"level":"debug","reason":"no_acceptable_certificate",... "TLS: no certificate for domain \"multi.example.test\" is acceptable by the client, and the default certificate is not either, closing connection"}
{"level":"debug","reason":"no_acceptable_certificate",... "TLS: strict SNI enabled - No certificate found for domain: \"multi.example.test\", closing connection"}
{"level":"debug","reason":"no_certificate_for_name",... "Serving default certificate for request: \"multi.example.test\""}
```

`make` 侧的命令等价于 `go test ./pkg/tls/`；`go build ./...`、`golangci-lint run ./pkg/tls/...`
（0 issues）、`gofmt -l pkg/tls/`（无输出）均通过。

## 未能验证的部分

- 本机无 gcc，`go test -race` 无法运行（`-race requires cgo`）。
  改用并发更新压测（`TestCertificateSelection_ConcurrentUpdate`，多 goroutine 选证书 +
  反复发布快照）间接覆盖；建议在有 cgo 的环境补跑一次 `make test-unit` 下的 `-race`。
- `pkg/provider/docker` 的 `TestDynConfBuilder_getIPAddress_docker` 在本机失败，
  但已用 `git stash` 在未改动的基线上复现，与本次改动无关（依赖本机网络接口地址）。
