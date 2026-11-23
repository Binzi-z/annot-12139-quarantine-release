# 并行隔离区放行控制（Go 标准库，Windows）

两个租户共享 3 个并行扫描工作槽的本地文件隔离区。扫描器是随项目交付的确定性模拟器，
只读取合成无害文件。实现仅用 Go 标准库，`go test ./...` 可在 Windows 上直接完成核心验收。

## 目录

```
quarantine/                 核心库
  types.go                  领域类型、绑定哈希、任务状态
  clock.go                  可控时钟（SystemClock / ManualClock）
  scanner.go                确定性模拟器 + Scanner 接口
  store.go                  内容寻址 blob、原子状态文件、发布目录
  engine.go                 Engine、加载/持久化、审计事件
  engine_ops.go             提交/合并、调度、取消、放行、查询
  lock_windows.go           LockFileEx 数据目录互斥锁
  testkit.go                测试用可控扫描器与放行钩子
  demo.go                   离线演示
  internal/model/           独立顺序参考状态机（仅测试使用）
cmd/quarantine/main.go      CLI + 离线演示命令
```

## 核心不变量与提交点

所有提交点都在同一把引擎互斥锁下完成，因此语义与真实并发无关、只取决于谁先拿到锁。

- **输入冻结**：上传即按内容 `SHA-256` 命名 blob，先写临时文件再原子改名，永不覆盖。
  任务保存 `(租户, 摘要, 冻结规则版本, 任务ID)`，结果里带 `Binding = SHA256(任务ID,租户,
  摘要,规则版本)`；任何字段被篡改都会被 `Result.Validate` 拒绝。
- **扫描结果提交**：只有任务仍是当前尝试、未被取消时才提交。被取消/被取代/超时后的迟到
  响应一律丢弃（审计事件 `discard_late`），永不改写任务或占用槽位。
- **取消提交**：取消先于结果则结果不能再附着；结果先于取消则取消返回 `ErrTooLate`。
  合并任务取消其一，只解绑该任务，共享扫描继续；全部取消才停止扫描。
- **放行提交**：在锁内要求"干净结果 + 结果规则版本 == 当前规则版本 + 未在放行中"。
  规则更新先拿到锁 ⇒ 旧结果 `ErrStaleResult`，不产生文件；放行先拿到锁 ⇒ 复制照常完成。
  复制后重新计算落盘摘要，发布目录里的实际字节即为放行证明。
- **失败/超时仅留隔离区**：重试有界（`MaxAttempts`），耗尽后提交 `VerdictError` 的绑定结果，
  该结果对该租户/摘要/规则粘滞，重复请求不再扫描，且永远无法放行。

## 任务合并与租户隔离

- 同租户、同摘要、同冻结规则版本的**活跃**任务合并为一次扫描（`RouteMerged`）。
- 其他租户永远不附着：键包含租户，`RouteNew`。
- 已完成的结果按同样键缓存，重复提交直接命中（`RouteCached`），不新增扫描调用。
- 相同 `requestID` 重复提交返回先前任务的确定结果（`RouteDuplicate`）；同一 ID 不同内容报
  `ErrRequestConflict`。

## 调度与公平性

- 3 个工作槽 = 最多 3 个并行真实扫描调用（`Stats().MaxInflight <= 3`）。
- 有多个租户等待时，单租户最多占 `Slots-1 = 2` 个槽，剩余槽位留给另一租户；无争用时允许
  占满，避免空转。选择在租户间轮转、租户内按提交顺序。
- 某租户持续提交/取消时，另一租户的最早作业会在有限调度轮次内获得槽位
  （`TestFairnessUnderFloodingTenant`、`TestCancelStormDoesNotStarveOtherTenant`）。
- 重试退避有定时唤醒（`nextBackoffLocked`），不会因退避而永久挂起。

## CLI

默认数据目录 `./demo-data`，可用 `-data DIR` 或环境变量 `QUARANTINE_DATA` 覆盖；`-json`
输出机器可读结果。每次调用打开引擎、执行、关闭，已提交结果与规则版本跨进程持久化。

```bash
# 提交并等待确定结果（离线合成文件）
quarantine submit -tenant tenant-a -file clean.bin -request req-1

# 结果查询：打印绑定信息
quarantine result -tenant tenant-a -task 1

# 放行（仅干净且规则版本匹配）
quarantine release -tenant tenant-a -task 1

# 查询 / 更新规则版本
quarantine rules
quarantine rules -update

# 查看任务、槽位统计、取消
quarantine list   -tenant tenant-a
quarantine slots
quarantine cancel -tenant tenant-a -task 2

# 一条离线演示命令
quarantine demo
```

`submit` 与 `release` 对同一任务重复调用是幂等的；放行旧规则结果会被拒绝且不留文件。

## 离线演示

`quarantine demo` 在临时目录中用真实引擎、真实 worker 和确定性模拟器跑完整剧情：

1. tenant-a 两次上传同一内容 → 合并为一次扫描；
2. tenant-b 上传相同内容 → 独立扫描（跨租户不合并）；
3. tenant-a 上传感染样本 → 永不放行；
4. 同 `requestID` 重复请求 → 命中已确定结果；
5. 放行干净结果，再重新读取发布目录的实际摘要核对；
6. 输出调度顺序、扫描器调用计数、最大并行数。

演示结束保留数据目录供检查（`-out DIR` 指定目录，`-json` 输出结构化报告）。

## 测试

```bash
go test ./...            # Windows 上直接运行核心验收
go test ./... -count=1   # 禁用缓存
```

覆盖要点：

- **独立状态机对比**（`differential_test.go`）：`internal/model` 是不引用引擎的纯顺序状态机；
  对 10 个手写交错场景 + 25 轮确定性随机双租户交错逐步比对任务状态、结果、规则版本和放行。
- **真实 worker + 可控时钟 + 屏障**：
  - `TestCancelAfterMergeRepeated`（60 次）：取消合并任务后共享扫描只调用一次，其余任务仍得结果；
  - `TestOldRuleLateResultCannotRelease`、`TestTimedOutAttemptLateResultDiscarded`：旧规则/超时后
    才返回的结果不能提交；
  - `TestReleaseRuleRaceRepeated`（50 次双向）：放行与规则更新的两个提交方向都验证；
  - `TestTimedOutAttemptLateResultDiscarded`、`TestSlotFreedOnTimeout`：超时释放槽位、迟到结果丢弃；
  - `TestThreeSlotsBound`、`TestDispatchOrderIsRoundRobin`：并行上限与调度顺序；
  - `TestFairnessUnderFloodingTenant`、`TestCancelStormDoesNotStarveOtherTenant`：公平性；
  - `TestRestartDurability`：重启后结果/规则版本/放行幂等、未完成作业转为隔离失败。
- **按实际落盘摘要、扫描器调用计数、调度顺序核对**：`TestOfflineDemo` 读取发布目录重算 SHA-256，
  并断言扫描调用恰为 4 次、无感染文件泄漏。
- **CLI**（`cli_test.go`）：跨进程式调用 submit/result/release/rules/list/slots/demo，验证持久化与
  JSON 契约。

`main_test.go` 内置 40 秒看门狗，若测试死锁会打印所有 goroutine 栈并失败，便于在 Windows 上定位。
