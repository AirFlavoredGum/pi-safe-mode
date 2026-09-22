# v1.2.0 — 可移植化 + HARD-OFF（完全关闭）

> Tool-boundary policy enforcement for pi. This release focuses on portability,
> and on an honest, human-only full-off switch.
>
> - 发布标签：`v1.2.0`
> - 详细变更：也可看 [`CHANGELOG.md`](../CHANGELOG.md)
> - 安装与能力边界：见 [`README.md`](../README.md)（第 0、1、7、10 节）

---

## 一句话

以前它只在你那台机器的 `D:\pi-agent` 下才真正生效；现在**装到哪都能正确保护自己的边界**，
并且多了一个**只有你本人能打开、只活一个会话**的「完全关闭」开关。

---

## 新增：HARD-OFF（完全关闭，`safe.txt` §38）

```
/safe off --hard      # 确认框 + 键入「完全关闭」两步人工确认
pi --unsafe           # 启动即完全关闭（仅本次运行）
```

关闭后扩展退化成「这个窗口没装过 Safe Mode」：

| 项 | HARD-OFF 时 |
| --- | --- |
| 工具调用裁决 | 不做（不弹窗、不拒绝） |
| system prompt 约束注入 | 不做 |
| 审计日志 | 不写 |
| 完整性校验 / fail-closed 降级 | 不跑 |
| 工具输出秘密脱敏 | 不做 |
| 手打 `!` 命令 | 直接透传 |
| 状态栏徽标 | **保留** `🛡 SAFE: HARD-OFF — no protection` |
| 会话记录 | 只记一条「已完全关闭」（便于事后查证） |

刻意的取舍（`safe.txt` §38 已写明）：

- **只能由人开启** —— `/safe` 是用户命令，`pi --unsafe` 也得你自己敲；命令端还要求
  真人当下在场（确认框 + 键入确认词），避免「一句话骗你敲一下就永久无保护」
- **永不持久化** —— 重启 pi 即回到配置等级。因为关闭期间磁盘上没有任何东西受保护，
  一个可持久化的关闭开关只要被改一次，就会长期静默失守
- **模型不得使用它** —— §38 明确禁止模型开启、建议开启、或拿它绕过被拒绝的操作；
  `Ctrl+Alt+S` 与 `/safe on` 在 HARD-OFF 下**只能**重新开启，不会关得更彻底
- **fail-open 且可见** —— 它检测不到任何针对自己的篡改，所以必须始终显示徽标，
  让「无保护」不会被误认为「已保护」

---

## 新增：路径可移植（`pi-extension/paths.ts`）

之前 `SAFE_ROOT` 默认写死 `D:\pi-agent`，`policy.ts` 里 16 条边界路径正则硬编码
`^d:/pi-agent/...` —— 装到别的盘符或目录时，**边界路径保护会静默失效**（最糟的失败方式）。
现在所有路径由一个模块解析，优先级：

| 顺序 | 来源 |
| --- | --- |
| 1 | `SAFE_MODE_ROOT` |
| 2 | `SAFE_MODE_HOME` 的父目录 |
| 3 | `PI_CODING_AGENT_DIR` 的父目录（pi 自己导出，零配置） |
| 4 | 镜像自身位置（`<root>\agent\extensions\safe-mode\…` 反推） |
| 5 | 历史默认值 `D:\pi-agent`（仅当它真实存在） |

边界规则改由 `boundaryPathRe()` / `boundaryChildRe()` 从上述路径构造。
`/safe doctor` 新增 `Safe root: <路径>（来源）` 与 `MODE` 行 —— 路径判定不再是黑箱。
`safe-bootstrap.ps1` / `safe-regen.ps1` 同样支持环境变量覆盖（默认取脚本所在目录的上一级）。

---

## 新增：非 Windows 平台主动降级（fail-closed）

本版本的路径语义按 Windows 校验（驱动器号、大小写不敏感、`\` 与 `/` 混用、MSYS `/d/foo`）。
在 macOS / Linux 上路径比较会不可靠 —— 此时扩展**不会假装没事**：完整性校验主动报
`platform` 问题 → 状态 **DEGRADED** → 高风险操作 fail-closed 拒绝（日常读写、编译、测试不受影响）。

> 宁可不能用，也不假装路径保护有效。

要真正支持 POSIX，需要把 `checks.ts` 的 `normalizePath`、`paths.ts` 的归一化改成平台感知，
并替换 `policy.ts` 里 Windows 专有的规则（系统目录、盘符根）。欢迎 PR。

---

## 新增：测试可在任意安装位置运行

- 新增 `pi-extension/tests/harness.mjs`：自动发现 pi / jiti / 实现目录
  （`SAFE_TEST_IMPL_DIR`、`SAFE_TEST_LOAD_DIR`、`SAFE_TEST_JITI`、`SAFE_TEST_PI_ROOT` 可覆盖）
- `e2e.test.mjs` 增加 18 项 HARD-OFF 行为检查：确认被拒 / 确认词错误 / 真正关闭 /
  无策略注入 / 无脱敏 / `!` 命令直通 / 不落盘 / 快捷键只能恢复 / `--unsafe` / 软关闭仍然拦截
- **本地验证结果：engine 102 项 + e2e 170 项全部通过**
- 未部署（没有 `safe-manifest.json`）时，依赖清单的用例显式打印 `SKIP` 并说明原因

---

## 修复

- **`safe-bootstrap.ps1` / `safe-regen.ps1`：根目录多推了一层父目录**。
  `$PSScriptRoot` 已经是 `<root>\safe-mode`，只需一层 `Split-Path -Parent`；
  写成两层后会去找 `D:\safe-mode\...`，在非默认布局下报一串 `missing`。
- **`safe-regen.ps1`：三个脚本被静默漏出清单**。把 `$Extras` 改成绝对路径后，
  代码里仍然执行 `Join-Path $Root $name` → 得到无效路径 → `Test-Path` 失败 → 直接跳过。
  后果是 `safe-bootstrap.ps1` / `safe-launch.cmd` / `safe-regen.ps1`
  **不再被任何哈希校验**（L1 自校验的核心被架空，且不报错）。
  现在同时接受绝对/相对路径，且任一文件缺失就**硬报错 `exit 2`**。
- **`safe-regen.ps1`：镜像目录缺失时也硬报错**，否则会生成只覆盖单侧副本的隐性残缺清单。
- **`safe-regen.ps1`：`$Root` / `$SafeHome` / `$AgentDir` 去掉尾部反斜杠**，
  避免按前缀推导相对路径时多切一个字符。
- `safe-regen.ps1` 结尾的 “Next:” 提示不再写死 `D:\pi-agent\...`。

> 教训（已写进实现）：安全层的脚本里，**任何「找不到就跳过」的写法都是缺陷**。
> 清单少登记一个文件不会报错，只会静静失去对该文件的篡改检测。所以现在一律 fail-loud。

---

## 安装

```powershell
git clone https://github.com/AirFlavoredGum/pi-safe-mode.git D:\pi-safe-mode

# 先看它要做什么（只读，不写盘）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\pi-safe-mode\install.ps1 -Root D:\pi-agent -WhatIf

# 真正安装
powershell -NoProfile -ExecutionPolicy Bypass -File D:\pi-safe-mode\install.ps1 -Root D:\pi-agent
```

`-Root` 指**包含 `safe-mode\` 目录的那一级**。然后按脚本提示做两步：

```powershell
# 生成完整性清单（会让你键入 yes —— 只有人能把当前文件认定为可信基线）
powershell -NoProfile -File D:\pi-agent\safe-mode\safe-regen.ps1

# 把镜像与规范副本对齐
powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -Fix
```

打开 pi → `/safe doctor`，看到 `Integrity: integrity OK` 即完成。

### 升级已有安装

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File <repo>\install.ps1 -Root <pi root> -Force
powershell -NoProfile -File <pi root>\safe-mode\safe-bootstrap.ps1 -Fix
powershell -NoProfile -File <pi root>\safe-mode\safe-regen.ps1     # 键入 yes
powershell -NoProfile -File <pi root>\safe-mode\safe-bootstrap.ps1 -VerifyOnly   # 期望 RESULT: OK
```

顺序很重要：`regen` 会把「规范副本 + 镜像」两份都冻进清单，所以**镜像必须先同步到位**。
未重设基线时 `/safe verify` 会报 `DEGRADED`（高风险操作 fail-closed）—— 这是设计，不是故障。

---

## 边界声明

这是**工具边界策略层（Tool-boundary Policy Enforcement），不是安全沙箱**：
不做 OS 级隔离，也无法限制已放行程序内部的行为、扩展内部的 `pi.exec`/fs 调用、
MCP server 进程内部行为，以及提示注入防御的实现强度。
完整能力矩阵与残留风险见 `README.md` 第 1 节与第 7 节。

许可：MIT（见 [`LICENSE`](../LICENSE)）。

---

## English summary

**Safe Mode for pi v1.2.0 — portable paths + a real off switch.**

- **Portable**: no path is hardcoded any more. Every boundary rule is derived from
  `SAFE_MODE_ROOT` / `SAFE_MODE_HOME` / `PI_CODING_AGENT_DIR` at runtime, so it protects the
  right files wherever you install it. `/safe doctor` shows which root was detected and why.
- **HARD-OFF**: `/safe off --hard` (confirmation dialog + typed word) or `pi --unsafe` turns the
  layer completely off for that session — no interception, no policy injection, no audit, no
  secret redaction. Session-scoped and never persisted, because a persisted off switch can be
  flipped once and stay flipped unnoticed. Only a human can enable it; the model must never use it.
- **Fail-closed platform gate**: path semantics are Windows-validated, so on other platforms the
  extension reports `DEGRADED` and refuses higher-risk operations instead of pretending to protect.
- **Tests run anywhere**: 102 engine + 170 end-to-end checks, including HARD-OFF behaviour.
- **Fixes**: two PowerShell bugs (root resolved one level too high; three scripts silently dropped
  from the integrity manifest — now a hard error instead of a silent skip).

It is a boundary policy layer, **not an OS sandbox**.
