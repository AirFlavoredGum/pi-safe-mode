# Safe Mode for Pi — `/safe`

给 [pi](https://github.com/earendil-works/pi) 的**工具边界策略执行层**：在每一次工具调用上做
ALLOW / CONFIRM / DENY 裁决（内建工具、扩展工具、MCP 工具都覆盖），把一套可审计的策略
（`safe.txt`）作为唯一权威来源，并且**发现自身被改动时主动降级**。

> **它不提供 OS 级隔离，不是沙箱。** 能力边界见第 1 节 —— 请先读完那一节再决定是否使用。

| | |
| --- | --- |
| 版本 | **v1.2.0**（变更记录 [`CHANGELOG.md`](CHANGELOG.md) · 发布说明 [`docs/release-notes-v1.2.0.md`](docs/release-notes-v1.2.0.md)） |
| 平台 | **Windows**（其它平台会主动降级为 DEGRADED，见下面 §0.2） |
| 许可 | MIT（见 `LICENSE`） |

---

## 0. 安装

### 0.1 三步装好

需要：Windows + PowerShell + 已经装好的 pi。不依赖网络，装完离线可用。

```powershell
# 1) 取到仓库
git clone https://github.com/AirFlavoredGum/pi-safe-mode.git D:\pi-safe-mode

# 2) 装到你的 Pi 根目录（先加 -WhatIf 可以只看它会做什么）
powershell -NoProfile -ExecutionPolicy Bypass -File D:\pi-safe-mode\install.ps1 -Root D:\pi-agent
```

`-Root` 指的是**包含 `safe-mode\` 目录的那一级**。装完后按脚本提示做两件事：

```powershell
# 3) 生成完整性清单（会让你键入 yes —— 这是刻意的：只有人能把当前文件认定为可信基线）
powershell -NoProfile -File D:\pi-agent\safe-mode\safe-regen.ps1

# 4) 把镜像与规范副本对齐
powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -Fix
```

打开 pi，输入 `/safe doctor`，看到 `Integrity: integrity OK` 就成了。
不想写盘只想体检：`safe-bootstrap.ps1 -VerifyOnly`。

### 0.2 装到哪由谁决定（无写死路径）

所有路径由一个模块解析（`pi-extension/paths.ts`），优先级如下：

| 顺序 | 来源 | 说明 |
| --- | --- | --- |
| 1 | `SAFE_MODE_ROOT` | 显式指定 Pi 根目录 |
| 2 | `SAFE_MODE_HOME` 的父目录 | 只指定了 Safe Mode 家目录时反推 |
| 3 | `PI_CODING_AGENT_DIR` 的父目录 | pi 自己导出的变量（零配置） |
| 4 | 镜像自身位置 | 由 `<root>\agent\extensions\safe-mode\…` 反推 |
| 5 | `D:\pi-agent` | 历史默认值（仅当它真实存在） |

策略表里的边界规则（16 条）也全部由这些路径构造，所以装到任何盘符都照常保护。
`/safe doctor` 会显示 `Safe root: <路径>（来源）`，路径判定永远可自查。

**平台支持（重要）**：本版本的路径语义按 Windows 校验（驱动器号、大小写不敏感、`\` 与 `/` 混用、
MSYS 风格 `/d/foo`）。在 macOS / Linux 上路径比较会不可靠 —— 此时扩展**不会**假装没事，
而是把完整性报成 **DEGRADED** 并 fail-closed 拒绝高风险操作（日常读写、编译、测试不受影响）。
要真正支持 POSIX，需要把 `checks.ts` 的 `normalizePath`、`paths.ts` 的归一化改成平台感知，
并替换 `policy.ts` 里 Windows 专有的规则（系统目录、盘符根）。

### 0.3 怎么改、怎么提交

1. 只改**规范副本** `safe-mode\pi-extension\`（不要直接改镜像，镜像会被 bootstrap 恢复）
2. `safe-bootstrap.ps1 -Fix` 同步镜像（此时会因清单还是旧的而报 FAILED —— 预期）
3. `safe-regen.ps1` 重新生成清单（**必须你手动键入 yes**）
4. `safe-bootstrap.ps1 -VerifyOnly` 复核，期望 `RESULT: OK`
5. 在 pi 里 `/safe verify`，顺手 `/safe check`

---

## 1. 定位与边界（必读）

> **Safe Mode 是 Tool-boundary Policy Enforcement（工具边界策略执行层）。**
> **它不提供 OS-level Hard Enforcement，不是系统级隔离沙箱。**

| 能力 | 强度 |
| --- | --- |
| 主会话中**所有**工具调用的 ALLOW / CONFIRM / DENY（含扩展与 MCP 注册的工具） | **硬拦截** |
| 拦截器抛异常 → 工具不执行 | **硬（引擎保证）**：`beforeToolCall` 被包在 try/catch 内，异常即产生 error result 而不执行 |
| 受保护路径的读 / 写 / 删 | **硬** |
| 危险命令模式 | **硬**（模式识别存在绕过面） |
| 后台 subagent（`async: true`） | **硬**（会加载本扩展） |
| 前台 subagent | **硬在"限制为只读"这一层**（通过 pi-subagents capability ceiling），不是逐调用检查 |
| 手打 `!` 命令 | **硬**（走 `user_bash`，可确认后放行或伪造结果拒绝） |
| 扩展内部 `pi.exec` / 直接 fs 调用 | ❌ **Behavioral only** |
| MCP server 进程内部行为 | ❌ **Behavioral only** |
| 被允许执行的脚本 / 程序**内部**行为 | ❌ **Behavioral only** |
| safe.txt §17 提示注入防御、§16 环境变量不泄漏 | ❌ **Behavioral only** |

> `This part of Safe Mode is behavioral only and cannot provide a hard execution boundary.`

### 版本

Safe Mode 当前版本：**v1.2.0**（`1.1.0` = 审计后加固版；`1.0.0` = 初版）。

会显示在：`/safe` 面板标题、`/safe status`、`/safe doctor`、以及注入给模型的 system prompt 里。
定义位置：`pi-extension/policy.ts` 的 `SAFE_MODE_VERSION`（也会通过 `__internals` 导出给测试用）。

它只是“现在跑的是哪一代实现”的标签：**篡改检测靠 `safe-manifest.json` 的哈希，不靠这个字符串**。
所以改实现之后依然必须重新生成清单（见 §6）。

---

## 2. 用法

**每次运行 `pi` 都以 BALANCED 开始** —— 不需要任何操作，也不需要在 PowerShell 里做任何设置。

### 直接用面板（推荐）

输入 `/safe` 回车，就打开**开关式设置面板**：

```
🛡 Safe Mode 设置

当前等级：🔵 平衡（本窗口一直有效）
新开 pi 时：🔵 平衡

选一个等级就切换。带 ✅ 的是当前生效的。
↑↓ 选择 · 回车确认 · Esc 关闭

✅ 🔵 平衡（BALANCED）—— 日常推荐：普通开发自动执行，危险操作问一下
　 🟠 严格（STRICT）—— 陌生项目、第三方代码、复杂命令时用
　 🟢 低（LOW）—— 开发最顺畅，几乎不弹窗
　 ⭕ 关闭（OFF）—— 只留最基本保护（凭据、窃取、恶意行为仍然拦）
────────────────────────────────
　⭐ 让新开的 pi 也用「平衡」
　ℹ️ 查看简版状态
　🔧 查看详细状态（技术信息）
　📖 查看规则清单（每条注明 safe.txt 出处）
　🔄 重新读取 safe.txt
　✅ 重新做完整性校验
```

切换等级后面板会**自动重新打开**，可以继续调；按 **Esc 关闭**。

### 等级什么时候会变

| 时机 | 会怎样 |
| --- | --- |
| 本窗口里选了某个等级 | **一直有效**，直到你自己再改 |
| 本窗口内发生内部重载（`/reload`、安装扩展触发的重载） | **保持不变**（会从会话记录恢复你的选择） |
| **新开一个 pi** | 回到「新开 pi 时」的等级（出厂 `BALANCED`） |

想让新开的 pi 也用你现在的等级 → 在面板里选 **⭐ 让新开的 pi 也用「X」**，或者 `/safe default X`。

### 键盘／命令方式

```
/safe                      打开设置面板
/safe low | balanced | strict | off     本窗口等级（一直有效，不写文件）
/safe default low          让新开的 pi 也用 LOW（显式操作，会写状态文件）
/safe reset                「新开 pi 时」恢复为 BALANCED
/safe status               简版状态（给人看）
/safe doctor               详细状态（排障：路径 / hash / 完整性明细 / Pi 版本 / 审计）
/safe rules                规则清单（每条注明 safe.txt 出处）
/safe check                离线检查：完整性 + 规则重复/遮蔽 + 决策矩阵 + 冲突扫描
/safe explain [n|all]      解释最近一次决策（规则 / 范围 / 为什么）
/safe test bash rm -rf build   模拟一条操作：只看结论，不执行、不弹窗、不写盘
/safe audit                查看决策审计日志（最后 20 条）
/safe verify | reload | log     完整性校验 / 重读策略 / 本次会话统计
/safe subagent readonly|block|off
Ctrl+Alt+S                 本次会话临时开关
pi --no-safe               本次启动临时关闭（不改启动默认）
```

### 你自己手敲的 `!` 命令

`!命令` 是**你本人**在输入框里敲的，所以：

| 命中的规则 | 行为 |
| --- | --- |
| ALLOW | 直接执行 |
| CONFIRM（含 IRON CORE 的供应链 / 安全边界） | **直接执行，不再弹二次确认**（会在状态卡里记一笔） |
| DENY（凭据窃取 / 明显恶意） | 仍然拒绝，且不会执行 |

理由：只有真人能敲 `!`，不存在“外部内容伪造用户意图”的路径；让用户确认自己刚敲的命令只是白费一步。
但完整性未确认（`DEGRADED`）时，连你自己的 `!` 命令也会按 fail-closed 拒绝 —— 先修复完整性再干活。

两个概念分开，不会互相干扰：

| | 含义 | 怎么改 |
| --- | --- | --- |
| **本窗口等级** | 你在这个 pi 窗口里选的等级。**一直有效**，内部重载（`/reload`、装扩展）也不会丢 | `/safe low/balanced/strict/off`、面板、`Ctrl+Alt+S` |
| **新开 pi 时的等级** | 新开一个 pi 用哪个等级，出厂 `BALANCED` | `/safe default …` 或在面板里选「让新开的 pi 也用「X」」 |

所以：某次 `/safe off` 或 `/safe strict` **不会**影响新开的 pi —— 新开的 pi 用「新开 pi 时的等级」。

状态文件：`D:\pi-agent\safe-mode\safe-state.json`（只存**启动默认等级**）。
它**不是**策略源；受 `iron.boundary-write` 保护（模型改写它必须经你确认）；
**不**纳入 manifest。文件不存在/损坏 → 自动回到出厂值 `BALANCED`。

---

## 3. 两层结构

### IRON CORE —— 永远生效（含 OFF）

| 规则 | 动作 | 出处 |
| --- | --- | --- |
| `iron.credential-path` | **DENY** | safe.txt §8, §15 |
| `iron.malicious` | **DENY** | safe.txt §4 LEVEL 4, §28 |
| `iron.secret-exfil` | **DENY** | safe.txt §15, §14 |
| `iron.supply-chain`（Pi 更新 / `pi install`/`uninstall`/`config`） | **CONFIRM** | safe.txt §19, §20 |
| `iron.boundary-write`（写 safe.txt / safe-mode / settings.json / extensions / skills / sessions / current） | **CONFIRM** | safe.txt §8, §20 |

### RISK LEVEL —— 开发摩擦度

`off` / `low` / `balanced`（默认）/ `strict`。
用 `/safe rules` 查看当前生效的完整规则表（每条都标注 safe.txt 章节）。

---

## 4. 完整性校验（三层）

| 层 | 位置 | 作用 |
| --- | --- | --- |
| L1 | `D:\pi-agent\safe-mode\safe-bootstrap.ps1` + `safe-launch.cmd` | **唯一能发现"扩展整体消失"的机制**。校验 safe.txt + 逐文件比对规范副本/镜像 + 检查 settings.json 未强制排除 safe-mode + 记录 Pi 版本；镜像被改则从规范副本恢复；失败则**不启动 Pi** |
| L2 | 扩展内 `verifyIntegrity()` | `session_start` / `/safe verify` / `/safe reload`，以及 **safe.txt 内容真的变了之后自动复验一次**；校验 safe.txt hash、manifest、manifest schema 版本、自身源码 hash、策略自检（内置危险样本必须 DENY）。它**不在每一次工具调用上跑**（热路径只做 `statSync` 签名判断，≈0.005 ms） |
| L3 | 更新后重检 | 检测到 Pi 更新 / 扩展变更 / `/reload` 后重新执行 L2 并报告 |

校验不通过时状态显示 `DEGRADED` / `UNAVAILABLE`，并且：

- **高风险操作 fail-closed 拒绝**
- 普通低风险开发操作（读文件、改代码、编译、测试）**照常放行**

---

## 5. 文件布局

**所有 Safe Mode 文件都在 Safe Mode 家目录下**（Pi Home 之外，Pi 更新碰不到）。
下面用 `D:\pi-agent` 表示 Pi 根目录；你的实际位置以 `/safe doctor` 的 `Safe root` 行为准
（`SAFE_MODE_ROOT` / `SAFE_MODE_HOME` / `PI_CODING_AGENT_DIR` 都可以改它）：

```
D:\pi-agent\
├─ safe-mode\                        ← Safe Mode 的家（Pi Home 之外）
│   ├─ safe.txt                      策略源（唯一权威）
│   ├─ safe.txt.bak                  人工回滚备份（惰性，运行时从不加载）
│   ├─ safe-manifest.json            完整性基线（只存哈希）
│   ├─ safe-state.json               新开 pi 时的默认等级（偏好，不是策略）
│   ├─ safe-audit.jsonl             决策审计（JSONL，只记有裁决的事件；超过 2 MB 轮转为 .1）
│   ├─ safe-integrity.log            L1 校验日志
│   ├─ safe-bootstrap.ps1            L1 校验 / 自动恢复
│   ├─ safe-launch.cmd               启动入口（可选）
│   ├─ safe-regen.ps1                清单生成器（需你键入 yes）
│   ├─ backup\<时间戳>\              实现备份（不是运行的一部分，不纳入哈希）
│   ├─ README.md                     本文件
│   └─ pi-extension\                 ← 规范实现（**唯一镜像源**）
│       ├─ index.ts  policy.ts  checks.ts  loader.ts  manifest.ts
│       └─ tests\
└─ agent\extensions\safe-mode\      ← Pi 自动发现并加载的镜像（内容 = pi-extension\）
```

**为什么不把「可变文件」放进 `pi-extension\`**：那个目录会被递归哈希、并被镜像到 Pi 扩展目录，所以：

| 若放进去 | 后果 |
| --- | --- |
| `safe-manifest.json` | 变成自哈希，永远不可能自洽 |
| `safe-state.json` | 你每改一次等级就变一次 → 哈希永不通过 → **永久 DEGRADED** |
| `safe-integrity.log` | 每次校验都追加 → 同上 |
| `safe-audit.jsonl` | 每次裁决都追加 → 同上（而且它是审计数据，不是实现） |
| `backup\` | 实现备份目录，没必要参与哈希 |
| `safe.txt` | 会在 Pi 扩展目录里出现**第二份策略副本**，破坏"唯一权威源" |

因此它们是刻意排除在哈希之外的；`safe.txt` 通过 `policySha256` 单独登记，
而 `safe-manifest.json` 另外记录生成时的 `piVersion`（仅用于启动时的版本漂移提醒，**不**做兼容性判定）。

---

## 6. 修改 safe.txt / 修改 Safe Mode 实现之后

1. 编辑规范实现：**`D:\pi-agent\safe-mode\pi-extension\`**（不要直接改镜像 —— 镜像由 bootstrap 恢复）
2. **同步镜像**（清单同时冻结两边，所以必须先同步再 regen）：
   ```powershell
   powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -Fix
   ```
   此步会因清单还是旧的而报 `FAILED` —— **这是预期的**，只要它把镜像修好即可。
3. 重新生成清单：
   ```powershell
   powershell -NoProfile -File D:\pi-agent\safe-mode\safe-regen.ps1
   ```
   在弹出的提示处键入 `yes`。
   （`safe-regen.ps1` 必须由**你**手动确认；它会把当前文件状态认定为可信基线，不会自动触发）
4. 只读复核（**此开关不写任何文件**，不修复镜像也不写日志）：
   ```powershell
   powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -VerifyOnly
   ```
   看到 `RESULT: OK` 即可。
5. 在 Pi 里 `/safe verify`（或 `/safe reload`），顺手 `/safe check` 看规则自检。

未更新 manifest 时，`/safe verify` 会报 `DEGRADED` —— 这是**预期行为**，不是故障。
在 `DEGRADED` 期间，**所有需要确认或拒绝的操作都会被 fail-closed 拦下**（含你自己手敲的 `!` 命令）；
普通低风险开发（读文件、改代码、编译、运行测试）不受影响。

> 注意：修改 `safe.txt` 或 Safe Mode 实现，在任何等级（含 OFF）都属于 **CONFIRM**；
> 模型不得自行确认，必须由你在弹窗里明确按键。
> 而**重新生成清单永远只能由你手动跑并键入 `yes`** —— 模型无法把被篡改的实现“洗白”。

---

## 7. 残留风险（无法在纯扩展层消除）

1. **扩展无法报告自己的缺席**。safe-mode 被删除或被 `pi config` 禁用后，它发不出警告；只有 L1 bootstrap 能发现。
2. **`pi config` 是用户自己的显式行为**，在扩展加载前运行，Safe Mode 无法阻止，只能事后由 bootstrap 检出。
3. **命令解析不可能完备**：`-EncodedCommand`、Base64、变量拼接、别名、多层 `cmd /c`。
   缓解：无法静态复核的命令标记为 `UNKNOWN / UNPARSED / OPAQUE COMMAND` 并进入 CONFIRM（不是放行）。
4. **前台 subagent 的只读限制依赖 `pi-subagents/capability-ceiling`**。该 API 不可用时自动降级为**禁止** `subagent` 工具，而不是假装已拦截。
5. **模型可改安全层源码后请你 `/reload`**：已由 manifest hash 检出并降级为 DEGRADED。
6. **`.env` 读取在 LOW 下放行**（按你的决定）；secret 脱敏是模式匹配，**不能保证 100% 覆盖**所有密钥格式。
7. **审计日志只记“有裁决”的事件**（DENY / CONFIRM 结果 / 会话授权 / fail-closed）。普通 ALLOW 不写盘，所以日志里看不到“全都放行了什么”。写入前会先过秘密脱敏，但仍不能保证识出所有秘密格式。超过 2 MB 会轮转为 `safe-audit.jsonl.1`。
8. 本层**不**扫描下载内容、**不**做网络代理、**不**影响下载速度。
9. **`/safe explain` 里的 Source / Operation / Scope / Sensitivity 是推导值**：pi 的 `tool_call` 事件只提供 `toolName` / `toolCallId` / `input`（没有 actor，也没有 tool source）。这些字段只用于展示与审计，不参与任何裁决。
10. 你自己手敲的 `!` 命令命中 CONFIRM 时**不会弹二次确认**（见 §2）。如果你希望“即使是我自己敲的也要问”，告诉我一声，改回来只需要一处判断。
11. **批准修改安全边界后会立即复验一次完整性**（一次 ~4 ms 哈希）。所以“模型改安全层源码 + 你点了允许”之后，状态会立刻变成 `DEGRADED`，而不是等到下次 `/safe verify` 才发现。
12. `SAFE_MODE_VERSION` 只是标签，**不是**防篡改手段；真正的检测是 manifest 哈希。

---

## 8. 启动方式

| 方式 | 适用 |
| --- | --- |
| **`pi`** | 日常。扩展自动加载 → Safe Mode 默认开启，L2 运行时校验照常工作 |
| `D:\pi-agent\safe-mode\safe-launch.cmd` | 需要额外保证时（改过配置 / 装过扩展 / 更新过 Pi 之后）。多一层 L1：能发现"扩展整体消失"、自动修复镜像、失败则拒绝启动 |
| `pi --no-safe` | 一次性关闭本次会话（不改变已记住的等级） |
| `powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -VerifyOnly` | 只做 L1 体检，**不写任何文件**（不修复镜像、不写日志）；看到 `RESULT: OK` 即可 |
| `powershell -NoProfile -File D:\pi-agent\safe-mode\safe-bootstrap.ps1 -Fix` | 校验并把镜像从规范副本恢复（写 `safe-integrity.log`） |

## 9. 事件与钩子（实现说明）

| 钩子 | 用途 |
| --- | --- |
| `tool_call` | 主拦截点；返回 `{block:true, reason}` 阻止执行 |
| `user_bash` | 手打 `!` 命令；命中 DENY 时返回伪造 `BashResult`（命令不执行）；命中 CONFIRM 时**直接放行**（见 §2） |
| `before_agent_start` | 把 Safe Mode 约束注入 system prompt（软约束；不含全文以免每轮多花 token） |
| `tool_result` | 秘密脱敏（私钥块、`sk-`/`ghp_`/`AKIA`/`xox`、`api_key=…` 等） |
| `session_start` / `session_shutdown` | 策略加载、完整性校验、subagent ceiling 注册与释放、读取 Pi 版本做漂移提醒 |

**只做允许 / 拦截，绝不改写工具参数** —— 避免"净化"逻辑本身成为绕过面。

---

## 10. 完全关闭（HARD-OFF）

`/safe off` **不等于**关闭：Always-On Core 在任何等级（含 OFF）都生效。要真正全部关掉：

```
/safe off --hard      # 两步人工确认（确认框 + 键入「完全关闭」）
pi --unsafe           # 启动即完全关闭（仅本次运行）
```

关闭后扩展退化成「这个窗口没装过 Safe Mode」：

| 项 | HARD-OFF 时 |
| --- | --- |
| 工具调用裁决 | 不做（不弹窗、不拒绝、不审计） |
| system prompt 约束注入 | 不做 |
| 完整性校验 / fail-closed 降级 | 不跑 |
| 工具输出秘密脱敏 | 不做 |
| 手打 `!` 命令 | 直接透传 |
| 状态栏徐标 | **保留**：`🛡 SAFE: HARD-OFF — no protection` |
| 会话记录 | 只记一条「已完全关闭」（便于事后查证） |

几条刻意的设计：

- **只能由人开启**：`/safe` 是用户命令，`pi --unsafe` 也得你自己敲；命令端还要求真人当下在场
  （确认框 + 键入确认词），防止「一句话骗你敲一下就永久无保护」
- **永不持久化**：重启 pi 就回到配置的等级。因为关闭期间磁盘上没有任何东西受保护，
  一个可持久化的关闭开关只要被改一次，就会长期静默失守
- **模型不得使用它**：`safe.txt` §38 写明模型不能开启、不能建议开启、不能拿它绕过被拒绝的操作；
  `Ctrl+Alt+S` 与 `/safe on` 在 HARD-OFF 下**只能**重新开启，不会关得更彻底
- **fail-open**：HARD-OFF 自己检测不到任何篡改 —— 这正是它只做会话级、且必须留可见徐标的原因

## 11. 仓库结构

```
pi-safe-mode/
├─ install.ps1             部署脚本（复制实现到你的 Pi 根目录；不生成清单）
├─ safe.txt                策略源（唯一权威）
├─ safe-bootstrap.ps1      L1 校验 / 镜像恢复（-VerifyOnly 只读体检）
├─ safe-launch.cmd         启动入口（Windows）
├─ safe-regen.ps1          清单生成器（必须人工键入 yes）
├─ pi-extension/           可执行派生（会被镜像到 Pi 扩展目录）
│   ├─ index.ts            钩子注册、HARD-OFF、/safe 命令
│   ├─ policy.ts           规则表（边界路径由 paths.ts 构造）
│   ├─ checks.ts           命令 / 路径解析与裁决引擎
│   ├─ loader.ts           策略加载 + 完整性快路径
│   ├─ manifest.ts         完整性校验 + 策略自检
│   ├─ paths.ts            路径解析（唯一来源）
│   └─ tests/              engine.test.mjs · e2e.test.mjs · harness.mjs
├─ README.md  CHANGELOG.md  LICENSE
```

**运行态文件不在仓库里**（`.gitignore` 已排除）：`safe-manifest.json`、`safe-state.json`、
`safe-audit.jsonl`、`safe-integrity.log`、`backup/` —— 它们是本机状态，由 `safe-regen.ps1`
与运行时生成。

> 不要把仓库直接克隆/初始化到 `safe-mode\` 里面：bootstrap 会把规范副本里的**每个文件**
> 同步到镜像，regen 也会把它们写进清单；多一个 `.git\` 会让两边永久不一致。
> 正确做法就是用 `install.ps1` 把文件拷进去。

## 12. 开发与测试

测试不绑定安装位置（`tests/harness.mjs` 自动发现 pi 与 jiti）：

```powershell
node <safe-mode>\pi-extension\tests\engine.test.mjs   # 策略引擎 + 归一化 + 审计（102 项）
node <safe-mode>\pi-extension\tests\e2e.test.mjs      # 运行时端到端 + HARD-OFF（170 项）
```

解析不到时用环境变量指定：`SAFE_TEST_JITI`、`SAFE_TEST_PI_ROOT`、`SAFE_TEST_IMPL_DIR`、
`SAFE_TEST_LOAD_DIR`、`SAFE_MODE_ROOT`。未部署（没有 `safe-manifest.json`）时，依赖清单的
用例会打印 `SKIP` 并说明原因（此时扩展处于 DEGRADED，所有 CONFIRM 都是 fail-closed）。

## 13. 许可与边界声明

MIT —— 见 `LICENSE`。请连同这句话一起理解它：**这是工具边界策略层，不是安全沙箱**。
它不做 OS 级隔离，也无法限制已被放行程序内部的行为；安全模型与残留风险见第 1、7 节。
