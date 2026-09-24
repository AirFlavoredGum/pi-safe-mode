# CHANGELOG

## Unreleased — 版本漂移提醒确认（`acknowledgedPiVersion`）

- 修一个死循环式的提醒：`safe-manifest.json` 里的 `piVersion` 只有 `safe-regen.ps1` 会改写，
  所以「Pi 版本与基线不一致」这句提醒**单靠 `/safe verify` 永远消不掉**——你按它说的做了校验，
  下次开 pi 它还是照旧出现（提醒里那句「请重跑 /safe verify」实际上是失效的）
- `safe-state.json` 新增 `acknowledgedPiVersion`：只在用户**显式**做完整性校验
  （`/safe verify` 或面板里的「✅ 重新做完整性校验」）**且校验通过**时写入；同一版本不再提醒，
  Pi 再升级（版本号变了）→ 重新提醒一次；校验失败**不**写入，DEGRADED 每次都照常提醒
- 状态文件改为**合并写入**（`writeStateFile`）：写 `acknowledgedPiVersion` 不会覆盖 `defaultLevel`，
  反之亦然；继续兼容旧字段 `level`
- 读取只降级，绝不参与裁决：文件缺失/损坏/非法 JSON/不是 JSON 对象 → 忽略并报告，
  策略裁决不依赖状态文件；损坏文件在下次写入时自愈
- 文档：README 说明状态文件的两类偏好字段与漂移提醒的消失条件；测试用例数同步更新
- 测试：engine 102 → **121**（+19：合并写入互不覆盖、旧字段兼容、非法等级、空字符串、
  非对象、损坏自愈）；e2e 181 → **188**（+7：用假 `package.json` 造出**真实**版本漂移，
  验证「校验通过才记录 / 同进程内不重复 / 重启后仍安静 / 版本再变再提醒 / 校验失败不记录也不写文件」）

> 说明：本次提交把此前只存在于**部署副本**（本机 safe-mode 目录与 Pi 镜像）里的改动收进仓库，
> 否则下次 `install.ps1` 重装或 Pi 升级会把该特性默默丢掉。
> 尚未写 `docs/release-notes-*.md`，也未改 `safe.txt` 或 `SAFE_MODE_VERSION`（仍为 1.3.0）。

## v1.3.0 — HARD-OFF 进入设置面板

> 面向使用者的说明（含面板截图式示例、升级步骤、English summary）：[`docs/release-notes-v1.3.0.md`](docs/release-notes-v1.3.0.md)

- `/safe` 面板新增 **⛔ 完全关闭（HARD-OFF）**，与四个等级并列（放在 STRICT 之后）
- 选中它**仍走两步人工确认**（确认框 + 键入「完全关闭」）—— 面板只降低「找到它」的成本，
  不降低「触发它」的成本
- HARD-OFF 生效时：面板标题显示当前状态、✅ 落在 ⛔ 那一行、四个等级都不再标 ✅
  （因为此时没有任何等级在生效）
- HARD-OFF 生效时从面板选任一等级 = **恢复保护**（新增 `applyLevel()`：先重新开启
  —— 重读策略 + 完整性校验 + 重装子代理上限 —— 再切等级）
- 面板的选项回调改为支持 async（`actions[]` 允许返回 Promise），`setLevel` 保持同步不变
- `safe.txt` §38 补上「面板」这条入口，并写明它仍是两步确认
- `SAFE_MODE_VERSION` → `1.3.0`
- 测试：新增 11 项面板检查，**engine 102 + e2e 181 全部通过**

## v1.2.0 — 可移植化 + HARD-OFF（完全关闭）

> 面向使用者的完整说明（含安装、升级、English summary）：[`docs/release-notes-v1.2.0.md`](docs/release-notes-v1.2.0.md)

### 新增：HARD-OFF（`safe.txt` §38）

- `/safe off --hard`：**两步人工确认**（确认框 + 键入「完全关闭」）后，本会话彻底关闭
- `pi --unsafe`：启动即完全关闭（仅本次运行）
- HARD-OFF 时扩展退化成「没装过」：不拦截、不注入策略、不写审计、不校验完整性、不做秘密脱敏；
  只保留状态栏徽标 `🛡 SAFE: HARD-OFF — no protection` 与一条会话记录
- **永不持久化**：重启 pi 即回到配置的等级。因为关闭期间磁盘上没有任何保护，
  一个可持久化的关闭开关只要被改一次就会长期静默失守
- 模型无法开启它，也无法用它绕过被拒绝的操作（§20 仍然生效）
- `Ctrl+Alt+S` 与 `/safe on` 在 HARD-OFF 下一律是「重新开启」，不会关得更彻底

### 新增：路径可移植（`pi-extension/paths.ts`）

- 之前 `loader.ts` 的默认 `SAFE_ROOT` 与 `policy.ts` 里 16 条边界路径正则
  都写死了同一个固定的绝对路径 —— 装到别的盘符或目录时**边界路径保护会静默失效**
- 现在全部路径由一个模块解析，优先级：
  `SAFE_MODE_ROOT` → `SAFE_MODE_HOME` 的父目录 → `PI_CODING_AGENT_DIR` 的父目录 →
  镜像自身位置 → 实现里的历史默认值（仅当那个目录真实存在）
- `policy.ts` 的边界规则改由 `boundaryPathRe()` / `boundaryChildRe()` 从上述路径构造
- `/safe doctor` 新增 `Safe root`（含来源）与 `MODE` 行，路径判定不再是黑箱
- `safe-bootstrap.ps1` / `safe-regen.ps1` 同样按环境变量解析根目录（默认取脚本位置的上一级）

### 新增：平台降级（fail-closed，而不是静默失守）

- 本版本的路径语义按 Windows 校验（驱动器号 + 大小写不敏感）
- 在非 Windows 平台上，完整性校验会主动报 `platform` 问题 → 状态变为 **DEGRADED**，
  高风险操作 fail-closed 拒绝。宁可不能用，也不假装路径保护有效

### 新增：测试可在任意安装位置运行

- 新增 `pi-extension/tests/harness.mjs`：自动发现 pi / jiti / 实现目录
  （`SAFE_TEST_IMPL_DIR`、`SAFE_TEST_LOAD_DIR`、`SAFE_TEST_JITI`、`SAFE_TEST_PI_ROOT` 可覆盖）
- `e2e.test.mjs` 新增 18 项 HARD-OFF 行为检查（确认被拒 / 确认词错误 / 真正关闭 /
  无策略注入 / 无脱敏 / `!` 命令直通 / 不落盘 / 快捷键只能恢复 / `--unsafe` / 软关闭仍然拦截）
- 未部署（无 `safe-manifest.json`）时，依赖清单的用例显式打印 `SKIP` 并说明原因

### 其他

- `SAFE_MODE_VERSION` → `1.2.0`；`safe.txt` §8/§37 的路径描述改为相对 Pi 根目录
- `safe.txt` 新增 §38，并在 §32/§33 加了交叉引用（HARD-OFF 不是等级，也不能被模型使用）
- 新增 `LICENSE`（MIT）、`.gitignore`、`install.ps1`、本 CHANGELOG

### 修复（可移植化过程中引入 / 暴露的问题）

- **`safe-bootstrap.ps1` / `safe-regen.ps1`：根目录多推了一层**。
  `$PSScriptRoot` 已经是 `<root>\safe-mode`，只需一层 `Split-Path -Parent`；
  写成两层后会去找 `D:\safe-mode\...`，在非默认布局下报一串 `missing`
- **`safe-regen.ps1`：三个脚本被静默漏出清单**。把 `$Extras` 改成绝对路径后，
  后面仍然执行 `Join-Path $Root $name`，得到无效路径 → `Test-Path` 失败 → `if` 直接跳过。
  后果是 `safe-bootstrap.ps1` / `safe-launch.cmd` / `safe-regen.ps1`
  **不再被任何哈希校验**（L1 自校验的核心被架空，且不报错）。
  现在同时接受绝对/相对路径，且任一文件缺失就**硬报错退出（exit 2）**，绝不再静默生成不完整清单
- **`safe-regen.ps1`：镜像目录缺失时也硬报错**（否则会生成只覆盖单侧副本的隐性残缺清单）
- **`safe-regen.ps1`：`$Root` / `$SafeHome` / `$AgentDir` 去尾部反斜杠**，
  避免用 `Substring($Root.Length)` 推相对路径时多切掉一个字符
- `safe-regen.ps1` 结尾的 “Next:” 提示不再写死那个绝对路径

> 教训（已写进实现）：安全层的脚本里，**任何 “找不到就跳过” 的写法都是缺陷**。
> 清单少登记一个文件不会报错，只会静静失去对该文件的篡改检测。所以现在一律 fail-loud。

## v1.1.0 — 审计后的加固版

- 大范围加固（此版本之前的初版为 1.0.0）
- 完整性校验分三层（L1 bootstrap / L2 扩展内 / L3 更新后重检）
- 决策审计日志（`safe-audit.jsonl`，写前脱敏，2 MB 轮转）
- `iron.boundary-write`：安全边界写入在批准后立即复验完整性

## v1.0.0 — 初版

- `/safe` 面板与四个等级（off / low / balanced / strict）+ Always-On Core
- 工具边界策略执行（`tool_call` / `user_bash` / `tool_result`）
